// Author: eeff <eeff at eeff dot dev>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "core/nng_impl.h"

// MQTT client implementation.
//
// 1. MQTT client sockets have a single implicit dialer, and cannot
//    support creation of additional dialers or listeners.
// 2. Send sends PUBLISH messages.
// 3. Receive is used to receive published data from the server.

// FIXME: assign valid id, or do we need these ?
#define NNG_MQTT_SELF 0
#define NNG_MQTT_SELF_NAME "mqtt-client"
#define NNG_MQTT_PEER 0
#define NNG_MQTT_PEER_NAME "mqtt-server"

typedef struct mqtt_sock_s mqtt_sock_t;
typedef struct mqtt_pipe_s mqtt_pipe_t;
typedef struct mqtt_ctx_s  mqtt_ctx_t;

static int  mqtt_sock_init(void *arg, nni_sock *sock);
static void mqtt_sock_fini(void *arg);
static void mqtt_sock_open(void *arg);
static void mqtt_sock_send(void *arg, nni_aio *aio);
static void mqtt_sock_recv(void *arg, nni_aio *aio);
static void mqtt_send_cb(void *arg);
static void mqtt_recv_cb(void *arg);
static void mqtt_keep_alive_cb(void *arg);
static void mqtt_timer_cb(void *arg);
static void mqtt_send_start(mqtt_sock_t *s);
static void mqtt_recv_start(mqtt_sock_t *s, nni_aio *aio);
static void mqtt_run_recv_queue(mqtt_sock_t *s);

static int  mqtt_pipe_init(void *arg, nni_pipe *pipe, void *s);
static void mqtt_pipe_fini(void *arg);
static int  mqtt_pipe_start(void *arg);
static void mqtt_pipe_stop(void *arg);
static void mqtt_pipe_close(void *arg);

static int  mqtt_ctx_init(void *arg, void *sock);
static void mqtt_ctx_fini(void *arg);
static void mqtt_ctx_send(void *arg, nni_aio *aio);
static void mqtt_ctx_recv(void *arg, nni_aio *aio);

typedef nni_mqtt_packet_type packet_type_t;

// Work state indicating what MQTT packet we *expect* to send/recv.
//
// bits:   7 6 5 4 3 2 1 0
// error <_/ | | | |
// final <___/ | | \________> lower nib encoding packet type
// init  <_____/ \__________> ack received
typedef uint8_t work_state_t;

#define WORK_STATE_ACKED 0x10 // state we had received expected ack packet
#define WORK_STATE_INIT 0x20  // start state
#define WORK_STATE_FINAL 0x40 // final state
#define WORK_STATE_ERROR 0x80 // error state

#define work_is_acked(work) ((work)->state & WORK_STATE_ACKED)
#define work_is_error(work) ((work)->state & WORK_STATE_ERROR)
#define work_is_final(work) ((work)->state & WORK_STATE_FINAL)
#define work_packet_type(work) ((work)->state & 0xEF)

#define work_set_init(work) ((work)->state = WORK_STATE_INIT)
#define work_set_send(work, packet) ((work)->state = (packet))
#define work_set_recv(work, packet) ((work)->state = (packet))
#define work_set_acked(work) ((work)->state |= WORK_STATE_ACKED)
#define work_set_error(work) ((work)->state = WORK_STATE_ERROR)
#define work_set_final(work) ((work)->state = WORK_STATE_FINAL)

// A work_t represents an asynchronous send/recv of MQTT packet.
typedef struct {
	work_state_t   state;
	uint8_t        ntrial;    // number of times we transmit
	uint8_t        qos;       // QoS of the MQTT PUBLISH packet
	uint16_t       packet_id; // packet id of the message that have it
	mqtt_sock_t *  mqtt_sock;
	nni_msg *      msg;      // message to send, or receive from pipe
	nni_aio *      user_aio; // if not null, the aio that starts this work
	nni_duration   timeout;  // time out in milliseconds
	nni_timer_node timer;    // timer
	nni_list_node  node; // in one of send_queue, recv_queue or free_list
} work_t;

// A mqtt_ctx_s is our per-ctx protocol private state.
struct mqtt_ctx_s {
	mqtt_sock_t *mqtt_sock;
};

// A mqtt_pipe_s is our per-pipe protocol private structure.
struct mqtt_pipe_s {
	nni_atomic_bool closed;
	nni_atomic_int  next_packet_id; // next packet id to use
	nni_pipe *      pipe;
	mqtt_sock_t *   mqtt_sock;
	work_t          ping_work;     // work to send a ping request
	nni_id_map      send_unack;    // send messages unacknowledged
	nni_id_map      recv_unack;    // recv messages unacknowledged
	nni_aio         send_aio;      // send aio to the underlying transport
	nni_aio         recv_aio;      // recv aio to the underlying transport
	nni_lmq         recv_messages; // recv messages queue
};

// A mqtt_sock_s is our per-socket protocol private structure.
struct mqtt_sock_s {
	nni_atomic_bool closed;
	nni_atomic_int  ttl;
	nni_duration    retry;
	nni_mtx         mtx;    // TODO: more fine grained mutual exclusion
	mqtt_ctx_t      master; // to which we delegate send/recv calls
	mqtt_pipe_t *   mqtt_pipe;
	nni_list        send_queue; // work pending to send
	nni_list        recv_queue; // work pending to receive
	nni_list        free_list;  // free list of work
};

/******************************************************************************
 *                              Work Implementation                           *
 ******************************************************************************/

static inline void
work_init(
    work_t *work, mqtt_sock_t *s, nni_duration timeout_ms, nni_cb timer_cb)
{
	work_set_init(work);
	work->ntrial    = 0;
	work->qos       = 0;
	work->packet_id = 0;
	work->msg       = NULL;
	work->user_aio  = NULL;
	work->mqtt_sock = s;
	work->timeout   = timeout_ms;
	nni_timer_init(&work->timer, timer_cb, work);
	NNI_LIST_NODE_INIT(&work->node);
}

static inline void
work_fini(work_t *work)
{
	nni_timer_cancel(&work->timer);
	nni_timer_fini(&work->timer);
	nni_msg_free(work->msg);
}

static inline void
work_reset(work_t *work)
{
	work_set_init(work);
	work->ntrial    = 0;
	work->qos       = 0;
	work->packet_id = 0;
	nni_msg_free(work->msg);
	work->msg      = NULL;
	work->user_aio = NULL;
	// NOTE: keep the timeout
	nni_list_node_remove(&work->node);
}

static inline void
work_timer_schedule(work_t *work)
{
	++work->ntrial;
	nni_timer_schedule(&work->timer, nni_clock() + work->timeout);
}

static inline void
work_timer_cancel(work_t *work)
{
	nni_timer_schedule(&work->timer, NNI_TIME_NEVER);
}

/******************************************************************************
 *                              Sock Implementation                           *
 ******************************************************************************/

static int
mqtt_sock_init(void *arg, nni_sock *sock)
{
	NNI_ARG_UNUSED(sock);
	mqtt_sock_t *s = arg;

	nni_atomic_init_bool(&s->closed);
	nni_atomic_set_bool(&s->closed, false);

	nni_atomic_init(&s->ttl);
	nni_atomic_set(&s->ttl, 8);

	// this is "semi random" start for request IDs.
	s->retry = NNI_SECOND * 60;

	nni_mtx_init(&s->mtx);

	mqtt_ctx_init(&s->master, s);

	s->mqtt_pipe = NULL;

	NNI_LIST_INIT(&s->send_queue, work_t, node);
	NNI_LIST_INIT(&s->recv_queue, work_t, node);
	NNI_LIST_INIT(&s->free_list, work_t, node);

	return (0);
}

static void
mqtt_sock_fini(void *arg)
{
	mqtt_sock_t *s = arg;
	work_t *     work;

	nni_mtx_lock(&s->mtx);
	NNI_ASSERT(nni_list_empty(&s->send_queue));
	NNI_ASSERT(nni_list_empty(&s->recv_queue));

	while (NULL != (work = nni_list_first(&s->free_list))) {
		nni_list_remove(&s->free_list, work);
		work_fini(work);
		nni_free(work, sizeof(work_t));
	}
	nni_mtx_unlock(&s->mtx);

	mqtt_ctx_fini(&s->master);
	nni_mtx_fini(&s->mtx);
}

static void
mqtt_sock_open(void *arg)
{
	NNI_ARG_UNUSED(arg);
}

static void
mqtt_sock_close(void *arg)
{
	mqtt_sock_t *s = arg;

	nni_atomic_set_bool(&s->closed, true);
}

static void
mqtt_sock_send(void *arg, nni_aio *aio)
{
	mqtt_sock_t *s = arg;
	mqtt_ctx_send(&s->master, aio);
}

static void
mqtt_sock_recv(void *arg, nni_aio *aio)
{
	mqtt_sock_t *s = arg;
	mqtt_ctx_recv(&s->master, aio);
}

// Note: This routine should be called with the sock lock held.
static inline work_t *
mqtt_sock_get_work(mqtt_sock_t *s)
{
	// TODO: reduce number of allocation
	// TODO: shrink when low load
	work_t *work = nni_list_first(&s->free_list);
	if (NULL != work) {
		nni_list_remove(&s->free_list, work);
	} else {
		work = nni_zalloc(sizeof(work_t));
		if (NULL == work) {
			return NULL; // oom
		}
		work_init(work, s, s->retry, mqtt_timer_cb);
	}
	return work;
}

// Note: This routine should be called with the sock lock held.
static inline void
mqtt_sock_free_work(mqtt_sock_t *s, work_t *work)
{
	work_reset(work);
	nni_list_append(&s->free_list, work);
}

// Note: This routine should be called with the sock lock held.
static inline void
mqtt_sock_close_work(mqtt_sock_t *s, work_t *work)
{
	if (NULL != work->user_aio) {
		nni_aio_finish_error(work->user_aio, NNG_ECONNRESET);
	}
	mqtt_sock_free_work(s, work);
}

// Note: This routine should be called with the sock lock held.
static inline void
mqtt_sock_close_work_queue(mqtt_sock_t *s, nni_list *queue)
{
	work_t *work;
	while (NULL != (work = nni_list_first(queue))) {
		mqtt_sock_close_work(s, work); // remove from the list
	}
}

/******************************************************************************
 *                              Pipe Implementation                           *
 ******************************************************************************/

static int
mqtt_pipe_init(void *arg, nni_pipe *pipe, void *s)
{
	mqtt_pipe_t *p    = arg;
	mqtt_sock_t *sock = s;

	nni_atomic_init_bool(&p->closed);
	nni_atomic_set_bool(&p->closed, false);
	nni_atomic_set(&p->next_packet_id, 0);
	p->pipe      = pipe;
	p->mqtt_sock = s;
	// FIXME: passing keep alive timeout
	work_init(&p->ping_work, s, sock->retry, mqtt_keep_alive_cb);
	nni_mqtt_msg_alloc(&p->ping_work.msg, 0);
	nni_mqtt_msg_set_packet_type(p->ping_work.msg, NNG_MQTT_PINGREQ);
	work_set_send(&p->ping_work, NNG_MQTT_PINGREQ);
	nni_mqtt_msg_encode(p->ping_work.msg);
	nni_aio_init(&p->send_aio, mqtt_send_cb, p);
	nni_aio_init(&p->recv_aio, mqtt_recv_cb, p);
	// Packet IDs are 16 bits
	// We start at a random point, to minimize likelihood of
	// accidental collision across restarts.
	nni_id_map_init(&p->send_unack, 0x0000u, 0xffffu, true);
	nni_id_map_init(&p->recv_unack, 0x0000u, 0xffffu, true);
	nni_lmq_init(&p->recv_messages, 128); // FIXME: remove hard code value

	return (0);
}

static void
mqtt_pipe_fini(void *arg)
{
	mqtt_pipe_t *p = arg;
	work_fini(&p->ping_work);
	nni_aio_fini(&p->send_aio);
	nni_aio_fini(&p->recv_aio);
	nni_id_map_fini(&p->send_unack);
	nni_id_map_fini(&p->recv_unack);
	nni_lmq_fini(&p->recv_messages);
}

static int
mqtt_pipe_start(void *arg)
{
	mqtt_pipe_t *p = arg;
	mqtt_sock_t *s = p->mqtt_sock;

	// TODO: do we need this ?
	// if (nni_pipe_peer(p->pipe) != NNG_MQTT_SELF) {
	// 	return (NNG_EPROTO);
	// }

	nni_mtx_lock(&s->mtx);
	s->mqtt_pipe = p;
	mqtt_send_start(s);
	work_timer_schedule(&p->ping_work);
	nni_mtx_unlock(&s->mtx);

	nni_pipe_recv(p->pipe, &p->recv_aio);

	return (0);
}

static void
mqtt_pipe_stop(void *arg)
{
	mqtt_pipe_t *p = arg;
	mqtt_sock_t *s = p->mqtt_sock;

	nni_mtx_lock(&s->mtx);
	nni_aio_stop(&p->send_aio);
	nni_aio_stop(&p->recv_aio);
	nni_mtx_unlock(&s->mtx);
}

void
mqtt_close_unack_work_cb(void *arg)
{
	work_t *work = arg;
	mqtt_sock_close_work(work->mqtt_sock, work);
}

static void
mqtt_pipe_close(void *arg)
{
	mqtt_pipe_t *p = arg;
	mqtt_sock_t *s = p->mqtt_sock;

	nni_mtx_lock(&s->mtx);
	s->mqtt_pipe = NULL;
	nni_aio_close(&p->send_aio);
	nni_aio_close(&p->recv_aio);
	mqtt_sock_close_work_queue(s, &s->send_queue);
	mqtt_sock_close_work_queue(s, &s->recv_queue);
	nni_id_map_foreach(&p->send_unack, mqtt_close_unack_work_cb);
	nni_id_map_foreach(&p->recv_unack, mqtt_close_unack_work_cb);
	nni_mtx_unlock(&s->mtx);

	nni_atomic_set_bool(&p->closed, true);
}

static uint16_t
mqtt_pipe_get_next_packet_id(mqtt_pipe_t *p)
{
	int packet_id;
	do {
		packet_id = nni_atomic_get(&p->next_packet_id);
	} while (
	    !nni_atomic_cas(&p->next_packet_id, packet_id, packet_id + 1));
	return packet_id & 0xFFFF;
}

static inline void
mqtt_pipe_recv_msgq_putq(mqtt_pipe_t *p, nni_msg *msg)
{
	if (0 != nni_lmq_putq(&p->recv_messages, msg)) {
		// resize to ensure we do not lost messages
		// TODO: add option to drop messages
		if (0 !=
		    nni_lmq_resize(&p->recv_messages,
		        nni_lmq_len(&p->recv_messages) * 2)) {
			// drop the message when no memory available
			nni_msg_free(msg);
			return;
		}
		nni_lmq_putq(&p->recv_messages, msg);
	}
}

// Keep alive timer callback to send ping request.
static void
mqtt_keep_alive_cb(void *arg)
{
	work_t *     work = arg;
	mqtt_sock_t *s    = work->mqtt_sock;

	nni_mtx_lock(&s->mtx);

	mqtt_pipe_t *p = s->mqtt_pipe;

	if (NULL == p || nni_atomic_get_bool(&p->closed)) {
		return;
	}

	// keep alive time out
	// if there is work in the send queue, no need to send PINGREQ
	if (nni_list_empty(&s->send_queue)) {
		// no work in send queue, then send a PINGREQ
		nni_list_append(&s->send_queue, &p->ping_work);
		mqtt_send_start(s);
	}

	work_timer_schedule(&p->ping_work);

	nni_mtx_unlock(&s->mtx);
}

// Timer callback, we use it for retransmitting.
static void
mqtt_timer_cb(void *arg)
{
	work_t *     work = arg;
	mqtt_sock_t *s    = work->mqtt_sock;

	nni_mtx_lock(&s->mtx);

	mqtt_pipe_t *p = s->mqtt_pipe;

	if (NULL == p || nni_atomic_get_bool(&p->closed)) {
		return;
	}

	if (work->ntrial < nni_atomic_get(&s->ttl)) {
		// try again
		nni_list_append(&s->send_queue, work);
		if (nni_list_first(&s->send_queue) == work) {
			mqtt_send_start(s);
		}
	} else {
		// reach max retransmitting, quit
		nni_aio_finish_error(work->user_aio, NNG_EAGAIN);
		nni_id_remove(&p->send_unack, work->packet_id);
		mqtt_sock_free_work(s, work);
	}

	nni_mtx_unlock(&s->mtx);
}

static void
mqtt_send_cb(void *arg)
{
	mqtt_pipe_t *p = arg;
	mqtt_sock_t *s = p->mqtt_sock;
	work_t *     work;

	nni_mtx_lock(&s->mtx);

	work = nni_list_first(&s->send_queue); // will not be NULL
	nni_list_remove(&s->send_queue, work);

	if (nni_aio_result(&p->send_aio) != 0) {
		// We failed to send... clean up and deal with it.
		nni_msg_free(nni_aio_get_msg(&p->send_aio));
		nni_aio_set_msg(&p->send_aio, NULL);
		nni_mtx_unlock(&s->mtx);
		nni_pipe_close(p->pipe);
		return;
	}

	if (nni_atomic_get_bool(&s->closed) ||
	    nni_atomic_get_bool(&p->closed)) {
		// This occurs if the mqtt_pipe_close has been called.
		// In that case we don't want any more processing.
		nni_mtx_unlock(&s->mtx);
		return;
	}

	// state transitions
	switch (work_packet_type(work)) {
	case NNG_MQTT_CONNECT:
		// we have sent a CONNECT, expect receiving a CONNACK
		work_set_recv(work, NNG_MQTT_CONNACK);
		// FIXME
		work_set_final(work);
		break;

	case NNG_MQTT_DISCONNECT:
		// we have sent a DISCONNECT, just close the socket.
		work_set_final(work);
		// FIXME: close the socket
		break;

	case NNG_MQTT_PUBACK:
		// we have sent a PUBACK,
		// indicating a successful receipt of a QoS 1 message

		// fall through

	case NNG_MQTT_PUBCOMP:
		// FIXME: check packet id
		// we have sent a PUBCOMP,
		// indicating a successful receipt of a QoS 2 message
		work_set_final(work);
		nni_id_remove(&p->recv_unack, work->packet_id);
		// ownership of work->msg to the lmq
		mqtt_pipe_recv_msgq_putq(p, work->msg);
		work->msg = NULL;
		mqtt_sock_free_work(s, work);
		mqtt_run_recv_queue(s);
		mqtt_send_start(s);
		nni_mtx_unlock(&s->mtx);
		return;

	case NNG_MQTT_PINGREQ:
		// we have sent a PINGREQ
		mqtt_send_start(s);
		nni_mtx_unlock(&s->mtx);
		return;

	case NNG_MQTT_PUBLISH:
		// we have sent a PUBLISH
		if (0 == work->qos) {
			// QoS 0, no further actions
			work_set_final(work);
		} else {
			if (1 == work->qos) {
				// for QoS 1, expect receiving a PUBACK
				if (!work_is_acked(work)) {
					work_set_recv(work, NNG_MQTT_PUBACK);
					work_timer_schedule(work);
				} else {
					// scheduling disorder, PUBACK received
					work_set_final(work);
				}
			} else {
				// for QoS 2, expect receiving a PUBREC
				if (!work_is_acked(work)) {
					work_set_recv(work, NNG_MQTT_PUBREC);
					work_timer_schedule(work);
				} else {
					// scheduling disorder, PUBREC received
					work_set_recv(work, NNG_MQTT_PUBCOMP);
				}
			}
		}
		break;

	case NNG_MQTT_PUBREC:
		// we have sent a PUBREC, expect receiving a PUBREL
		work_set_recv(work, NNG_MQTT_PUBREL);
		break;

	case NNG_MQTT_PUBREL:
		// we have sent a PUBREL, expect receiving a PUBCOMP
		work_set_recv(work, NNG_MQTT_PUBCOMP);
		break;

	case NNG_MQTT_SUBSCRIBE:
		// we have sent a SUBSCRIBE, expect receiving a SUBACK
		if (!work_is_acked(work)) {
			work_set_recv(work, NNG_MQTT_SUBACK);
			work_timer_schedule(work);
		} else {
			// scheduling disorder, SUBACK received
			work_set_final(work);
		}
		break;

	case NNG_MQTT_UNSUBSCRIBE:
		// we have sent a UNSUBSCRIBE, expect receiving a UNSUBACK
		if (!work_is_acked(work)) {
			work_set_recv(work, NNG_MQTT_UNSUBACK);
			work_timer_schedule(work);
		} else {
			// scheduling disorder, UNSUBACK received
			work_set_final(work);
		}
		break;

	default:
		work_set_error(work);
		break;
	}

	if (work_is_error(work)) {
		// MQTT protocol error, terminate the connection
		nni_aio_finish_error(work->user_aio, NNG_EPROTO);
		nni_mtx_unlock(&s->mtx);
		nni_pipe_close(p->pipe);
		return;
	} else if (work_is_final(work)) {
		// good news, protocol state machine run to the end
		nni_aio *aio = work->user_aio;
		mqtt_sock_free_work(s, work);
		mqtt_send_start(s);
		nni_mtx_unlock(&s->mtx);
		if (NULL != aio) {
			nni_aio_finish(aio, 0, 0);
		}
		return;
	}

	mqtt_send_start(s);
	nni_mtx_unlock(&s->mtx);
	return;
}

static void
mqtt_recv_cb(void *arg)
{
	mqtt_pipe_t *p = arg;
	mqtt_sock_t *s = p->mqtt_sock;
	work_t *     work;

	nni_mtx_lock(&s->mtx);

	nni_msg *msg = nni_aio_get_msg(&p->recv_aio);

	if (nni_aio_result(&p->recv_aio) != 0) {
		nni_msg_free(msg);
		nni_mtx_unlock(&s->mtx);
		nni_pipe_close(p->pipe);
		return;
	}

	if (nni_atomic_get_bool(&s->closed) ||
	    nni_atomic_get_bool(&p->closed)) {
		nni_mtx_unlock(&s->mtx);
		return;
	}

	nni_aio_set_msg(&p->recv_aio, NULL);
	nni_msg_set_pipe(msg, nni_pipe_id(p->pipe));
	nni_mqtt_msg_proto_data_alloc(msg);
	nni_mqtt_msg_decode(msg);

	packet_type_t packet_type = nni_mqtt_msg_get_packet_type(msg);
	int32_t       packet_id;
	uint8_t       qos;

	// schedule another receive
	nni_pipe_recv(p->pipe, &p->recv_aio);

	// state transitions
	switch (packet_type) {
	case NNG_MQTT_CONNACK:
		// FIXME
		// we have received the CONNACK
		nni_mtx_unlock(&s->mtx);
		return;

	case NNG_MQTT_PUBACK:
		// we have received a PUBACK, successful delivery of a QoS 1

		// fall through

	case NNG_MQTT_PUBCOMP:
		// we have received a PUBCOMP, successful delivery of a QoS 2

		// fall through

	case NNG_MQTT_SUBACK:
		// we have received a SUBACK, successful subscription

		// fall through

	case NNG_MQTT_UNSUBACK:
		// we have received a UNSUBACK, successful unsubscription
		packet_id = nni_mqtt_msg_get_packet_id(msg);
		nni_msg_free(msg);
		work = nni_id_get(&p->send_unack, packet_id);
		if (NULL == work) {
			// ignore this message
			nni_mtx_unlock(&s->mtx);
			return;
		}
		nni_id_remove(&p->send_unack, packet_id);
		packet_type_t expect_packet_type = work_packet_type(work);
		if (expect_packet_type == packet_type) {
			work_set_final(work);
			work_timer_cancel(work);
		} else if (
		    // 1. we are sending QoS 1 and received PUBACK
		    (NNG_MQTT_PUBLISH == expect_packet_type &&
		        1 == work->qos && NNG_MQTT_PUBACK == packet_type) ||
		    // 2. we are sending QoS 2 and received PUBCOMP
		    (NNG_MQTT_PUBLISH == expect_packet_type &&
		        2 == work->qos && NNG_MQTT_PUBCOMP == packet_type) ||
		    // 3. we are sending SUBSCRIBE and received SUBACK
		    (NNG_MQTT_SUBSCRIBE == expect_packet_type &&
		        NNG_MQTT_SUBACK == packet_type) ||
		    // 4. we are sending UNSUBSCRIBE and received UNSUBACK
		    (NNG_MQTT_UNSUBSCRIBE == expect_packet_type &&
		        NNG_MQTT_UNSUBACK == packet_type)) {
			// scheduling disorder
			work_set_acked(work);
		} else {
			work_set_error(work);
		}
		break;

	case NNG_MQTT_PINGRESP:
		// do nothing
		nni_mtx_unlock(&s->mtx);
		return;

	case NNG_MQTT_PUBREC:
		// we have received a PUBREC in the QoS 2 delivery,
		// then send a PUBREL
		packet_id = nni_mqtt_msg_get_pubrec_packet_id(msg);
		nni_msg_free(msg);
		work = nni_id_get(&p->send_unack, packet_id);
		if (NULL == work) {
			// ignore this message
			nni_mtx_unlock(&s->mtx);
			return;
		}
		// the transport handled sending the PUBREL for us,
		// expect to receive a PUBCOMP
		if (work_packet_type(work) == packet_type) {
			work_set_recv(work, NNG_MQTT_PUBCOMP);
			work_timer_cancel(work);
		} else if (work_packet_type(work) == NNG_MQTT_PUBLISH &&
		    2 == work->qos) {
			// scheduling disorder
			work_set_acked(work);
		} else {
			work_set_error(work);
			work_timer_cancel(work);
		}
		break;

	case NNG_MQTT_PUBREL:
		// we have received a PUBREL, then send a PUBCOMP
		packet_id = nni_mqtt_msg_get_pubrel_packet_id(msg);
		work      = nni_id_get(&p->recv_unack, packet_id);
		if (NULL == work) {
			// ignore this message
			nni_msg_free(msg);
			nni_mtx_unlock(&s->mtx);
			return;
		}
		// the transport handled sending the PUBCOMP for us
		work_set_final(work);
		nni_id_remove(&p->recv_unack, work->packet_id);
		// ownership of work->msg to the lmq
		mqtt_pipe_recv_msgq_putq(p, work->msg);
		mqtt_run_recv_queue(s);
		work->msg = msg;
		mqtt_sock_free_work(s, work); // will release msg
		nni_mtx_unlock(&s->mtx);
		return;

	case NNG_MQTT_PUBLISH:
		// we have received a PUBLISH
		qos = nni_mqtt_msg_get_publish_qos(msg);
		if (2 > qos) {
			// QoS 0, successful receipt
			// QoS 1, the transport handled sending a PUBACK
			mqtt_pipe_recv_msgq_putq(p, msg);
			mqtt_run_recv_queue(s);
			nni_mtx_unlock(&s->mtx);
			return;
		} else {
			work = mqtt_sock_get_work(s);
			if (work == NULL) {
				nni_mtx_unlock(&s->mtx);
				nni_pipe_close(p->pipe);
				return;
			}
			work->qos = qos;
			work->msg = msg; // keep the message
			work->packet_id =
			    nni_mqtt_msg_get_publish_packet_id(msg);
			// the transport handled sending PUBREC,
			// expect to receive a PUBREL
			work_set_recv(work, NNG_MQTT_PUBREL);
			nni_id_set(&p->recv_unack, work->packet_id, work);
		}
		break;

	default:
		// unexpected packet type, server misbehaviour
		nni_mtx_unlock(&s->mtx);
		nni_pipe_close(p->pipe);
		return;
	}

	if (work_is_error(work)) {
		// protocol error, just close the connection
		nni_mtx_unlock(&s->mtx);
		nni_aio_finish_error(work->user_aio, NNG_EPROTO);
		nni_pipe_close(p->pipe);
		return;
	} else if (work_is_final(work)) {
		// good news, protocol state machine run to the end
		nni_aio *aio = work->user_aio;
		mqtt_sock_free_work(s, work);
		nni_mtx_unlock(&s->mtx);
		nni_aio_finish(aio, 0, 0);
		return;
	}

	nni_mtx_unlock(&s->mtx);

	return;
}

// Note: This routine should be called with the sock lock held.
static void
mqtt_recv_start(mqtt_sock_t *s, nni_aio *aio)
{
	mqtt_pipe_t *p = s->mqtt_pipe;
	work_t *     work;

	work = mqtt_sock_get_work(s);

	if (NULL == work) {
		nni_mtx_unlock(&s->mtx);
		nni_aio_finish_error(aio, NNG_ENOMEM);
		return;
	}

	work->user_aio = aio;
	work_set_recv(work, NNG_MQTT_PUBLISH);
	nni_list_append(&s->recv_queue, work); // enqueue to recv

	// no open pipe
	if (NULL == p || nni_atomic_get_bool(&p->closed)) {
		return;
	}

	mqtt_run_recv_queue(s);
}

// Note: This routine should be called with the sock lock held.
static void
mqtt_run_recv_queue(mqtt_sock_t *s)
{
	work_t *     work = nni_list_first(&s->recv_queue);
	mqtt_pipe_t *p    = s->mqtt_pipe;
	nni_msg *    msg;

	while (NULL != work) {
		if (0 != nni_lmq_getq(&p->recv_messages, &msg)) {
			break;
		}
		nni_list_remove(&s->recv_queue, work);
		// nni_pipe_recv(p->pipe, &work->recv_aio);
		nni_aio_set_msg(work->user_aio, msg);
		nni_aio_finish(work->user_aio, 0,
		    nni_msg_header_len(msg) + nni_msg_len(msg));
		mqtt_sock_free_work(s, work);
		work = nni_list_first(&s->recv_queue);
	}

	return;
}

// Note: This routine should be called with the sock lock held.
static void
mqtt_send_start(mqtt_sock_t *s)
{
	work_t *     work;
	mqtt_pipe_t *p = s->mqtt_pipe;
	uint16_t     packet_type;

	// no open pipe
	if (NULL == p) {
		return;
	}

	if (NULL != (work = nni_list_first(&s->send_queue))) {
		packet_type = nni_mqtt_msg_get_packet_type(work->msg);

		// we are not retransmitting the work
		if (0 == work->ntrial) {
			// only allow to send CONNECT, PINGREQ, PUBLISH,
			// SUBSCRIBE and UNSUBSCRIBE
			switch (packet_type) {
			case NNG_MQTT_CONNECT:
				// NOTE: the transport dialer handle CONNECT
				// fall through
			case NNG_MQTT_PINGREQ:
				break;

			case NNG_MQTT_PUBLISH:
				work->qos =
				    nni_mqtt_msg_get_publish_qos(work->msg);
				if (0 == work->qos) {
					break; // QoS 0 need no packet id
				}
				// fall through
			case NNG_MQTT_SUBSCRIBE:
			case NNG_MQTT_UNSUBSCRIBE:
				work->packet_id =
				    mqtt_pipe_get_next_packet_id(p);
				nni_mqtt_msg_set_packet_id(
				    work->msg, work->packet_id);
				NNI_ASSERT(nni_id_get(&p->send_unack,
				               work->packet_id) == NULL);
				if (0 !=
				    nni_id_set(&p->send_unack, work->packet_id,
				        work)) {
					// FIXME
				}
				break;

			default:
				work_set_error(work);
				nni_aio_finish_error(
				    work->user_aio, NNG_EPROTO);
				return;
			}

			nni_mqtt_msg_encode(work->msg);
		}

		work_set_send(work, packet_type);
		nni_msg_clone(work->msg);
		nni_aio_set_msg(&p->send_aio, work->msg);
		nni_pipe_send(p->pipe, &p->send_aio);
	}

	return;
}

/******************************************************************************
 *                           Context Implementation                           *
 ******************************************************************************/

static int
mqtt_ctx_init(void *arg, void *sock)
{
	mqtt_ctx_t * ctx = arg;
	mqtt_sock_t *s   = sock;

	ctx->mqtt_sock = s;

	return (0);
}

static void
mqtt_ctx_fini(void *arg)
{
	NNI_ARG_UNUSED(arg);
}

static void
mqtt_ctx_send(void *arg, nni_aio *aio)
{
	mqtt_ctx_t * ctx = arg;
	mqtt_sock_t *s   = ctx->mqtt_sock;
	work_t *     work;

	if (nni_aio_begin(aio) != 0) {
		return;
	}

	nni_mtx_lock(&s->mtx);

	if (nni_atomic_get_bool(&s->closed)) {
		nni_aio_finish_error(aio, NNG_ECLOSED);
		return;
	}

	work = mqtt_sock_get_work(s);

	if (NULL == work) {
		nni_mtx_unlock(&s->mtx);
		nni_aio_finish_error(aio, NNG_ENOMEM);
		return;
	}

	work->user_aio = aio;
	work->msg      = nni_aio_get_msg(aio);
	nni_aio_bump_count(
	    aio, nni_msg_header_len(work->msg) + nni_msg_len(work->msg));
	nni_list_append(&s->send_queue, work); // enqueue to send

	if (nni_list_first(&s->send_queue) == work) {
		mqtt_send_start(s);
	}

	nni_mtx_unlock(&s->mtx);
}

static void
mqtt_ctx_recv(void *arg, nni_aio *aio)
{
	mqtt_ctx_t * ctx = arg;
	mqtt_sock_t *s   = ctx->mqtt_sock;

	nni_mtx_lock(&s->mtx);

	if (nni_aio_begin(aio) != 0) {
		return;
	}

	if (nni_atomic_get_bool(&s->closed)) {
		nni_aio_finish_error(aio, NNG_ECLOSED);
		return;
	}

	mqtt_recv_start(s, aio);

	nni_mtx_unlock(&s->mtx);
}

/******************************************************************************
 *                                Proto                                       *
 ******************************************************************************/

static nni_proto_pipe_ops mqtt_pipe_ops = {
	.pipe_size  = sizeof(mqtt_pipe_t),
	.pipe_init  = mqtt_pipe_init,
	.pipe_fini  = mqtt_pipe_fini,
	.pipe_start = mqtt_pipe_start,
	.pipe_close = mqtt_pipe_close,
	.pipe_stop  = mqtt_pipe_stop,
};

static nni_option mqtt_ctx_options[] = {
	{
	    .o_name = NULL,
	},
};

static nni_proto_ctx_ops mqtt_ctx_ops = {
	.ctx_size    = sizeof(mqtt_ctx_t),
	.ctx_init    = mqtt_ctx_init,
	.ctx_fini    = mqtt_ctx_fini,
	.ctx_recv    = mqtt_ctx_recv,
	.ctx_send    = mqtt_ctx_send,
	.ctx_options = mqtt_ctx_options,
};

static nni_option mqtt_sock_options[] = {
	// terminate list
	{
	    .o_name = NULL,
	},
};

static nni_proto_sock_ops mqtt_sock_ops = {
	.sock_size    = sizeof(mqtt_sock_t),
	.sock_init    = mqtt_sock_init,
	.sock_fini    = mqtt_sock_fini,
	.sock_open    = mqtt_sock_open,
	.sock_close   = mqtt_sock_close,
	.sock_options = mqtt_sock_options,
	.sock_send    = mqtt_sock_send,
	.sock_recv    = mqtt_sock_recv,
};

static nni_proto mqtt_proto = {
	.proto_version  = NNI_PROTOCOL_VERSION,
	.proto_self     = { NNG_MQTT_SELF, NNG_MQTT_SELF_NAME },
	.proto_peer     = { NNG_MQTT_PEER, NNG_MQTT_PEER_NAME },
	.proto_flags    = NNI_PROTO_FLAG_SNDRCV,
	.proto_sock_ops = &mqtt_sock_ops,
	.proto_pipe_ops = &mqtt_pipe_ops,
	.proto_ctx_ops  = &mqtt_ctx_ops,
};

int
nng_mqtt_client_open(nng_socket *sock)
{
	return (nni_proto_open(sock, &mqtt_proto));
}
