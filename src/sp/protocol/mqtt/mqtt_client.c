// Author: eeff <eeff at eeff dot dev>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//
#include <stdio.h>

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

#define MQTT_WORK_NUM 64

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
static void mqtt_send_start(mqtt_sock_t *s, nni_aio *aio);
static void mqtt_recv_start(mqtt_sock_t *s, nni_aio *aio);
static void mqtt_run_send_queue(mqtt_sock_t *s);
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

// Work state indicating what MQTT packet we *expect* to send/recv.
typedef enum {
	WORK_START, // start state
	WORK_CONNECT,
	WORK_CONNACK,
	WORK_DISCONNECT,  // send      DISCONNECT
	WORK_PUBACK,      // send/recv PUBACK
	WORK_PUBCOMP,     // send/recv PUBCOMP
	WORK_PUBLISH,     // send/recv PUBLISH
	WORK_PUBRECV,     // send/recv PUBRECV
	WORK_PUBREL,      // send/recv PUBREL
	WORK_SUBSCRIBE,   // send      SUBSCRIBE
	WORK_SUBACK,      // recv      SUBACK
	WORK_UNSUBSCRIBE, // send      UNSUBSCRIBE
	WORK_UNSUBACK,    // recv      UNSUBACK
	WORK_ERROR,       // error state
	WORK_END,         // terminal state
} work_state_t;

// A work_t represents an asynchronous send/recv of MQTT packet.
typedef struct {
	work_state_t  state;
	uint8_t       qos;       // QoS of the MQTT PUBLISH packet
	uint16_t      packet_id; // packet id of the message that have it
	mqtt_sock_t * mqtt_sock;
	nni_msg *     msg;
	nni_aio *     user_aio;
	nni_aio       send_aio; // send aio to the underlying transport
	nni_list_node node;     // in one of send_queue, free_list
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
	nni_id_map      send_unack;    // send messages unacknowledged
	nni_id_map      recv_unack;    // recv messages unacknowledged
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
	nni_list        send_queue;           // work pending to send
	nni_list        recv_queue;           // work pending to receive
	nni_list        free_list;            // free list of work
	work_t          works[MQTT_WORK_NUM]; // pre allocated work
};

/******************************************************************************
 *                              Work Implementation                           *
 ******************************************************************************/

static inline void
work_init(work_t *work, mqtt_sock_t *s)
{
	work->state     = WORK_START;
	work->qos       = 0;
	work->packet_id = 0;
	work->msg       = NULL;
	work->user_aio  = NULL;
	nni_aio_init(&work->send_aio, mqtt_send_cb, work);
	work->mqtt_sock = s;
	NNI_LIST_NODE_INIT(&work->node);
}

static inline void
work_fini(work_t *work)
{
	nni_aio_fini(&work->send_aio);
}

static inline void
work_reset(work_t *work)
{
	work->state     = WORK_START;
	work->qos       = 0;
	work->packet_id = 0;
	nni_msg_free(work->msg);
	work->msg      = NULL;
	work->user_aio = NULL;
	nni_list_node_remove(&work->node);
}

// cancels any outstanding operation,
// and waits for the work to complete, if still running.
static inline void
work_stop(work_t *work)
{
	nni_aio_stop(&work->send_aio);
	nni_list_node_remove(&work->node);
}

// closes the aio for further activity.
// It aborts any in-progress transaction (if it can).
static inline void
work_close(work_t *work)
{
	nni_aio_close(&work->send_aio);
	if (NULL != work->user_aio) {
		nni_aio_finish_error(work->user_aio, NNG_ECONNRESET);
		work->msg      = NULL;
		work->user_aio = NULL;
	}
	nni_list_node_remove(&work->node);
}

static inline void
work_stop_queue(nni_list *queue)
{
	work_t *work;
	NNI_LIST_FOREACH (queue, work) {
		work_stop(work);
	}
}

static inline void
work_close_queue(nni_list *queue)
{
	work_t *work;
	NNI_LIST_FOREACH (queue, work) {
		work_close(work);
	}
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
	for (int i = 0; i < MQTT_WORK_NUM; ++i) {
		work_init(&s->works[i], s);
		nni_list_append(&s->free_list, &s->works[i]);
	}

	return (0);
}

static void
mqtt_sock_fini(void *arg)
{
	mqtt_sock_t *s = arg;

	nni_mtx_lock(&s->mtx);
	NNI_ASSERT(nni_list_empty(&s->send_queue));
	NNI_ASSERT(nni_list_empty(&s->recv_queue));
	nni_mtx_unlock(&s->mtx);

	for (int i = 0; i < MQTT_WORK_NUM; ++i) {
		work_fini(&s->works[i]);
	}

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

/******************************************************************************
 *                              Pipe Implementation                           *
 ******************************************************************************/

static int
mqtt_pipe_init(void *arg, nni_pipe *pipe, void *s)
{
	mqtt_pipe_t *p    = arg;
	mqtt_sock_t *sock = s;

	nni_mtx_lock(&sock->mtx);
	sock->mqtt_pipe = p;
	nni_mtx_unlock(&sock->mtx);

	nni_atomic_init_bool(&p->closed);
	nni_atomic_set_bool(&p->closed, false);
	nni_atomic_set(&p->next_packet_id, 0);
	p->pipe      = pipe;
	p->mqtt_sock = s;
	nni_aio_init(&p->recv_aio, mqtt_recv_cb, p);
	// Packet IDs are 16 bits
	// We start at a random point, to minimize likelihood of
	// accidental collision across restarts.
	nni_id_map_init(&p->send_unack, 0x0000u, 0xffffu, true);
	nni_id_map_init(&p->recv_unack, 0x0000u, 0xffffu, true);
	nni_lmq_init(&p->recv_messages, 1024); // FIXME: remove hard code value
	return (0);
}

static void
mqtt_pipe_fini(void *arg)
{
	mqtt_pipe_t *p = arg;
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
	mqtt_run_send_queue(s);
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
	nni_aio_stop(&p->recv_aio);
	work_stop_queue(&s->send_queue);
	work_stop_queue(&s->recv_queue);
	nni_mtx_unlock(&s->mtx);
}

static void
mqtt_pipe_close(void *arg)
{
	mqtt_pipe_t *p = arg;
	mqtt_sock_t *s = p->mqtt_sock;

	nni_mtx_lock(&s->mtx);
	mqtt_sock_close(s);
	s->mqtt_pipe = NULL;
	nni_aio_close(&p->recv_aio);
	work_close_queue(&s->send_queue);
	work_close_queue(&s->recv_queue);
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

static void
mqtt_send_cb(void *arg)
{
	work_t *     work = arg;
	mqtt_sock_t *s    = work->mqtt_sock;
	mqtt_pipe_t *p;

	nni_mtx_lock(&s->mtx);
	p = s->mqtt_pipe;

	if (nni_aio_result(&work->send_aio) != 0) {
		// We failed to send... clean up and deal with it.
		nni_msg_free(nni_aio_get_msg(&work->send_aio));
		nni_aio_set_msg(&work->send_aio, NULL);
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
	switch (work->state) {
	case WORK_CONNECT:
		// we have sent a CONNECT, expect receiving a CONNACK
		work->state = WORK_CONNACK;
		// FIXME
		work->state = WORK_END;
		break;

	case WORK_DISCONNECT:
		// we have sent a DISCONNECT, just close the socket.
		work->state = WORK_END;
		// FIXME: close the socket
		break;

	case WORK_PUBACK:
		// we have sent a PUBACK,
		// indicating a successful receipt of a QoS 1 message

		// fall through

	case WORK_PUBCOMP:
		// FIXME: check packet id
		// we have sent a PUBCOMP,
		// indicating a successful receipt of a QoS 2 message
		work->state = WORK_END;
		nni_id_remove(&p->recv_unack, work->packet_id);
		nni_lmq_putq(&p->recv_messages, work->msg);
		mqtt_run_recv_queue(s);
		work->msg = NULL;
		work_reset(work);
		nni_list_append(&s->free_list, work);
		nni_mtx_unlock(&s->mtx);
		return;

	case WORK_PUBLISH:
		// TODO: handle retry
		// we have sent a PUBLISH
		if (0 == work->qos) {
			// QoS 0, no further actions
			work->state = WORK_END;
		} else {
			// for QoS 1, expect receiving a PUBACK
			// for QoS 2, expect receiving a PUBRECV
			work->state =
			    (1 == work->qos) ? WORK_PUBACK : WORK_PUBRECV;
			if (0 !=
			    nni_id_set(
			        &p->send_unack, work->packet_id, work)) {
				// FIXME
			}
		}
		break;

	case WORK_PUBRECV:
		// we have sent a PUBRECV, expect receiving a PUBREL
		work->state = WORK_PUBREL;
		break;

	case WORK_PUBREL:
		// we have sent a PUBREL, expect receiving a PUBCOMP
		work->state = WORK_PUBCOMP;
		break;

	case WORK_SUBSCRIBE:
		// we have sent a SUBSCRIBE, expect receiving a SUBACK
		work->state = WORK_SUBACK;
		nni_id_set(&p->send_unack, work->packet_id, work);
		break;

	case WORK_UNSUBSCRIBE:
		// we have sent a UNSUBSCRIBE, expect receiving a UNSUBACK
		work->state = WORK_UNSUBACK;
		nni_id_set(&p->send_unack, work->packet_id, work);
		break;

	default:
		work->state = WORK_ERROR;
		break;
	}

	if (WORK_ERROR == work->state) {
		// MQTT protocol error, terminate the connection
		nni_aio_finish_error(work->user_aio, NNG_EPROTO);
		nni_mtx_unlock(&s->mtx);
		nni_pipe_close(p->pipe);
		return;
	} else if (WORK_END == work->state) {
		// good news, protocol state machine run to the end
		if (NULL != work->user_aio) {
			nni_aio_finish_sync(work->user_aio, 0, 0);
		}
		work_reset(work);
		nni_list_append(&s->free_list, work);
	}

	nni_mtx_unlock(&s->mtx);
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

	nni_mqtt_packet_type packet_type = nni_mqtt_msg_get_packet_type(msg);
	int32_t              packet_id;
	uint8_t              qos;

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
		// we have received a SUBACK, successful subcription

		// fall through

	case NNG_MQTT_UNSUBACK:
		// we have received a UNSUBACK, successful unsubcription
		// FIXME: check packet type match
		packet_id = nni_mqtt_msg_get_packet_id(msg);
		work      = nni_id_get(&p->send_unack, packet_id);
		if (NULL == work) {
			nni_msg_free(msg);
			nni_mtx_unlock(&s->mtx);
			nni_pipe_close(p->pipe);
			return;
		}
		nni_msg_free(msg);
		nni_id_remove(&p->send_unack, packet_id);
		work->state = WORK_END;
		break;

	case NNG_MQTT_PUBREC:
		// we have received a PUBRECV in the QoS 2 delivery,
		// then send a PUBREL
		packet_id = nni_mqtt_msg_get_pubrec_packet_id(msg);
		work      = nni_id_get(&p->send_unack, packet_id);
		if (NULL == work) {
			// ignore this message
			nni_msg_free(msg);
			nni_mtx_unlock(&s->mtx);
			return;
		}
		// the transport handled sending the PUBREL for us
		// work->state = WORK_PUBREL;
		// reuse msg
		// nni_mqtt_msg_set_packet_type(msg, NNG_MQTT_PUBREL);
		// nni_mqtt_msg_set_pubrel_packet_id(msg, packet_id);
		// nni_mqtt_msg_encode(msg);
		// nni_aio_set_msg(&work->send_aio, msg);
		// nni_pipe_send(p->pipe, &work->send_aio);
		nni_id_remove(&p->send_unack, packet_id);
		work->state = WORK_PUBCOMP;
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
		work->state = WORK_END;
		nni_id_remove(&p->recv_unack, work->packet_id);
		nni_lmq_putq(&p->recv_messages, work->msg);
		mqtt_run_recv_queue(s);
		work->msg = msg;
		work_reset(work);
		nni_list_append(&s->free_list, work);
		nni_mtx_unlock(&s->mtx);
		return;
		// work->state = WORK_PUBCOMP;
		// reuse msg
		// nni_mqtt_msg_set_packet_type(msg, NNG_MQTT_PUBCOMP);
		// nni_mqtt_msg_set_pubcomp_packet_id(msg, packet_id);
		// nni_mqtt_msg_encode(msg);
		// nni_aio_set_msg(&work->send_aio, msg);
		// nni_pipe_send(p->pipe, &work->send_aio);
		break;

	case NNG_MQTT_PUBLISH:
		// we have received a PUBLISH
		qos = nni_mqtt_msg_get_publish_qos(msg);
		if (2 > qos) {
			// QoS 0, successful receipt
			// QoS 1, the transport handled sending a PUBACK
			nni_lmq_putq(&p->recv_messages, msg);
			mqtt_run_recv_queue(s);
			nni_mtx_unlock(&s->mtx);
			return;
		} else {
			work = nni_list_first(&s->free_list);
			nni_list_remove(&s->free_list, work);
			// keep the message, and alloc a new ack message
			work->qos = qos;
			work->msg = msg;
			work->packet_id =
			    nni_mqtt_msg_get_publish_packet_id(msg);
			// the transport handled sending PUBACK/PUBRECV
			work->state = WORK_PUBREL;
			nni_id_set(&p->recv_unack, work->packet_id, work);
			// nni_mqtt_msg_alloc(&msg, 0);
			// QoS 2, then send a PUBRECV
			// work->state = WORK_PUBRECV;
			// nni_mqtt_msg_set_packet_type(msg, NNG_MQTT_PUBREC);
			// nni_mqtt_msg_set_pubrec_packet_id(msg,
			// work->packet_id);
			// nni_mqtt_msg_encode(msg);
			// nni_aio_set_msg(&work->send_aio, msg);
			// nni_pipe_send(p->pipe, &work->send_aio);
		}
		break;

	default:
		// something bad happen
		break;
	}

	if (WORK_ERROR == work->state) {
		// protocol error, just close the connection
		nni_aio_finish_error(work->user_aio, NNG_EPROTO);
		nni_mtx_unlock(&s->mtx);
		nni_pipe_close(p->pipe);
		return;
	} else if (WORK_END == work->state) {
		// good news, protocol state machine run to the end
		nni_aio_finish_sync(work->user_aio, 0, 0);
		work_reset(work);
		nni_list_append(&s->free_list, work);
	}

	nni_mtx_unlock(&s->mtx);

	return;
}

static void
mqtt_send_start(mqtt_sock_t *s, nni_aio *aio)
{
	work_t *work;

	nni_mtx_lock(&s->mtx);

	work = nni_list_first(&s->free_list);
	if (NULL == work) {
		nni_mtx_unlock(&s->mtx);
		nni_aio_finish_error(aio, NNG_EBUSY);
		return;
	}

	work->user_aio = aio;
	nni_list_remove(&s->free_list, work);
	nni_list_append(&s->send_queue, work); // enqueue to send
	mqtt_run_send_queue(s);

	nni_mtx_unlock(&s->mtx);
}

static void
mqtt_recv_start(mqtt_sock_t *s, nni_aio *aio)
{
	work_t *work;

	nni_mtx_lock(&s->mtx);

	work = nni_list_first(&s->free_list);

	if (NULL == work) {
		nni_mtx_unlock(&s->mtx);
		nni_aio_finish_error(aio, NNG_EBUSY);
		return;
	}

	work->user_aio = aio;
	work->state    = WORK_PUBLISH;
	nni_list_remove(&s->free_list, work);
	nni_list_append(&s->recv_queue, work); // enqueue to recv
	mqtt_run_recv_queue(s);

	nni_mtx_unlock(&s->mtx);
}

// Note: This routine should be called with the sock lock held.
static void
mqtt_run_recv_queue(mqtt_sock_t *s)
{
	work_t *     work = nni_list_first(&s->recv_queue);
	mqtt_pipe_t *p    = s->mqtt_pipe;
	nni_msg *    msg;

	while (NULL != work) {
		if (nni_lmq_getq(&p->recv_messages, &msg)) {
			break;
		}
		nni_list_remove(&s->recv_queue, work);
		// nni_pipe_recv(p->pipe, &work->recv_aio);
		nni_aio_set_msg(work->user_aio, msg);
		nni_aio_finish_sync(work->user_aio, 0, nni_msg_len(msg));
		nni_list_append(&s->free_list, work);
		work = nni_list_first(&s->recv_queue);
	}

	return;
}

// Note: This routine should be called with the sock lock held.
static void
mqtt_run_send_queue(mqtt_sock_t *s)
{
	work_t *     work;
	mqtt_pipe_t *p = s->mqtt_pipe;
	uint16_t     packet_type;

	// no open pipe
	if (NULL == p) {
		return;
	}

	// TODO: handle retry
	while (NULL != (work = nni_list_first(&s->send_queue))) {
		nni_list_remove(&s->send_queue, work);
		nni_msg *msg = nni_aio_get_msg(work->user_aio);
		packet_type  = nni_mqtt_msg_get_packet_type(msg);

		// only allow to send PUBLISH, SUBSCRIBE and UNSUBSCRIBE packet
		switch (packet_type) {
		case NNG_MQTT_CONNECT:
			work->state = WORK_CONNECT;
			break;
		case NNG_MQTT_PUBLISH:
			work->state     = WORK_PUBLISH;
			work->packet_id = mqtt_pipe_get_next_packet_id(p);
			nni_mqtt_msg_set_publish_packet_id(
			    msg, work->packet_id);
			work->qos = nni_mqtt_msg_get_publish_qos(msg);
			break;
		case NNG_MQTT_SUBSCRIBE:
			work->state     = WORK_SUBSCRIBE;
			work->packet_id = mqtt_pipe_get_next_packet_id(p);
			nni_mqtt_msg_set_subscribe_packet_id(
			    msg, work->packet_id);
			break;
		case NNG_MQTT_UNSUBSCRIBE:
			work->state     = WORK_UNSUBSCRIBE;
			work->packet_id = mqtt_pipe_get_next_packet_id(p);
			nni_mqtt_msg_set_unsubscribe_packet_id(
			    msg, work->packet_id);
			break;
		default:
			work->state = WORK_ERROR;
			nni_aio_finish_error(work->user_aio, NNG_EPROTO);
			return;
		}

		nni_msg_clone(msg);
		nni_aio_set_msg(work->user_aio, NULL);
		nni_aio_bump_count(work->user_aio, nni_msg_len(msg));
		work->msg = msg;
		nni_aio_set_msg(&work->send_aio, msg);
		nni_pipe_send(p->pipe, &work->send_aio);
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

	if (nni_aio_begin(aio) != 0) {
		return;
	}

	if (nni_atomic_get_bool(&s->closed)) {
		nni_aio_finish_error(aio, NNG_ECLOSED);
		return;
	}

	mqtt_send_start(s, aio);
}

static void
mqtt_ctx_recv(void *arg, nni_aio *aio)
{
	mqtt_ctx_t * ctx = arg;
	mqtt_sock_t *s   = ctx->mqtt_sock;

	if (nni_aio_begin(aio) != 0) {
		return;
	}

	if (nni_atomic_get_bool(&s->closed)) {
		nni_aio_finish_error(aio, NNG_ECLOSED);
		return;
	}

	mqtt_recv_start(s, aio);
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
