// Author: eeff <eeff at eeff dot dev>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "core/nng_impl.h"
#include "supplemental/mqtt/mqtt_msg.h"

// MQTT client implementation.
//
// 1. MQTT client sockets have a single implicit dialer, and cannot
//    support creation of additional dialers or listeners.
// 2. Send sends PUBLISH messages.
// 3. Receive is used to receive published data from the server.

#define NNG_MQTT_SELF 0
#define NNG_MQTT_SELF_NAME "mqtt-client"
#define NNG_MQTT_PEER 0
#define NNG_MQTT_PEER_NAME "mqtt-server"

typedef struct mqtt_sock_s mqtt_sock_t;
typedef struct mqtt_pipe_s mqtt_pipe_t;
typedef struct mqtt_ctx_s  mqtt_ctx_t;

static void mqtt_sock_init(void *arg, nni_sock *sock);
static void mqtt_sock_fini(void *arg);
static void mqtt_sock_open(void *arg);
static void mqtt_sock_send(void *arg, nni_aio *aio);
static void mqtt_sock_recv(void *arg, nni_aio *aio);
static void mqtt_send_cb(void *arg);
static void mqtt_recv_cb(void *arg);
static void mqtt_keep_alive_cb(void *arg);
static void mqtt_timer_cb(void *arg);
static void mqtt_run_recv_queue(mqtt_sock_t *s);

static int  mqtt_pipe_init(void *arg, nni_pipe *pipe, void *s);
static void mqtt_pipe_fini(void *arg);
static int  mqtt_pipe_start(void *arg);
static void mqtt_pipe_stop(void *arg);
static void mqtt_pipe_close(void *arg);

static void mqtt_ctx_init(void *arg, void *sock);
static void mqtt_ctx_fini(void *arg);
static void mqtt_ctx_send(void *arg, nni_aio *aio);
static void mqtt_ctx_recv(void *arg, nni_aio *aio);

typedef nni_mqtt_packet_type packet_type_t;

// A mqtt_ctx_s is our per-ctx protocol private state.
struct mqtt_ctx_s {
	mqtt_sock_t *mqtt_sock;
	nni_aio *  saio;             // send aio
	nni_aio *  raio;             // recv aio
	nni_list_node sqnode;
	nni_list_node rqnode;
};

// A mqtt_pipe_s is our per-pipe protocol private structure.
struct mqtt_pipe_s {
	nni_atomic_bool closed;
	nni_atomic_int  next_packet_id; // next packet id to use
	nni_pipe *      pipe;
	mqtt_sock_t *   mqtt_sock;
	// work_t          ping_work;     // work to send a ping request
	nni_id_map      sent_unack;    // send messages unacknowledged
	nni_id_map      recv_unack;    // recv messages unacknowledged
	nni_aio         send_aio;      // send aio to the underlying transport
	nni_aio         recv_aio;      // recv aio to the underlying transport
	nni_lmq         recv_messages; // recv messages queue
	nni_lmq         send_messages; // send messages queue
	nni_lmq         ctx_aios;      // awaiting aio of QoS
	bool            busy;
};

// A mqtt_sock_s is our per-socket protocol private structure.
struct mqtt_sock_s {
	nni_atomic_bool closed;
	nni_atomic_int  ttl;
	nni_duration    retry;
	nni_mtx         mtx;    // more fine grained mutual exclusion
	mqtt_ctx_t      master; // to which we delegate send/recv calls
	mqtt_pipe_t *   mqtt_pipe;
	nni_list        recv_queue; // ctx pending to receive
	// nni_list        free_list;  // free list of work
};

/******************************************************************************
 *                              Sock Implementation                           *
 ******************************************************************************/

static void
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
	NNI_LIST_INIT(&s->recv_queue, mqtt_ctx_t, rqnode);
	// NNI_LIST_INIT(&s->free_list, work_t, node);
}

static void
mqtt_sock_fini(void *arg)
{
	mqtt_sock_t *s = arg;
	// work_t *     work;

	// nni_mtx_lock(&s->mtx);
	// NNI_ASSERT(nni_list_empty(&s->recv_queue));

	// while (NULL != (work = nni_list_first(&s->free_list))) {
	// 	nni_list_remove(&s->free_list, work);
	// 	work_fini(work);
	// 	nni_free(work, sizeof(work_t));
	// }
	// nni_mtx_unlock(&s->mtx);

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
static inline void
mqtt_sock_close_work_queue(mqtt_sock_t *s, nni_list *queue)
{
	nni_msg * msg;
	while (NULL != (msg = nni_list_first(queue))) {
		nni_msg_free(msg);
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
	// passing keep alive timeout
	// work_init(&p->ping_work, s, sock->retry, mqtt_keep_alive_cb);
	// nni_mqtt_msg_alloc(&p->ping_work.msg, 0);
	// nni_mqtt_msg_set_packet_type(p->ping_work.msg, NNG_MQTT_PINGREQ);
	// work_set_send(&p->ping_work, NNG_MQTT_PINGREQ);
	// nni_mqtt_msg_encode(p->ping_work.msg);
	nni_aio_init(&p->send_aio, mqtt_send_cb, p);
	nni_aio_init(&p->recv_aio, mqtt_recv_cb, p);
	// Packet IDs are 16 bits
	// We start at a random point, to minimize likelihood of
	// accidental collision across restarts.
	nni_id_map_init(&p->sent_unack, 0x0000u, 0xffffu, true);
	nni_id_map_init(&p->recv_unack, 0x0000u, 0xffffu, true);
	nni_lmq_init(&p->recv_messages, 1024); // remove hard code value
	nni_lmq_init(&p->send_messages, 1024); // remove hard code value

	return (0);
}

static void
mqtt_pipe_fini(void *arg)
{
	mqtt_pipe_t *p = arg;
	nni_msg * msg;
	// work_fini(&p->ping_work);
	if ((msg = nni_aio_get_msg(&p->recv_aio)) != NULL) {
		nni_aio_set_msg(&p->recv_aio, NULL);
		nni_msg_free(msg);
	}
	if ((msg = nni_aio_get_msg(&p->send_aio)) != NULL) {
		nni_aio_set_msg(&p->send_aio, NULL);
		nni_msg_free(msg);
	}

	nni_aio_fini(&p->send_aio);
	nni_aio_fini(&p->recv_aio);
	nni_id_map_fini(&p->sent_unack);
	nni_id_map_fini(&p->recv_unack);
	nni_lmq_fini(&p->recv_messages);
	nni_lmq_fini(&p->send_messages);
}

static int
mqtt_pipe_start(void *arg)
{
	mqtt_pipe_t *p = arg;
	mqtt_sock_t *s = p->mqtt_sock;

	nni_mtx_lock(&s->mtx);
	s->mqtt_pipe = p;
	// mqtt_send_start(s);
	nni_mtx_unlock(&s->mtx);
	// work_timer_schedule(&p->ping_work);
	nni_pipe_recv(p->pipe, &p->recv_aio);

	return (0);
}

static void
mqtt_pipe_stop(void *arg)
{
	mqtt_pipe_t *p = arg;
	nni_aio_stop(&p->send_aio);
	nni_aio_stop(&p->recv_aio);
}

void
mqtt_close_unack_work_cb(void *arg)
{
	nni_msg * msg = arg;
	nni_msg_free(msg);
	//TODO trigger aio inside msg?
	// mqtt_sock_close_work(work->mqtt_sock, work);
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
	// mqtt_sock_close_work_queue(s, &s->recv_queue);
	//TODO free msg for each map
	nni_id_map_foreach(&p->sent_unack, mqtt_close_unack_work_cb);
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
	if (0 != nni_lmq_put(&p->recv_messages, msg)) {
		// resize to ensure we do not lost messages
		// add option to drop messages
		if (0 !=
		    nni_lmq_resize(&p->recv_messages,
		        nni_lmq_len(&p->recv_messages) * 2)) {
			// drop the message when no memory available
			nni_msg_free(msg);
			return;
		}
		nni_lmq_put(&p->recv_messages, msg);
	}
}

// Keep alive timer callback to send ping request.
static void
mqtt_keep_alive_cb(void *arg)
{
}

// Timer callback, we use it for retransmitting.
static void
mqtt_timer_cb(void *arg)
{
}

static void
mqtt_send_cb(void *arg)
{
	mqtt_pipe_t *p = arg;
	mqtt_sock_t *s = p->mqtt_sock;
	nni_msg     *msg;

	if (nni_aio_result(&p->send_aio) != 0) {
		// We failed to send... clean up and deal with it.
		nni_msg_free(nni_aio_get_msg(&p->send_aio));
		nni_aio_set_msg(&p->send_aio, NULL);
		nni_mtx_unlock(&s->mtx);
		nni_pipe_close(p->pipe);
		return;
	}
	nni_mtx_lock(&s->mtx);

	if (nni_atomic_get_bool(&s->closed) ||
	    nni_atomic_get_bool(&p->closed)) {
		// This occurs if the mqtt_pipe_close has been called.
		// In that case we don't want any more processing.
		nni_mtx_unlock(&s->mtx);
		return;
	}
	if (nni_lmq_get(&p->send_messages, &msg) == 0) {
		nni_mqtt_msg_encode(msg);
		nni_aio_set_msg(&p->send_aio, msg);
		nni_pipe_send(p->pipe, &p->send_aio);
		nni_mtx_unlock(&s->mtx);
		return;
	}

	p->busy = false;
	nni_mtx_unlock(&s->mtx);
	return;
}

static void
mqtt_recv_cb(void *arg)
{
	mqtt_pipe_t *p = arg;
	mqtt_sock_t *s = p->mqtt_sock;
	nni_aio * user_aio = NULL;
	nni_msg * cached_msg = NULL;
	mqtt_ctx_t * ctx;


	if (nni_aio_result(&p->recv_aio) != 0) {
		nni_pipe_close(p->pipe);
		return;
	}

	nni_mtx_lock(&s->mtx);
	nni_msg *msg = nni_aio_get_msg(&p->recv_aio);
	nni_aio_set_msg(&p->recv_aio, NULL);
	if (nni_atomic_get_bool(&s->closed) ||
	    nni_atomic_get_bool(&p->closed)) {
		//free msg and dont return data when pipe is closed.
		if (msg) {
			nni_msg_free(msg);
		}
		nni_mtx_unlock(&s->mtx);
		return;
	}
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
		packet_id  = nni_mqtt_msg_get_packet_id(msg);
		cached_msg = nni_id_get(&p->sent_unack, packet_id);
		if (cached_msg != NULL) {
			nni_id_remove(&p->sent_unack, packet_id);
			user_aio   = nni_mqtt_msg_get_aio(cached_msg);
			nni_msg_free(cached_msg);
		}
		nni_msg_free(msg);
		break;

	case NNG_MQTT_PINGRESP:
		// do nothing
		nni_mtx_unlock(&s->mtx);
		return;

	case NNG_MQTT_PUBREC:
		// // we have received a PUBREC in the QoS 2 delivery,
		// // then send a PUBREL
		// packet_id = nni_mqtt_msg_get_pubrec_packet_id(msg);
		// nni_msg_free(msg);
		// work = nni_id_get(&p->sent_unack, packet_id);
		// if (NULL == work) {
		// 	// ignore this message
		// 	nni_mtx_unlock(&s->mtx);
		// 	return;
		// }
		// // the transport handled sending the PUBREL for us,
		// // expect to receive a PUBCOMP
		// if (work_packet_type(work) == packet_type) {
		// 	work_set_recv(work, NNG_MQTT_PUBCOMP);
		// 	work_timer_cancel(work);
		// } else if (work_packet_type(work) == NNG_MQTT_PUBLISH &&
		//     2 == work->qos) {
		// 	// scheduling disorder
		// 	work_set_acked(work);
		// } else {
		// 	work_set_error(work);
		// 	work_timer_cancel(work);
		// }
		nni_msg_free(msg);
		break;

	case NNG_MQTT_PUBREL:
		// we have received a PUBREL, then send a PUBCOMP
		// packet_id = nni_mqtt_msg_get_pubrel_packet_id(msg);
		// cached_msg      = nni_id_get(&p->recv_unack, packet_id);
		// if (NULL == work) {
		// 	// ignore this message
		// 	nni_msg_free(msg);
		// 	nni_mtx_unlock(&s->mtx);
		// 	return;
		// }
		// // the transport handled sending the PUBCOMP for us
		// work_set_final(work);
		// nni_id_remove(&p->recv_unack, work->packet_id);
		// ownership of work->msg to the lmq
		// mqtt_pipe_recv_msgq_putq(p, work->msg);
		// mqtt_run_recv_queue(s);
		// work->msg = msg;
		// mqtt_sock_free_work(s, work); // will release msg
		// nni_mtx_unlock(&s->mtx);
		packet_id = nni_mqtt_msg_get_pubrel_packet_id(msg);
		cached_msg = nni_id_get(&p->recv_unack, packet_id);
		nni_msg_free(msg);
		if (cached_msg == NULL) {
			nni_plat_printf("ERROR! packet id %d not found", packet_id);
			break;
		}

		if ((ctx = nni_list_first(&s->recv_queue)) == NULL) {
			// No one waiting to receive yet, putting msg
			// into lmq
			mqtt_pipe_recv_msgq_putq(p, cached_msg);
			nni_mtx_unlock(&s->mtx);
			nni_println("ERROR: no ctx found!! create more ctxs!");
			return;
		}
		nni_list_remove(&s->recv_queue, ctx);
		user_aio  = ctx->raio;
		ctx->raio = NULL;
		nni_aio_set_msg(user_aio, cached_msg);
		nni_mtx_unlock(&s->mtx);
		nni_aio_finish(user_aio, 0, nni_msg_len(cached_msg));
		return;

	case NNG_MQTT_PUBLISH:
		// we have received a PUBLISH
		qos = nni_mqtt_msg_get_publish_qos(msg);
		if (2 > qos) {
			// QoS 0, successful receipt
			// QoS 1, the transport handled sending a PUBACK
			// mqtt_pipe_recv_msgq_putq(p, msg);
			// mqtt_run_recv_queue(s);
			if ((ctx = nni_list_first(&s->recv_queue)) == NULL) {
				// No one waiting to receive yet, putting msg
				// into lmq
				mqtt_pipe_recv_msgq_putq(p, msg);
				nni_mtx_unlock(&s->mtx);
				nni_println("ERROR: no ctx found!! create more ctxs!");
				return;
			}
			nni_list_remove(&s->recv_queue, ctx);
			user_aio = ctx->raio;
			ctx->raio = NULL;
			nni_aio_set_msg(user_aio, msg);
			nni_mtx_unlock(&s->mtx);
			nni_aio_finish(user_aio, 0, nni_msg_len(msg));
			return;
		} else {
			// work = mqtt_sock_get_work(s);
			// if (work == NULL) {
			// 	nni_mtx_unlock(&s->mtx);
			// 	nni_pipe_close(p->pipe);
			// 	return;
			// }
			// work->qos = qos;
			// work->msg = msg; // keep the message
			// work->packet_id =
			//     nni_mqtt_msg_get_publish_packet_id(msg);
			// // the transport handled sending PUBREC,
			// // expect to receive a PUBREL
			// work_set_recv(work, NNG_MQTT_PUBREL);
			packet_id = nni_mqtt_msg_get_publish_packet_id(msg);
			nni_id_set(&p->recv_unack, packet_id, msg);
		}
		break;

	default:
		// unexpected packet type, server misbehaviour
		nni_mtx_unlock(&s->mtx);
		nni_pipe_close(p->pipe);
		return;
	}

	// if (work_is_error(work)) {
	// 	// protocol error, just close the connection
	// 	nni_mtx_unlock(&s->mtx);
	// 	nni_aio_finish_error(work->user_aio, NNG_EPROTO);
	// 	nni_pipe_close(p->pipe);
	// 	return;
	// } else if (work_is_final(work)) {
	// 	// good news, protocol state machine run to the end
	// 	nni_aio *aio = work->user_aio;
	// 	mqtt_sock_free_work(s, work);
	// 	nni_mtx_unlock(&s->mtx);
	// 	nni_aio_finish(aio, 0, 0);
	// 	return;
	// }

	nni_mtx_unlock(&s->mtx);
	if (user_aio) {
		nni_aio_finish(user_aio, 0, 0);
	}

	return;
}

// Note: This routine should be called with the sock lock held.
// static void
// mqtt_run_recv_queue(mqtt_sock_t *s)
// {
// 	work_t *     work = nni_list_first(&s->recv_queue);
// 	mqtt_pipe_t *p    = s->mqtt_pipe;
// 	nni_msg *    msg;

// 	while (NULL != work) {
// 		if (0 != nni_lmq_get(&p->recv_messages, &msg)) {
// 			break;
// 		}
// 		nni_list_remove(&s->recv_queue, work);
// 		// nni_pipe_recv(p->pipe, &work->recv_aio);
// 		nni_aio_set_msg(work->user_aio, msg);
// 		nni_aio_finish(work->user_aio, 0,
// 		    nni_msg_header_len(msg) + nni_msg_len(msg));
// 		mqtt_sock_free_work(s, work);
// 		work = nni_list_first(&s->recv_queue);
// 	}

// 	return;
// }

/******************************************************************************
 *                           Context Implementation                           *
 ******************************************************************************/

static void
mqtt_ctx_init(void *arg, void *sock)
{
	mqtt_ctx_t * ctx = arg;
	mqtt_sock_t *s   = sock;

	ctx->mqtt_sock = s;
	NNI_LIST_NODE_INIT(&ctx->sqnode);
	NNI_LIST_NODE_INIT(&ctx->rqnode);
}

static void
mqtt_ctx_fini(void *arg)
{
	mqtt_ctx_t * ctx = arg;
	mqtt_sock_t *s   = ctx->mqtt_sock;
	nni_aio *  aio;

	nni_mtx_lock(&s->mtx);
	if ((aio = ctx->saio) != NULL) {
		ctx->saio     = NULL;
		nni_aio_finish_error(aio, NNG_ECLOSED);
	}
	if ((aio = ctx->raio) != NULL) {
		nni_list_remove(&s->recv_queue, ctx);
		ctx->raio = NULL;
		nni_aio_finish_error(aio, NNG_ECLOSED);
	}
	nni_mtx_unlock(&s->mtx);
}

static void
mqtt_ctx_send(void *arg, nni_aio *aio)
{
	mqtt_ctx_t * ctx = arg;
	mqtt_sock_t *s   = ctx->mqtt_sock;
	mqtt_pipe_t *p   = s->mqtt_pipe;
	uint16_t     ptype, packet_id;
	uint8_t      qos;
	nni_msg *    msg;
	nni_msg *    tmsg;

	if (nni_aio_begin(aio) != 0) {
		return;
	}

	nni_mtx_lock(&s->mtx);

	if (nni_atomic_get_bool(&s->closed)) {
		nni_mtx_unlock(&s->mtx);
		nni_aio_finish_error(aio, NNG_ECLOSED);
		return;
	}
	msg   = nni_aio_get_msg(aio);
	ptype = nni_mqtt_msg_get_packet_type(msg);
	switch (ptype) {
	case NNG_MQTT_CONNECT:
	case NNG_MQTT_PINGREQ:
		break;

	case NNG_MQTT_PUBLISH:
		qos = nni_mqtt_msg_get_publish_qos(msg);
		if (0 == qos) {
			nni_aio_finish(aio, 0, 0);
			break; // QoS 0 need no packet id
		}
	case NNG_MQTT_SUBSCRIBE:
	case NNG_MQTT_UNSUBSCRIBE:
		packet_id     = mqtt_pipe_get_next_packet_id(p);
		nni_mqtt_msg_set_packet_id(msg, packet_id);
		nni_mqtt_msg_set_aio(msg, aio);
		tmsg = nni_id_get(&p->sent_unack, packet_id);
		if (tmsg != NULL) {
			nni_plat_printf("Warning : msg %d lost due to "
			                "insufficient computing power!",
			    packet_id);
			nni_aio_finish_error(
			    nni_mqtt_msg_get_aio(tmsg), NNG_EPROTO);
			nni_msg_free(tmsg);
			nni_id_remove(&p->sent_unack, packet_id);
		}
		nni_msg_clone(msg);
		if (nni_id_set(&p->sent_unack, packet_id, msg) != 0) {
			nni_println("Warning! QoS msg caching failed");
			nni_msg_free(msg);
		}
		break;

	default:
		nni_mtx_unlock(&s->mtx);
		nni_aio_finish_error(aio, NNG_EPROTO);
		return;
	}
	if (!p->busy) {
		p->busy = true;
		nni_mqtt_msg_encode(msg);
		nni_aio_set_msg(&p->send_aio, msg);
		nni_aio_bump_count(aio,
		    nni_msg_header_len(msg) + nni_msg_len(msg));
		nni_pipe_send(p->pipe, &p->send_aio);
		nni_mtx_unlock(&s->mtx);
		nni_aio_set_msg(aio, NULL);
		return;
	}
	if (nni_lmq_full(&p->send_messages)) {
		(void) nni_lmq_get(&p->send_messages, &tmsg);
		nni_msg_free(tmsg);
	}

	if (0 != nni_lmq_put(&p->send_messages, msg)) {
		nni_println("Warning! msg lost due to busy socket");
	}
	nni_mtx_unlock(&s->mtx);
	nni_aio_set_msg(aio, NULL);
	return;
}

static void
mqtt_ctx_recv(void *arg, nni_aio *aio)
{
	mqtt_ctx_t * ctx = arg;
	mqtt_sock_t *s   = ctx->mqtt_sock;
	mqtt_pipe_t *p   = s->mqtt_pipe;
	nni_msg     *msg = NULL;

	if (nni_aio_begin(aio) != 0) {
		return;
	}

	nni_mtx_lock(&s->mtx);
	if (nni_atomic_get_bool(&s->closed) || nni_atomic_get_bool(&p->closed)) {
		nni_mtx_unlock(&s->mtx);
		nni_aio_finish_error(aio, NNG_ECLOSED);
		return;
	}

	if (nni_lmq_get(&p->recv_messages, &msg) == 0) {
		nni_aio_set_msg(aio, msg);
		nni_mtx_unlock(&s->mtx);
		//let user gets a quick reply
		nni_aio_finish(aio, 0, nni_msg_len(msg));
		return;
	}

	// no open pipe or msg wating
	if (ctx->raio != NULL) {
		nni_mtx_unlock(&s->mtx);
		nni_println("ERROR! former aio not finished!");
		nni_aio_finish_error(aio, NNG_ESTATE);
		return;
	}
	ctx->raio = aio;
	nni_list_append(&s->recv_queue, ctx);
	nni_mtx_unlock(&s->mtx);
	return;
	// msg = nni_aio_get_msg(&p->recv_aio);
	// if (msg == NULL) {
	// 	nni_mtx_unlock(&s->mtx);
	// 	return;
	// }
	// nni_aio_set_msg(&p->recv_aio, NULL);
	// nni_mtx_unlock(&s->mtx);
	// nni_aio_set_msg(aio, msg);
	// nni_aio_finish(aio, 0, nni_msg_len(msg));
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
