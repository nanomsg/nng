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

#define MQTT_WORK_NUM 16

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
	WORK_DISCONNECT, // send      DISCONNECT
	WORK_PUBACK,     // send/recv PUBACK
	WORK_PUBCOMP,    // send/recv PUBCOMP
	WORK_PUBLISH,    // send/recv PUBLISH
	WORK_PUBRECV,    // send/recv PUBRECV
	WORK_PUBREL,     // send/recv PUBREL
	WORK_SUBSCRIBE,  // send      SUBSCRIBE
	WORK_SUBACK,     // recv      SUBACK
	WORK_ERROR,      // error state
	WORK_END,        // terminal state
} work_state_t;

// A work_t represents an asynchronous send/recv of MQTT packet.
typedef struct {
	work_state_t  state;
	uint8_t       qos; // QoS of the MQTT PUBLISH packet
	mqtt_sock_t * mqtt_sock;
	nni_aio *     user_aio;
	nni_aio       send_aio; // send aio to the underlying transport
	nni_aio       recv_aio; // recv aio to the underlying transport
	nni_list_node node;     // in one of send_queue, free_list
} work_t;

// A mqtt_ctx_s is our per-ctx protocol private state.
struct mqtt_ctx_s {
	mqtt_sock_t *mqtt_sock;
};

// A mqtt_pipe_s is our per-pipe protocol private structure.
struct mqtt_pipe_s {
	nni_atomic_bool closed;
	nni_pipe *      pipe;
	mqtt_sock_t *   mqtt_sock;
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
	work->user_aio  = NULL;
	work->mqtt_sock = s;
	nni_aio_init(&work->send_aio, mqtt_send_cb, work);
	nni_aio_init(&work->recv_aio, mqtt_recv_cb, work);
	NNI_LIST_NODE_INIT(&work->node);
}

static inline void
work_fini(work_t *work)
{
	nni_aio_fini(&work->send_aio);
	nni_aio_fini(&work->recv_aio);
}

static inline void
work_reset(work_t *work)
{
	work->state    = WORK_START;
	work->qos      = 0;
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
	p->pipe      = pipe;
	p->mqtt_sock = s;
	return (0);
}

static void
mqtt_pipe_fini(void *arg)
{
	NNI_ARG_UNUSED(arg);
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
	mqtt_run_recv_queue(s);
	nni_mtx_unlock(&s->mtx);

	return (0);
}

static void
mqtt_pipe_stop(void *arg)
{
	mqtt_pipe_t *p = arg;
	mqtt_sock_t *s = p->mqtt_sock;

	nni_mtx_lock(&s->mtx);
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
	s->mqtt_pipe = NULL;
	work_close_queue(&s->send_queue);
	work_close_queue(&s->recv_queue);
	nni_mtx_unlock(&s->mtx);

	nni_atomic_set_bool(&p->closed, true);
}

static void
mqtt_send_cb(void *arg)
{
	work_t *     work = arg;
	mqtt_sock_t *s    = work->mqtt_sock;

	nni_mtx_lock(&s->mtx);
	mqtt_pipe_t *p = s->mqtt_pipe;
	nni_mtx_unlock(&s->mtx);

	if (nni_aio_result(&work->send_aio) != 0) {
		// We failed to send... clean up and deal with it.
		nni_msg_free(nni_aio_get_msg(&work->send_aio));
		nni_aio_set_msg(&work->send_aio, NULL);
		nni_pipe_close(p->pipe);
		return;
	}

	if (nni_atomic_get_bool(&p->closed) ||
	    nni_atomic_get_bool(&s->closed)) {
		// This occurs if the mqtt_pipe_close has been called.
		// In that case we don't want any more processing.
		return;
	}

	// state transitions
	switch (work->state) {
	case WORK_CONNECT:
		work->state = WORK_CONNACK;
		nni_pipe_recv(p->pipe, &work->recv_aio);
		break;
	case WORK_DISCONNECT:
		// fall through
	case WORK_PUBACK:
		// fall through
	case WORK_PUBCOMP:
		work->state = WORK_END;
		break;
	case WORK_PUBLISH:
		// TODO: handle retry
		if (0 == work->qos) {
			work->state = WORK_END;
		} else if (1 == work->qos) {
			work->state = WORK_PUBACK;
			nni_pipe_recv(p->pipe, &work->recv_aio);
		} else if (2 == work->qos) {
			work->state = WORK_PUBRECV;
			nni_pipe_recv(p->pipe, &work->recv_aio);
		}
		break;
	case WORK_PUBRECV:
		work->state = WORK_PUBREL;
		nni_pipe_recv(p->pipe, &work->recv_aio);
		break;
	case WORK_PUBREL:
		work->state = WORK_PUBCOMP;
		nni_pipe_recv(p->pipe, &work->recv_aio);
		break;
	case WORK_SUBSCRIBE:
		printf("mqtt_send_cb send SUBSCRIBE done\n");
		work->state = WORK_SUBACK;
		nni_pipe_recv(p->pipe, &work->recv_aio);
		break;
	default:
		work->state = WORK_ERROR;
		break;
	}

	if (WORK_ERROR == work->state) {
		nni_aio_finish_error(work->user_aio, NNG_EPROTO);
		nni_pipe_close(p->pipe);
	} else if (WORK_END == work->state) {
		nni_aio_finish_sync(work->user_aio, 0, 0);
		work_reset(work);
		nni_mtx_lock(&s->mtx);
		nni_list_append(&s->free_list, work);
		nni_mtx_unlock(&s->mtx);
	}
}

static void
mqtt_recv_cb(void *arg)
{
	work_t *     work = arg;
	mqtt_sock_t *s    = work->mqtt_sock;
	nni_msg *    msg  = nni_aio_get_msg(&work->recv_aio);

	nni_mtx_lock(&s->mtx);
	mqtt_pipe_t *p = s->mqtt_pipe;
	nni_mtx_unlock(&s->mtx);

	if (nni_aio_result(&work->recv_aio) != 0) {
		nni_msg_free(msg);
		nni_pipe_close(p->pipe);
		return;
	}

	if (nni_atomic_get_bool(&p->closed) ||
	    nni_atomic_get_bool(&s->closed)) {
		return;
	}

	nni_aio_set_msg(&work->recv_aio, NULL);
	nni_msg_set_pipe(msg, nni_pipe_id(p->pipe));
	nni_mqtt_msg_proto_data_alloc(msg);
	nni_mqtt_msg_decode(msg);
	nni_mqtt_packet_type packet_type = nni_mqtt_msg_get_packet_type(msg);

	// state transitions
	switch (work->state) {
	case WORK_CONNACK:
		work->state =
		    (MQTT_CONNACK == packet_type) ? WORK_END : WORK_ERROR;
		break;
	case WORK_PUBACK:
		work->state =
		    (MQTT_PUBACK == packet_type) ? WORK_END : WORK_ERROR;
		break;
	case WORK_PUBCOMP:
		work->state =
		    (MQTT_PUBCOMP == packet_type) ? WORK_END : WORK_ERROR;
		break;
	case WORK_SUBACK:
		printf("mqtt_recv_cb recv SUBACK done\n");
		work->state =
		    (MQTT_SUBACK == packet_type) ? WORK_END : WORK_ERROR;
		break;
	case WORK_PUBREL:
		if (MQTT_PUBREL != packet_type) {
			work->state = WORK_ERROR;
			break;
		}
		work->state = WORK_PUBCOMP;
		nni_pipe_send(p->pipe, &work->send_aio);
		break;
	case WORK_PUBRECV:
		if (MQTT_PUBREC != packet_type) {
			work->state = WORK_ERROR;
			break;
		}
		work->state = WORK_PUBREL;
		nni_pipe_send(p->pipe, &work->send_aio);
		break;
	case WORK_PUBLISH:
		if (MQTT_PUBLISH != packet_type) {
			work->state = WORK_ERROR;
			break;
		}
		// TODO: handle retry
		uint8_t qos = nni_mqtt_msg_get_publish_qos(msg);
		if (0 == qos) {
			work->state = WORK_END;
		} else if (1 == qos) {
			work->state = WORK_PUBACK;
			nni_pipe_send(p->pipe, &work->send_aio);
		} else if (2 == qos) {
			work->state = WORK_PUBRECV;
			nni_pipe_send(p->pipe, &work->send_aio);
		}
		nni_aio_finish_msg(work->user_aio, msg);
		break;
	default:
		work->state = WORK_ERROR;
		break;
	}

	if (WORK_ERROR == work->state) {
		nni_aio_finish_error(work->user_aio, NNG_EPROTO);
		nni_pipe_close(p->pipe);
	} else if (WORK_END == work->state) {
		nni_aio_finish_sync(work->user_aio, 0, 0);
		work->state = WORK_START;
		nni_mtx_lock(&s->mtx);
		nni_list_append(&s->free_list, work);
		nni_mtx_unlock(&s->mtx);
	}

	return;
}

static void
mqtt_send_start(mqtt_sock_t *s, nni_aio *aio)
{
	work_t *             work;
	nni_mqtt_packet_type packet_type;

	nni_mtx_lock(&s->mtx);

	work = nni_list_first(&s->free_list);
	if (NULL == work) {
		nni_mtx_unlock(&s->mtx);
		nni_aio_finish_error(aio, NNG_EBUSY);
		return;
	}

	// only allow to send PUBLISH and SUBSCRIBE packet
	nni_msg *msg = nni_aio_get_msg(aio);
	packet_type  = nni_mqtt_msg_get_packet_type(msg);

	switch (packet_type) {
	case MQTT_CONNECT:
		work->state = WORK_CONNECT;
		break;
	case MQTT_PUBLISH:
		work->state = WORK_PUBLISH;
		break;
	case MQTT_SUBSCRIBE:
		work->state = WORK_SUBSCRIBE;
		break;
	default:
		work->state = WORK_ERROR;
		nni_mtx_unlock(&s->mtx);
		nni_aio_finish_error(aio, NNG_EPROTO);
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

	while (NULL != work) {
		nni_list_remove(&s->recv_queue, work);
		nni_pipe_recv(p->pipe, &work->recv_aio);
		work = nni_list_first(&s->recv_queue);
	}

	return;
}

// Note: This routine should be called with the pipe lock held.
static void
mqtt_run_send_queue(mqtt_sock_t *s)
{
	work_t *     work;
	mqtt_pipe_t *p = s->mqtt_pipe;

	// no open pipe
	if (NULL == p) {
		return;
	}

	// TODO: handle retry
	while (NULL != (work = nni_list_first(&s->send_queue))) {
		nni_list_remove(&s->send_queue, work);
		nni_msg *msg = nni_aio_get_msg(work->user_aio);
		nni_aio_set_msg(work->user_aio, NULL);
		nni_aio_bump_count(work->user_aio, nni_msg_len(msg));
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
	mqtt_pipe_t *p;

	if (nni_aio_begin(aio) != 0) {
		return;
	}

	if (nni_atomic_get_bool(&s->closed)) {
		nni_mtx_unlock(&s->mtx);
		nni_aio_finish_error(aio, NNG_ECLOSED);
		return;
	}

	nni_mtx_lock(&s->mtx);
	p = s->mqtt_pipe;
	nni_mtx_unlock(&s->mtx);

	mqtt_send_start(s, aio);
}

static void
mqtt_ctx_recv(void *arg, nni_aio *aio)
{
	mqtt_ctx_t * ctx = arg;
	mqtt_sock_t *s   = ctx->mqtt_sock;
	mqtt_pipe_t *p;

	if (nni_aio_begin(aio) != 0) {
		return;
	}

	if (nni_atomic_get_bool(&s->closed)) {
		nni_mtx_unlock(&s->mtx);
		nni_aio_finish_error(aio, NNG_ECLOSED);
		return;
	}

	nni_mtx_lock(&s->mtx);
	p = s->mqtt_pipe;
	nni_mtx_unlock(&s->mtx);

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
