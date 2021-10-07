//
// Copyright 2020 NanoMQ Team, Inc. <jaylin@emqx.io>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <conf.h>
#include <file.h>
#include <hash.h>
#include <mqtt_db.h>
#include <string.h>

#include "core/nng_impl.h"
#include "core/sockimpl.h"
#include "nng/nng.h"
#include "nng/protocol/mqtt/mqtt.h"
#include "nng/protocol/mqtt/mqtt_parser.h"
#include "nng/protocol/mqtt/nano_tcp.h"

#include <sub_handler.h>

// TODO rewrite as nano_mq protocol with RPC support

typedef struct nano_pipe          nano_pipe;
typedef struct nano_sock          nano_sock;
typedef struct nano_ctx           nano_ctx;
typedef struct cs_msg_list        cs_msg_list;

static void        nano_pipe_send_cb(void *);
static void        nano_pipe_recv_cb(void *);
static void        nano_pipe_fini(void *);
static void        nano_pipe_close(void *);
static inline void close_pipe(nano_pipe *p);
// static void nano_period_check(nano_sock *s, nni_list *sent_list, void *arg);
// static void nano_keepalive(nano_pipe *p, void *arg);

// huge context/ dynamic context?
struct nano_ctx {
	nano_sock *sock;
	uint32_t   pipe_id;
	// uint32_t      resend_count;
	// uint32_t      pipe_len;	//record total length of pipe_id queue
	// when resending
	nano_pipe *spipe, *qos_pipe; // send pipe
	nni_aio *  saio;             // send aio
	nni_aio *  raio;             // recv aio
	// uint32_t*     rspipes;// pub resend pipe queue Qos 1/2
	// nni_list      send_queue; // contexts waiting to send.
	nni_list_node sqnode;
	nni_list_node rqnode;
	// nni_timer_node qos_timer;
};

// nano_sock is our per-socket protocol private structure.
struct nano_sock {
	nni_mtx        lk;
	nni_atomic_int ttl;
	nni_id_map     pipes;
	nni_lmq        waitlmq;
	nni_list       recvpipes; // list of pipes with data to receive
	nni_list       recvq;
	nano_ctx       ctx; // base socket
	nni_pollable   readable;
	nni_pollable   writable;
	conf *         conf;
	void *         db;
};

// nano_pipe is our per-pipe protocol private structure.
struct nano_pipe {
	nni_mtx          lk;
	nni_pipe *       pipe;
	nano_sock *      rep;
	uint32_t         id;
	void *           tree; // root node of db tree
	nni_aio          aio_send;
	nni_aio          aio_recv;
	nni_aio          aio_timer;
	nni_list_node    rnode; // receivable list linkage
	nni_list         sendq; // contexts waiting to send
	bool             busy;
	bool             closed;
	bool             kicked;
	uint8_t          reason_code;
	uint8_t          ka_refresh;
	nano_conn_param *conn_param;
	nni_lmq          rlmq;
};

static inline int
nano_nni_lmq_getq(nni_lmq *lmq, nng_msg **msg, uint8_t *qos)
{
	int rv = nni_lmq_getq(lmq, msg);
	if (rv == 0) {
		if (qos) {
			*qos = NANO_NNI_LMQ_GET_QOS_BITS(*msg);
		}
		*msg = NANO_NNI_LMQ_GET_MSG_POINTER(*msg);
	}
	return rv;
}

void
nano_nni_lmq_flush(nni_lmq *lmq)
{
	while (lmq->lmq_len > 0) {
		nng_msg *msg = lmq->lmq_msgs[lmq->lmq_get++];
		lmq->lmq_get &= lmq->lmq_mask;
		lmq->lmq_len--;
		nni_msg_free(NANO_NNI_LMQ_GET_MSG_POINTER(msg));
	}
}

int
nano_nni_lmq_resize(nni_lmq *lmq, size_t cap)
{
	nng_msg * msg;
	nng_msg **newq;
	size_t    alloc;
	size_t    len;

	alloc = 2;
	while (alloc < cap) {
		alloc *= 2;
	}

	newq = nni_alloc(sizeof(nng_msg *) * alloc);
	if (newq == NULL) {
		return (NNG_ENOMEM);
	}

	len = 0;
	while ((len < cap) && (nni_lmq_getq(lmq, &msg) == 0)) {
		newq[len++] = msg;
	}

	// Flush anything left over.
	nano_nni_lmq_flush(lmq);

	nni_free(lmq->lmq_msgs, lmq->lmq_alloc * sizeof(nng_msg *));
	lmq->lmq_msgs  = newq;
	lmq->lmq_cap   = cap;
	lmq->lmq_alloc = alloc;
	lmq->lmq_mask  = alloc - 1;
	lmq->lmq_len   = len;
	lmq->lmq_put   = len;
	lmq->lmq_get   = 0;

	return (0);
}

void
nano_nni_lmq_fini(nni_lmq *lmq)
{
	if (lmq == NULL) {
		return;
	}

	/* Free any orphaned messages. */
	while (lmq->lmq_len > 0) {
		nng_msg *msg = lmq->lmq_msgs[lmq->lmq_get++];
		lmq->lmq_get &= lmq->lmq_mask;
		lmq->lmq_len--;
		nni_msg_free(NANO_NNI_LMQ_GET_MSG_POINTER(msg));
	}

	nni_free(lmq->lmq_msgs, lmq->lmq_alloc * sizeof(nng_msg *));
}

static void
nano_pipe_timer_cb(void *arg)
{
	nano_pipe *p = arg;
	int        qos_timer = p->rep->conf->qos_timer;
	nni_msg *  msg, *rmsg;
	nni_time   time;
	nni_pipe * npipe = p->pipe;
	uint16_t   pid;
	uint8_t    qos;

	if (nng_aio_result(&p->aio_timer) != 0) {
		return;
	}
	nni_mtx_lock(&p->lk);
	if (p->ka_refresh * (qos_timer) > p->conn_param->keepalive_mqtt) {
		nni_println("Warning: close pipe & kick client due to KeepAlive "
		       "timeout!");
		// TODO check keepalived timer interval
		p->reason_code = 0x8D;
		nni_aio_finish_error(&p->aio_recv, NNG_ECONNREFUSED);
		nni_mtx_unlock(&p->lk);
		return;
	}
	p->ka_refresh++;
	if (!p->busy) {
		msg = nni_id_get_any(npipe->nano_qos_db, &pid);
		if (msg != NULL) {
			qos = NANO_NNI_LMQ_GET_QOS_BITS(msg);
			rmsg = NANO_NNI_LMQ_GET_MSG_POINTER(msg);
			time = nni_msg_get_timestamp(msg);
			if ((nni_clock() - time) >=
			    (long unsigned) qos_timer * 1250) {
				p->busy = true;
				//TODO set max retrying times in nanomq.conf
				nni_msg_clone(rmsg);
				nano_msg_set_dup(rmsg);
				nni_aio_set_packetid(&p->aio_send, pid);
				nni_aio_set_msg(&p->aio_send, rmsg);
				debug_msg("resending qos msg packetid: %d", pid);
				nni_pipe_send(p->pipe, &p->aio_send);
				nni_id_remove(npipe->nano_qos_db, pid);
			}
		}
	}

	nni_mtx_unlock(&p->lk);
	nni_sleep_aio(qos_timer * 1000, &p->aio_timer);
	return;
}

/*
static void
nano_keepalive(nano_pipe *p, void *arg)
{
    uint16_t     interval;

    interval = conn_param_get_keepalive(p->conn_param);
    debug_msg("KeepAlive: %d", interval);
    //20% KeepAlive as buffer time for multi-threading
    nni_timer_schedule(&p->ka_timer, nni_clock() + NNI_SECOND * interval *
0.8);
}
*/

static void
nano_ctx_close(void *arg)
{
	nano_ctx * ctx = arg;
	nano_sock *s   = ctx->sock;
	nni_aio *  aio;

	debug_msg("nano_ctx_close");
	nni_mtx_lock(&s->lk);
	if ((aio = ctx->saio) != NULL) {
		// nano_pipe *pipe = ctx->spipe;
		ctx->saio     = NULL;
		ctx->spipe    = NULL;
		ctx->qos_pipe = NULL;
		nni_aio_finish_error(aio, NNG_ECLOSED);
	}
	if ((aio = ctx->raio) != NULL) {
		nni_list_remove(&s->recvq, ctx);
		ctx->raio = NULL;
		nni_aio_finish_error(aio, NNG_ECLOSED);
	}
	nni_mtx_unlock(&s->lk);
}

static void
nano_ctx_fini(void *arg)
{
	nano_ctx *ctx = arg;

	nano_ctx_close(ctx);

	// timer
	debug_msg("========= nano_ctx_fini =========");
	// nni_timer_cancel(&ctx->qos_timer);
	// nni_timer_fini(&ctx->qos_timer);
}

static int
nano_ctx_init(void *carg, void *sarg)
{
	nano_sock *s   = sarg;
	nano_ctx * ctx = carg;

	debug_msg("&&&&&&&& nano_ctx_init %p &&&&&&&&&", ctx);
	NNI_LIST_NODE_INIT(&ctx->sqnode);
	NNI_LIST_NODE_INIT(&ctx->rqnode);

	ctx->sock    = s;
	ctx->pipe_id = 0;

	return (0);
}

static void
nano_ctx_cancel_send(nni_aio *aio, void *arg, int rv)
{
	nano_ctx * ctx = arg;
	nano_sock *s   = ctx->sock;

	debug_msg("*********** nano_ctx_cancel_send ***********");
	nni_mtx_lock(&s->lk);
	if (ctx->saio != aio) {
		nni_mtx_unlock(&s->lk);
		return;
	}
	nni_list_node_remove(&ctx->sqnode);
	ctx->saio = NULL;
	nni_mtx_unlock(&s->lk);

	nni_msg_header_clear(nni_aio_get_msg(aio)); // reset the headers
	nni_aio_finish_error(aio, rv);
}

static void
nano_ctx_send(void *arg, nni_aio *aio)
{
	nano_ctx * ctx = arg;
	nano_sock *s   = ctx->sock;
	nano_pipe *p;
	nni_msg *  msg;
	int        rv;
	uint32_t   pipe;
	size_t     qos = 0;

	msg = nni_aio_get_msg(aio);

	if (nni_aio_begin(aio) != 0) {
		return;
	}

	debug_msg("#### nano_ctx_send with ctx %p msg type %x ####",
	    ctx, nni_msg_cmd_type(msg));

	if ((pipe = nni_msg_get_pipe(msg)) != 0) {
		nni_msg_set_pipe(msg, 0);
	} else {
		pipe = ctx->pipe_id; // reply to self
	}
	ctx->pipe_id = 0; // ensure connack/PING/DISCONNECT/PUBACK only sends once

	if (ctx == &s->ctx) {
		nni_pollable_clear(&s->writable);
	}

	nni_mtx_lock(&s->lk);
	debug_msg(" ******** working with pipe id : %d ctx ********", pipe);
	if ((p = nni_id_get(&s->pipes, pipe)) == NULL) {
		// Pipe is gone.  Make this look like a good send to avoid
		// disrupting the state machine.  We don't care if the peer
		// lost interest in our reply.
		nni_mtx_unlock(&s->lk);
		nni_aio_set_msg(aio, NULL);
		// TODO lastwill/SYS topic will trigger this (sub to the topic
		// that publish to by itself)
		debug_syslog("ERROR: pipe is gone, pub failed");
		nni_msg_free(msg);
		return;
	}
	nni_mtx_unlock(&s->lk);
	nni_mtx_lock(&p->lk);
	qos = (size_t) nni_aio_get_prov_extra(aio, 0);
	msg = NANO_NNI_LMQ_PACKED_MSG_QOS(msg, qos);
	if (!p->busy) {
		p->busy = true;
		nni_aio_set_msg(&p->aio_send, msg);
		nni_pipe_send(p->pipe, &p->aio_send);
		nni_mtx_unlock(&p->lk);
		nni_aio_set_msg(aio, NULL);
		return;
	}

	if ((rv = nni_aio_schedule(aio, nano_ctx_cancel_send, ctx)) != 0) {
		nni_msg_free(msg);
		nni_mtx_unlock(&p->lk);
		return;
	}
	debug_msg("WARNING: pipe %d occupied! resending in cb!", pipe);
	if (nni_lmq_full(&p->rlmq)) {
		// Make space for the new message. TODO add max limit of msgq
		// len in conf
		if ((rv = nano_nni_lmq_resize(
		         &p->rlmq, nni_lmq_cap(&p->rlmq) * 2)) != 0) {
			debug_syslog("warning msg dropped!");
			nni_msg *old;
			(void) nano_nni_lmq_getq(&p->rlmq, &old, NULL);
			nni_msg_free(old);
		}
	}

	nni_lmq_putq(&p->rlmq, msg);

	nni_mtx_unlock(&p->lk);
	nni_aio_set_msg(aio, NULL);
	return;
}

static void
nano_sock_fini(void *arg)
{
	nano_sock *s = arg;

	nni_id_map_fini(&s->pipes);
	nni_lmq_fini(&s->waitlmq);
	nano_ctx_fini(&s->ctx);
	nni_pollable_fini(&s->writable);
	nni_pollable_fini(&s->readable);
	nni_mtx_fini(&s->lk);

	conf_fini(s->conf);
}

static int
nano_sock_init(void *arg, nni_sock *sock)
{
	nano_sock *s = arg;

	NNI_ARG_UNUSED(sock);

	nni_mtx_init(&s->lk);

	nni_id_map_init(&s->pipes, 0, 0, false);
	nni_lmq_init(&s->waitlmq, 256);
	NNI_LIST_INIT(&s->recvq, nano_ctx, rqnode);
	NNI_LIST_INIT(&s->recvpipes, nano_pipe, rnode);

	nni_atomic_init(&s->ttl);
	nni_atomic_set(&s->ttl, 8);

	(void) nano_ctx_init(&s->ctx, s);

	debug_msg("************* nano_sock_init %p *************", s);
	// We start off without being either readable or writable.
	// Readability comes when there is something on the socket.
	nni_pollable_init(&s->writable);
	nni_pollable_init(&s->readable);

	return (0);
}

static void
nano_sock_open(void *arg)
{
	NNI_ARG_UNUSED(arg);
}

static void
nano_sock_close(void *arg)
{
	nano_sock *s = arg;

	nano_ctx_close(&s->ctx);
}

static void
nano_pipe_stop(void *arg)
{
	nano_pipe *p = arg;

	debug_msg("##########nano_pipe_stop###############");
	nni_aio_stop(&p->aio_send);
	nni_aio_stop(&p->aio_timer);
	nni_aio_stop(&p->aio_recv);
}

static void
nano_pipe_fini(void *arg)
{
	nano_pipe *         p = arg;
	nng_msg *           msg;

	debug_msg("########## nano_pipe_fini ###############");
	if ((msg = nni_aio_get_msg(&p->aio_recv)) != NULL) {
		nni_aio_set_msg(&p->aio_recv, NULL);
		nni_msg_free(msg);
	}

	if ((msg = nni_aio_get_msg(&p->aio_send)) != NULL) {
		nni_aio_set_msg(&p->aio_recv, NULL);
		nni_msg_free(msg);
	}

	nni_id_map * nano_qos_db = p->pipe->nano_qos_db;

	//TODO safely free the msgs in qos_db
//	nni_id_iterate(nano_qos_db, nni_id_msgfree_cb);
	nni_id_map_fini(nano_qos_db);
	nng_free(nano_qos_db, sizeof(struct nni_id_map));

	nni_mtx_fini(&p->lk);
	nni_aio_fini(&p->aio_send);
	nni_aio_fini(&p->aio_recv);
	nni_aio_fini(&p->aio_timer);
	nano_nni_lmq_fini(&p->rlmq);
}

static int
nano_pipe_init(void *arg, nni_pipe *pipe, void *s)
{
	nano_pipe *p    = arg;
	nano_sock *sock = s;

	debug_msg("##########nano_pipe_init###############");

	nni_mtx_init(&p->lk);
	nni_lmq_init(&p->rlmq, sock->conf->msq_len);
	nni_aio_init(&p->aio_send, nano_pipe_send_cb, p);
	nni_aio_init(&p->aio_timer, nano_pipe_timer_cb, p);
	nni_aio_init(&p->aio_recv, nano_pipe_recv_cb, p);

	p->reason_code             = 0x00;
	p->id                      = nni_pipe_id(pipe);
	p->pipe                    = pipe;
	p->rep                     = s;
	p->ka_refresh              = 0;
	p->kicked                  = false;
	p->conn_param              = nni_pipe_get_conn_param(pipe);
	p->tree                    = sock->db;
	p->conn_param->nano_qos_db = p->pipe->nano_qos_db;

	return (0);
}

static int
nano_pipe_start(void *arg)
{
	nano_pipe *p = arg;
	nano_sock *s = p->rep;
	nni_msg *  msg;
	uint8_t    rv, *reason; // reason code of CONNACK
	uint8_t    buf[4] = { 0x20, 0x02, 0x00, 0x00 };

	debug_msg("##########nano_pipe_start################");
	/*
	// TODO check peer protocol ver (websocket or tcp or quic??)
	if (nni_pipe_peer(p->pipe) != NNG_NANO_TCP_PEER) {
	        // Peer protocol mismatch.
	        return (NNG_EPROTO);
	}
	*/
	nni_msg_alloc(&msg, 0);
	nni_msg_header_append(msg, buf, 4);
	reason = nni_msg_header(msg) + 2;
	nni_mtx_lock(&s->lk);
	// TODO replace pipe_id with hash key of client_id
	// pipe_id is just random value of id_dyn_val with self-increment.
	nni_id_set(&s->pipes, nni_pipe_id(p->pipe), p);
	rv = verify_connect(p->conn_param, s->conf);
	if (rv != 0) {
		// TODO disconnect client && send connack with reason code 0x05
		debug_syslog("Invalid auth info.");
		*(reason + 1) = rv; // set return code
	}
	nni_mtx_unlock(&s->lk);

	// TODO MQTT V5 check return code
	if (*(reason + 1) == 0) {
		nni_sleep_aio(s->conf->qos_timer * 1500, &p->aio_timer);
	}
	nni_msg_set_cmd_type(msg, CMD_CONNACK);
	nni_msg_set_conn_param(msg, p->conn_param);
	// There is no need to check the  state of aio_recv
	// Since pipe_start is definetly the first cb to be excuted of pipe.
	nni_aio_set_msg(&p->aio_recv, msg);
	nni_aio_finish(&p->aio_recv, 0, nni_msg_len(msg));
	return (rv);
}

static inline void
close_pipe(nano_pipe *p)
{
	nano_sock *s = p->rep;
	nano_ctx * ctx;

	nni_aio_close(&p->aio_send);
	nni_aio_close(&p->aio_recv);
	nni_aio_close(&p->aio_timer);

	// nni_mtx_lock(&s->lk);
	p->closed = true;
	if (nni_list_active(&s->recvpipes, p)) {
		nni_list_remove(&s->recvpipes, p);
	}
	nano_nni_lmq_flush(&p->rlmq);

	// TODO delete
	while ((ctx = nni_list_first(&p->sendq)) != NULL) {
		nni_aio *aio;
		nni_msg *msg;
		nni_list_remove(&p->sendq, ctx);
		aio       = ctx->saio;
		ctx->saio = NULL;
		msg       = nni_aio_get_msg(aio);
		nni_aio_set_msg(aio, NULL);
		nni_aio_finish(aio, 0, nni_msg_len(msg));
		nni_msg_free(msg);
	}
	nni_id_remove(&s->pipes, nni_pipe_id(p->pipe));
}

static void
nano_pipe_close(void *arg)
{
	nano_pipe *p = arg;
	nano_sock *s = p->rep;
	nano_ctx * ctx;
	// conn_param *cparam;
	nni_aio *aio = NULL;
	nni_msg *msg;

	debug_msg("################# nano_pipe_close ##############");
	nni_mtx_lock(&s->lk);
	close_pipe(p);

	// create disconnect event msg
	msg = nano_msg_notify_disconnect(p->conn_param, p->reason_code);
	if (msg == NULL) {
		nni_mtx_unlock(&s->lk);
		return;
	}
	nni_msg_set_conn_param(msg, p->conn_param);
	nni_msg_set_cmd_type(msg, CMD_DISCONNECT_EV);
	nni_msg_set_pipe(msg, p->id);

	// expose disconnect event
	if ((ctx = nni_list_first(&s->recvq)) != NULL) {
		aio       = ctx->raio;
		ctx->raio = NULL;
		nni_list_remove(&s->recvq, ctx);
		nni_mtx_unlock(&s->lk);
		nni_aio_set_msg(aio, msg);
		nni_aio_finish_sync(aio, 0, nni_msg_len(msg));
		return;
	} else {
		// no enough ctx, so cache to waitlmq
		if (nni_lmq_full(&s->waitlmq)) {
			if (nni_lmq_resize(&s->waitlmq, nni_lmq_cap(&s->waitlmq) * 2) != 0) {
				debug_msg("wait lmq resize failed.");
			}
		}
		nni_lmq_putq(&s->waitlmq, msg);
	}
	nni_mtx_unlock(&s->lk);
}

static void
nano_pipe_send_cb(void *arg)
{
	nano_pipe *p = arg;
	nni_msg *  msg;
	uint8_t    qos;

	debug_msg("******** nano_pipe_send_cb %d ****", p->id);
	// retry here
	if (nni_aio_result(&p->aio_send) != 0) {
		nni_msg_free(nni_aio_get_msg(&p->aio_send));
		nni_aio_set_msg(&p->aio_send, NULL);
		nni_pipe_close(p->pipe);
		return;
	}
	nni_mtx_lock(&p->lk);

	nni_aio_set_packetid(&p->aio_send, 0);
	if (nni_lmq_getq(&p->rlmq, &msg) == 0) {
		// msg = NANO_NNI_LMQ_PACKED_MSG_QOS(msg, qos);
		nni_aio_set_msg(&p->aio_send, msg);
		debug_msg("rlmq msg resending! %ld msgs left\n", nni_lmq_len(&p->rlmq));
		nni_pipe_send(p->pipe, &p->aio_send);
		nni_mtx_unlock(&p->lk);
		return;
	}

	p->busy = false;
	nni_mtx_unlock(&p->lk);
	return;
}

static void
nano_cancel_recv(nni_aio *aio, void *arg, int rv)
{
	nano_ctx * ctx = arg;
	nano_sock *s   = ctx->sock;

	debug_msg("*********** nano_cancel_recv ***********");
	nni_mtx_lock(&s->lk);
	if (ctx->raio == aio) {
		nni_list_remove(&s->recvq, ctx);
		ctx->raio = NULL;
		nni_aio_finish_error(aio, rv);
	}
	nni_mtx_unlock(&s->lk);
}

static void
nano_ctx_recv(void *arg, nni_aio *aio)
{
	nano_ctx * ctx = arg;
	nano_sock *s   = ctx->sock;
	nano_pipe *p;
	// size_t     len;
	nni_msg *msg = NULL;

	if (nni_aio_begin(aio) != 0) {
		return;
	}

	debug_msg("nano_ctx_recv start %p", ctx);
	nni_mtx_lock(&s->lk);

	if (nni_lmq_getq(&s->waitlmq, &msg) == 0) {
		nni_mtx_unlock(&s->lk);
		debug_msg("handle msg in waitlmq.");
		nni_aio_set_msg(aio, msg);
		nni_aio_finish_sync(aio, 0, nni_msg_len(msg));
		return;
	}

	if ((p = nni_list_first(&s->recvpipes)) == NULL) {
		int rv;
		if ((rv = nni_aio_schedule(aio, nano_cancel_recv, ctx)) != 0) {
			nni_mtx_unlock(&s->lk);
			nni_aio_finish_error(aio, rv);
			return;
		}
		if (ctx->raio != NULL) {
			// Cannot have a second receive operation pending.
			// This could be ESTATE, or we could cancel the first
			// with ECANCELED.  We elect the former.
			debug_msg("ERROR: former aio not finish yet");
			nni_mtx_unlock(&s->lk);
			nni_aio_finish_error(aio, NNG_ESTATE);
			return;
		}
		ctx->raio = aio;
		nni_list_append(&s->recvq, ctx);
		nni_mtx_unlock(&s->lk);
		return;
	}
	msg = nni_aio_get_msg(&p->aio_recv);
	nni_aio_set_msg(&p->aio_recv, NULL);
	nni_list_remove(&s->recvpipes, p);
	if (nni_list_empty(&s->recvpipes)) {
		nni_pollable_clear(&s->readable);
	}
	nni_pipe_recv(p->pipe, &p->aio_recv);
	if ((ctx == &s->ctx) && !p->busy) {
		nni_pollable_raise(&s->writable);
	}

	// TODO MQTT 5 property

	ctx->pipe_id = nni_pipe_id(p->pipe);
	debug_msg("nano_ctx_recv ends %p pipe: %p pipe_id: %d", ctx, p,
	    ctx->pipe_id);
	nni_mtx_unlock(&s->lk);

	nni_aio_set_msg(aio, msg);
	nni_aio_finish(aio, 0, nni_msg_len(msg));
}

static void
nano_pipe_recv_cb(void *arg)
{
	nano_pipe *      p      = arg;
	nano_sock *      s      = p->rep;
	nano_conn_param *cparam = NULL;
	uint32_t         len, len_of_varint = 0;
	nano_ctx *       ctx;
	nni_msg *        msg, *qos_msg = NULL;
	nni_aio *        aio;
	nni_pipe *       npipe = p->pipe;
	uint8_t *        ptr;
	uint16_t         ackid;

	if (nni_aio_result(&p->aio_recv) != 0) {
		// unexpected disconnect
		nni_pipe_close(p->pipe);
		return;
	}
	debug_msg("######### nano_pipe_recv_cb ############");
	p->ka_refresh = 0;
	msg           = nni_aio_get_msg(&p->aio_recv);
	if (msg == NULL) {
		goto end;
	}

	// ttl = nni_atomic_get(&s->ttl);
	nni_msg_set_pipe(msg, p->id);
	ptr = nni_msg_body(msg);

	// TODO HOOK
	switch (nng_msg_cmd_type(msg)) {
	case CMD_UNSUBSCRIBE:
	case CMD_SUBSCRIBE:
		cparam = p->conn_param;
		if (cparam->pro_ver == PROTOCOL_VERSION_v5) {
			len = get_var_integer(ptr + 2, &len_of_varint);
			nni_msg_set_payload_ptr(
			    msg, ptr + 2 + len + len_of_varint);
		} else {
			nni_msg_set_payload_ptr(msg, ptr + 2);
		}
		break;
	case CMD_DISCONNECT:
		nni_pipe_close(p->pipe);
	case CMD_CONNACK:
	case CMD_PUBLISH:
	case CMD_PINGREQ:
		// Websocket need to reply PINGREQ in application layer
		break;
	case CMD_PUBACK:
	case CMD_PUBCOMP:
		nni_mtx_lock(&p->lk);
		NNI_GET16(ptr, ackid);
		if ((qos_msg = nni_id_get(npipe->nano_qos_db, ackid)) !=
		    NULL) {
		        qos_msg = NANO_NNI_LMQ_GET_MSG_POINTER(qos_msg);
			nni_msg_free(qos_msg);
			nni_id_remove(npipe->nano_qos_db, ackid);
		} else {
			// shouldn't get here BUG TODO
			debug_syslog("qos msg not found!");
		}
		nni_mtx_unlock(&p->lk);
	case CMD_CONNECT:
	case CMD_PUBREC:
	case CMD_PUBREL:
		goto drop;
	default:
		goto drop;
	}

	if (p->closed) {
		// If we are closed, then we can't return data.
		nni_aio_set_msg(&p->aio_recv, NULL);
		nni_msg_free(msg);
		debug_msg("ERROR: pipe is closed abruptly!!");
		return;
	}

	nni_mtx_lock(&s->lk);
	if ((ctx = nni_list_first(&s->recvq)) == NULL) {
		// No one waiting to receive yet, holding pattern.
		nni_list_append(&s->recvpipes, p);
		nni_pollable_raise(&s->readable);
		nni_mtx_unlock(&s->lk);
		debug_msg("ERROR: no ctx found!! create more ctxs!");
		// nni_println("ERROR: no ctx found!! create more ctxs!");
		return;
	}

	nni_list_remove(&s->recvq, ctx);
	aio       = ctx->raio;
	ctx->raio = NULL;
	nni_aio_set_msg(&p->aio_recv, NULL);
	if ((ctx == &s->ctx) && !p->busy) {
		nni_pollable_raise(&s->writable);
	}

	// schedule another receive
	nni_pipe_recv(p->pipe, &p->aio_recv);

	ctx->pipe_id = p->id;
	debug_msg("currently processing pipe_id: %d", p->id);

	nni_mtx_unlock(&s->lk);
	nni_aio_set_msg(aio, msg);

	nni_aio_finish_sync(aio, 0, nni_msg_len(msg));
	debug_msg("end of nano_pipe_recv_cb %p", ctx);
	return;

drop:
	nni_msg_free(msg);
end:
	nni_aio_set_msg(&p->aio_recv, NULL);
	nni_pipe_recv(p->pipe, &p->aio_recv);
	debug_msg("Warning:dropping msg");
	return;
}

static int
nano_sock_set_max_ttl(void *arg, const void *buf, size_t sz, nni_opt_type t)
{
	nano_sock *s = arg;
	int        ttl;
	int        rv;

	if ((rv = nni_copyin_int(&ttl, buf, sz, 1, NNI_MAX_MAX_TTL, t)) == 0) {
		nni_atomic_set(&s->ttl, ttl);
	}
	return (rv);
}

static int
nano_sock_get_max_ttl(void *arg, void *buf, size_t *szp, nni_opt_type t)
{
	nano_sock *s = arg;

	return (nni_copyout_int(nni_atomic_get(&s->ttl), buf, szp, t));
}

static int
nano_sock_get_sendfd(void *arg, void *buf, size_t *szp, nni_opt_type t)
{
	nano_sock *s = arg;
	int        rv;
	int        fd;

	if ((rv = nni_pollable_getfd(&s->writable, &fd)) != 0) {
		return (rv);
	}
	return (nni_copyout_int(fd, buf, szp, t));
}

static int
nano_sock_get_recvfd(void *arg, void *buf, size_t *szp, nni_opt_type t)
{
	nano_sock *s = arg;
	int        rv;
	int        fd;

	if ((rv = nni_pollable_getfd(&s->readable, &fd)) != 0) {
		return (rv);
	}

	return (nni_copyout_int(fd, buf, szp, t));
}

static void
nano_sock_send(void *arg, nni_aio *aio)
{
	nano_sock *s = arg;

	nano_ctx_send(&s->ctx, aio);
}

static void
nano_sock_recv(void *arg, nni_aio *aio)
{
	nano_sock *s = arg;

	nano_ctx_recv(&s->ctx, aio);
}

static void
nano_sock_setdb(void *arg, void *data)
{
	nano_sock *s         = arg;
	conf *     nano_conf = data;

	s->conf = nano_conf;
	s->db   = nano_conf->db_root;

	conf_auth_parser(s->conf);
}

// This is the global protocol structure -- our linkage to the core.
// This should be the only global non-static symbol in this file.
static nni_proto_pipe_ops nano_pipe_ops = {
	.pipe_size  = sizeof(nano_pipe),
	.pipe_init  = nano_pipe_init,
	.pipe_fini  = nano_pipe_fini,
	.pipe_start = nano_pipe_start,
	.pipe_close = nano_pipe_close,
	.pipe_stop  = nano_pipe_stop,
};

static nni_proto_ctx_ops nano_ctx_ops = {
	.ctx_size = sizeof(nano_ctx),
	.ctx_init = nano_ctx_init,
	.ctx_fini = nano_ctx_fini,
	.ctx_send = nano_ctx_send,
	.ctx_recv = nano_ctx_recv,
};

static nni_option nano_sock_options[] = {
	{
	    .o_name = NNG_OPT_MAXTTL,
	    .o_get  = nano_sock_get_max_ttl,
	    .o_set  = nano_sock_set_max_ttl,
	},
	{
	    .o_name = NNG_OPT_RECVFD,
	    .o_get  = nano_sock_get_recvfd,
	},
	{
	    .o_name = NNG_OPT_SENDFD,
	    .o_get  = nano_sock_get_sendfd,
	},
	{
	    .o_name = NULL,
	},
};

static nni_proto_sock_ops nano_sock_ops = {
	.sock_size    = sizeof(nano_sock),
	.sock_init    = nano_sock_init,
	.sock_fini    = nano_sock_fini,
	.sock_open    = nano_sock_open,
	.sock_close   = nano_sock_close,
	.sock_options = nano_sock_options,
	.sock_send    = nano_sock_send,
	.sock_recv    = nano_sock_recv,
};

static nni_proto nano_tcp_proto = {
	.proto_version  = NNI_PROTOCOL_VERSION,
	.proto_self     = { NNG_NANO_TCP_SELF, NNG_NANO_TCP_SELF_NAME },
	.proto_peer     = { NNG_NANO_TCP_PEER, NNG_NANO_TCP_PEER_NAME },
	.proto_flags    = NNI_PROTO_FLAG_SNDRCV,
	.proto_sock_ops = &nano_sock_ops,
	.proto_pipe_ops = &nano_pipe_ops,
	.proto_ctx_ops  = &nano_ctx_ops,
};

int
nng_nano_tcp0_open(nng_socket *sidp)
{
	// TODO Global binary tree init here
	return (nni_proto_mqtt_open(sidp, &nano_tcp_proto, nano_sock_setdb));
}