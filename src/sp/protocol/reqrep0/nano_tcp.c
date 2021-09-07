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
#include "nano_lmq.h"
#include "nng/nng.h"
#include "nng/protocol/mqtt/mqtt.h"
#include "nng/protocol/mqtt/mqtt_parser.h"
#include "nng/protocol/mqtt/nano_tcp.h"

#include <sub_handler.h>

// TODO rewrite as nano_mq protocol with RPC support

typedef struct nano_pipe          nano_pipe;
typedef struct nano_sock          nano_sock;
typedef struct nano_ctx           nano_ctx;
typedef struct nano_clean_session nano_clean_session;
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
	nni_id_map     clean_session_db;
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
	nano_pipe_db *   pipedb_root;
	nano_lmq         rlmq;
};

struct nano_clean_session {
	client_ctx *     cltx;
	nano_conn_param *cparam;
	nni_id_map *     msg_map;
	nano_pipe_db *   pipe_db;
	uint32_t         pipeid; // corresponding pipe id of nng
	bool             clean;
};

static void
nano_pipe_timer_cb(void *arg)
{
	nano_pipe *p = arg;
	nni_msg *  msg;
	nni_time   time;
	nni_pipe * npipe = p->pipe;
	uint16_t   pid;
	int        qos_timer = p->rep->conf->qos_timer;

	if (nng_aio_result(&p->aio_timer) != 0) {
		return;
	}
	nni_mtx_lock(&p->lk);
	if (p->ka_refresh * (qos_timer) > p->conn_param->keepalive_mqtt) {
		printf("Warning: close pipe & kick client due to KeepAlive "
		       "timeout!");
		// TODO check keepalived timer interval
		nni_mtx_unlock(&p->lk);
		p->reason_code = 0x8D;
		nano_pipe_close(p);
		return;
	}
	p->ka_refresh++;
	if (!p->busy) {
		msg = nni_id_get_any(npipe->nano_qos_db, &pid);

		if (msg != NULL) {
			time = nni_msg_get_timestamp(msg);
			if ((nni_clock() - time) >=
			    (long unsigned) qos_timer * 1250) {
				p->busy = true;
				nni_msg_clone(msg);
				nano_msg_set_dup(msg);
				nni_aio_set_packetid(&p->aio_send, pid);
				nni_aio_set_msg(&p->aio_send, msg);
				debug_msg("resending qos msg!\n");
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

	// TODO send list??
	// ctx->pp_len = 0;
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

	msg = nni_aio_get_msg(aio);

	if (nni_aio_begin(aio) != 0) {
		return;
	}

	debug_msg("############### nano_ctx_send with ctx %p msg type %x "
	          "###############",
	    ctx, nni_msg_cmd_type(msg));

	if ((pipe = nni_msg_get_pipe(msg)) != 0) {
		nni_msg_set_pipe(msg, 0);
	} else {
		pipe = ctx->pipe_id; // reply to self
	}
	ctx->pipe_id =
	    0; // ensure connack/PING/DISCONNECT/PUBACK only sends once

	if (ctx == &s->ctx) {
		nni_pollable_clear(&s->writable);
	}

	nni_mtx_lock(&s->lk);
	debug_msg("*************************** working with pipe id : %d "
	          "ctx***************************",
	    pipe);
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

	pub_extra *pub_extra_info =
	    (pub_extra *) nni_aio_get_prov_extra(aio, 0);

	debug_msg("pub_extra_info: %p", pub_extra_info);

	if (!p->busy) {
		p->busy = true;
		if (pub_extra_info) {
			nni_aio_set_prov_extra(
			    &p->aio_send, 0, pub_extra_info);
		}
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
	if (nano_lmq_full(&p->rlmq)) {
		// Make space for the new message. TODO add max limit of msgq
		// len in conf
		if ((rv = nano_lmq_resize_with_cb(&p->rlmq,
		         nano_lmq_cap(&p->rlmq) * 2,
		         (nano_lmq_free) nni_msg_free,
		         (nano_lmq_get_sub_msg) pub_extra_get_msg)) != 0) {
			debug_msg("warning msg dropped!");
			pub_extra *old;
			if (nano_lmq_getq(&p->rlmq, (void **) &old) == 0) {
				nni_msg *old_msg =
				    (nni_msg *) pub_extra_get_msg(old);
				nni_msg_free(old_msg);
				pub_extra_free(old);
			}
		} else {
			debug_msg("nano_lmq_resize error: %d", rv);
		}
	}

	pub_extra_set_msg(pub_extra_info, msg);
	rv = nano_lmq_putq(&p->rlmq, pub_extra_info);

	debug_msg("nano_lmq_putq %p, %d", pub_extra_info, rv);

	nni_mtx_unlock(&p->lk);
	nni_aio_set_msg(aio, NULL);
	return;
}

void
nano_clean_session_db_fini(nni_id_map *m)
{
	uint32_t            key = 0;
	nano_clean_session *cs  = NULL;
	while ((cs = nni_id_get_one(m, &key)) != NULL) {
		nano_conn_param *cparam  = cs->cparam;
		nni_id_map *     msg_map = cs->msg_map;

		destroy_conn_param(cparam);
		nni_id_iterate(msg_map, nni_id_msgfree_cb);
		nni_id_map_fini(msg_map);
		nng_free(msg_map, sizeof(struct nni_id_map));

		nni_id_remove(m, key);
		cs = NULL;
	}
	nni_id_map_fini(m);
}

static void
nano_sock_fini(void *arg)
{
	nano_sock *s = arg;

	nni_id_map_fini(&s->pipes);
	nano_clean_session_db_fini(&s->clean_session_db);
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
	nni_id_map_init(&s->clean_session_db, 0, 0, false);
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
nano_deep_copy_connparam(conn_param *new_cp, conn_param *cp)
{
	UPDATE_FIELD_INT(pro_ver, new_cp, cp);
	UPDATE_FIELD_INT(con_flag, new_cp, cp);
	UPDATE_FIELD_INT(keepalive_mqtt, new_cp, cp);
	UPDATE_FIELD_INT(clean_start, new_cp, cp);
	UPDATE_FIELD_INT(will_flag, new_cp, cp);
	UPDATE_FIELD_INT(will_retain, new_cp, cp);
	UPDATE_FIELD_INT(will_qos, new_cp, cp);
	UPDATE_FIELD_MQTT_STRING(pro_name, body, new_cp, cp);
	UPDATE_FIELD_MQTT_STRING(clientid, body, new_cp, cp);
	UPDATE_FIELD_MQTT_STRING(will_topic, body, new_cp, cp);
	UPDATE_FIELD_MQTT_STRING(will_msg, body, new_cp, cp);
	UPDATE_FIELD_MQTT_STRING(username, body, new_cp, cp);
	UPDATE_FIELD_MQTT_STRING(password, body, new_cp, cp);
	UPDATE_FIELD_INT(session_expiry_interval, new_cp, cp);
	UPDATE_FIELD_INT(rx_max, new_cp, cp);
	UPDATE_FIELD_INT(max_packet_size, new_cp, cp);
	UPDATE_FIELD_INT(topic_alias_max, new_cp, cp);
	UPDATE_FIELD_INT(req_resp_info, new_cp, cp);
	UPDATE_FIELD_INT(req_problem_info, new_cp, cp);
	UPDATE_FIELD_MQTT_STRING(auth_method, body, new_cp, cp);
	UPDATE_FIELD_MQTT_STRING(auth_data, body, new_cp, cp);
	UPDATE_FIELD_MQTT_STRING_PAIR(user_property, key, val, new_cp, cp);
	UPDATE_FIELD_INT(will_delay_interval, new_cp, cp);
	UPDATE_FIELD_INT(payload_format_indicator, new_cp, cp);
	UPDATE_FIELD_INT(msg_expiry_interval, new_cp, cp);
	UPDATE_FIELD_MQTT_STRING(content_type, body, new_cp, cp);
	UPDATE_FIELD_MQTT_STRING(resp_topic, body, new_cp, cp);
	UPDATE_FIELD_MQTT_STRING(corr_data, body, new_cp, cp);
	UPDATE_FIELD_MQTT_STRING_PAIR(
	    payload_user_property, key, val, new_cp, cp);
}

static void *
del_topic_clictx_from_tree(void *tree, topic_queue *tq, uint32_t pid)
{
	client_ctx *cli_ctx = NULL;

	while (tq) {
		if (tq->topic) {
			cli_ctx = search_and_delete(tree, tq->topic, pid);
		}
		debug_msg("delete pipe id [%d] topic: [%s]", pid, tq->topic);
		del_sub_ctx(cli_ctx, tq->topic);
		tq = tq->next;
	}

	return cli_ctx;
}

static void *
del_topic_from_tree(void *tree, topic_queue *tq, uint32_t pid)
{
	client_ctx *cli_ctx = NULL;

	while (tq) {
		if (tq->topic) {
			cli_ctx = search_and_delete(tree, tq->topic, pid);
		}
		debug_msg("delete pipe id [%d] topic: [%s]", pid, tq->topic);
		tq = tq->next;
	}

	return cli_ctx;
}

static void
restore_topic_to_tree(void *tree, client_ctx *cli_ctx, char *client_id)
{
	topic_node *tn_t = cli_ctx->sub_pkt->node;

	while (tn_t) {
		debug_msg("Now adding topic (from last session), body: [%s]",
		    tn_t->it->topic_filter.body);
		search_and_insert(tree, tn_t->it->topic_filter.body, client_id,
		    cli_ctx, cli_ctx->pid.id);
		tn_t = tn_t->next;
	}
}

static int
nano_session_restore(nano_pipe *p, nano_sock *s, uint8_t *flag)
{
	int                 ret;
	conn_param *        new_cparam = p->conn_param;
	uint32_t            key;
	uint8_t             clean_session_flag = new_cparam->clean_start;
	nano_clean_session *cs;

	key = DJBHashn(new_cparam->clientid.body, new_cparam->clientid.len);
	// TODO hash collision?
	cs = nni_id_get(&s->clean_session_db, key);

	// no matter if client enabled cleansession. use clean-session-db for
	// duplicate clientid verifying.
	if (cs == NULL) {
		if ((cs = nni_zalloc(sizeof(nano_clean_session) * 1)) ==
		    NULL) {
			return (NNG_ENOMEM);
		}
		// firts connection, store pipeid and hashed clientid
		cs->pipeid = p->id;
		if (clean_session_flag == 0) {
			debug_msg("(CS=0) Session cannot restore, cannot find "
			          "cached information based "
			          "on the clientID given (eithe first connect "
			          "or lose the backup)");
			cs->clean = false;
			ret       = 0;
		} else {
			debug_msg("(CS=1) No need for restoring a session");
			cs->clean = true;
			ret       = 0;
		}
		if (nni_id_set(&s->clean_session_db, key, cs) != 0) {
			debug_msg("(CS=0) UNEXPECTED: The nano_clean_session "
			          "structure is not set "
			          "as a new instance of hashtable");
			ret = NNG_ECONNABORTED;
		}
		return ret;
	} else if (cs->pipeid != 0) {
		// TODO kick prev connection or current one?(p or cs->pipeid)
		p->kicked = true;
		if (p->conn_param->pro_ver == 5) {
			*(flag + 1) = 0x8E;
		} else {
			*(flag + 1) = 0x02;
		}
		return (NNG_ECONNABORTED);
	}

	client_ctx *  cltx       = cs->cltx;
	conn_param *  cparam     = cs->cparam;
	nni_id_map *  msgs       = cs->msg_map;
	nano_pipe_db *topics     = cs->pipe_db;
	nano_pipe_db *topic_node = topics;

	cs->pipeid = p->id;
	if (clean_session_flag == 0) {
		*flag     = 0x01; // set session present flag
		cs->clean = false;
		// step 0 restore conn param
		nano_deep_copy_connparam(new_cparam, cparam);
		destroy_conn_param(cparam);
		cparam = NULL;
		// step 1 restore nano_qos_db
		// TODO new coming message may use the existing packet id in
		// one client nano_qos_db
		nni_id_map_fini(p->pipe->nano_qos_db);
		nng_free(p->pipe->nano_qos_db, sizeof(struct nni_id_map));
		p->pipe->nano_qos_db       = msgs;
		p->conn_param->nano_qos_db = msgs;
		// step 2 restore cli_ctx and cached_topic_queue
		if (cltx != NULL)
			cltx->pid.id = p->id;
		if (cached_check_id(key)) {
			restore_topic_all(key, p->id);
			restore_topic_to_tree(
			    p->tree, cltx, new_cparam->clientid.body);
		} else {
			debug_msg(
			    "(CS=0) UNEXPECTED: no stored cached topic queue");
		}
		// step 3 restore topic in pipe_db
		p->pipedb_root = topics;
		cs->pipe_db    = NULL;
		// step 4 restore nano_pipe_db<topic, pipe_db>
		while (topic_node->next) {
			nni_id_set(&p->pipe->nano_db,
			    DJBHashn(
			        topic_node->topic, strlen(topic_node->topic)),
			    topic_node);
			topic_node = topic_node->next;
		}
		debug_msg(
		    "(CS=0) All last session related information restored");
	} else {
		cs->clean = true;
		// step 0 remove conn param
		destroy_conn_param(cparam);
		cparam = NULL;
		// step 1 remove nano_qos_db
		nni_id_iterate(msgs, nni_id_msgfree_cb);
		nni_id_map_fini(msgs);
		nng_free(msgs, sizeof(struct nni_id_map));
		msgs = NULL;
		// step 2 delete 2-1 cli_ctx and cached topic queue
		if (cached_check_id(key)) {
			topic_queue *tq = get_cached_topic(key);
			while (tq) {
				del_sub_ctx(cltx, tq->topic);
				tq = tq->next;
			}
			del_cached_topic_all(key);
		} else {
			debug_msg(
			    "(CS=1) UNEXPECTED: no stored cached topic queue");
		}
		// step 3 delete topics in pipe_db
		nano_msg_free_pipedb(topics);
		debug_msg(
		    "(CS=1) All last session related information disgarded");
	}
	return 0;
}

static int
nano_session_cache(nano_pipe *p, nano_clean_session *temp_cs, uint32_t key)
{
	conn_param *        cp          = p->conn_param;
	nni_id_map *        nano_qos_db = cp->nano_qos_db;
	client_ctx *        cli_ctx     = NULL;
	struct topic_queue *tq          = NULL;

	// step 0 copy connection parameter
	conn_param *new_cp;
	if ((new_cp = nni_zalloc(sizeof(conn_param) * 1)) == NULL) {
		return (NNG_ENOMEM);
	}
	init_conn_param(new_cp);
	nano_deep_copy_connparam(new_cp, cp);
	temp_cs->cparam = new_cp;
	// step 1 move nano_qos_db to temp_cs struct (move pointer)
	temp_cs->msg_map = nano_qos_db;
	debug_msg("the nano_qos_db has an address: %p", nano_qos_db);
	nano_qos_db = NULL;
	// step 2-1 find cli_ctx and kept its pointer, but delete topic from
	// tree step 2-2 move topic from topic map to cached topic map
	// (hash.cc)
	if (check_id(p->id)) {
		tq = get_topic(p->id);
		if ((cli_ctx = del_topic_from_tree(p->tree, tq, p->id)) !=
		    NULL) {
			cli_ctx->pid.id = 0;
			temp_cs->cltx   = cli_ctx;
		}
		cache_topic_all(p->id, key);
	} else {
		debug_msg("(CS=0) UNEXPECTED: no stored topic queue, tq lost "
		          "or client may not subed topic");
	}
	// step 3 move nano_pipe_db to temp_cs struct (move pointer)
	temp_cs->pipe_db = p->pipedb_root;
	p->pipedb_root   = NULL;

	debug_msg("(CS=0) Session cached, all this session related "
	          "information kept");
	return 0;
}

static void
nano_sessiondb_clean(nano_pipe *p)
{
	conn_param *        cp = p->conn_param;
	nano_sock *         s  = p->rep;
	uint32_t            key;
	nano_clean_session *temp_cs;

	key = DJBHashn(cp->clientid.body, cp->clientid.len);
	// get temp_cs from clean_session_db
	temp_cs = nni_id_get(&s->clean_session_db, key);
	if (temp_cs != NULL) {
		// temp_cs->pipeid indicates if current session existed.
		if (p->closed == true && temp_cs->pipeid == p->id) {
			temp_cs->pipeid = 0;
		}
		if (temp_cs->clean == true) {
			// Do not kick the old one.
			if (temp_cs->pipeid == 0) {
				nni_id_remove(&s->clean_session_db, key);
				nng_free(temp_cs, sizeof(nano_clean_session));
			}
		}
	}
}

static void
nano_pipe_fini(void *arg)
{
	nano_pipe *         p = arg;
	nng_msg *           msg;
	uint32_t            key;
	nano_clean_session *temp_cs;
	conn_param *        cp = p->conn_param;
	nano_sock *         s  = p->rep;

	debug_msg("########## nano_pipe_fini ###############");
	if ((msg = nni_aio_get_msg(&p->aio_recv)) != NULL) {
		nni_aio_set_msg(&p->aio_recv, NULL);
		nni_msg_free(msg);
	}

	if ((msg = nni_aio_get_msg(&p->aio_send)) != NULL) {
		nni_aio_set_msg(&p->aio_recv, NULL);
		nni_msg_free(msg);
	}

	key = DJBHashn(cp->clientid.body, cp->clientid.len);
	// get temp_cs from clean_session_db
	// TODO potential risk without lock
	temp_cs = nni_id_get(&s->clean_session_db, key);
	if (p->conn_param->clean_start == 0 && temp_cs != NULL &&
	    p->kicked != true) {
		nano_session_cache(p, temp_cs, key);
	} else {
		// When clean_session is set to 1
		nni_id_map *        nano_qos_db = p->conn_param->nano_qos_db;
		client_ctx *        cli_ctx     = NULL;
		struct topic_queue *tq          = NULL;

		nni_id_iterate(nano_qos_db, nni_id_msgfree_cb);
		nni_id_map_fini(nano_qos_db);
		nng_free(nano_qos_db, sizeof(struct nni_id_map));

		if (check_id(p->id) && p->tree != NULL) {
			tq = get_topic(p->id);
			if ((cli_ctx = del_topic_clictx_from_tree(
			         p->tree, tq, p->id)) != NULL) {
				debug_msg("(CS=1) Unexpected, not all topic "
				          "has been delete from sub_pkt");
			}
			del_topic_all(p->id);
		} else {
			debug_msg("(CS=1) UNEXPECTED: no stored topic queue, "
			          "tq lost or maybe not subed any topic");
		}
		nano_msg_free_pipedb(p->pipedb_root);
		p->pipedb_root = NULL;
	}
	destroy_conn_param(p->conn_param);

	nni_mtx_fini(&p->lk);
	nni_aio_fini(&p->aio_send);
	nni_aio_fini(&p->aio_recv);
	nni_aio_fini(&p->aio_timer);

	nano_lmq_fini_with_cb(&p->rlmq, (nano_lmq_free) nni_msg_free,
	    (nano_lmq_get_sub_msg) pub_extra_get_msg);
}

static int
nano_pipe_init(void *arg, nni_pipe *pipe, void *s)
{
	nano_pipe *p    = arg;
	nano_sock *sock = s;

	debug_msg("##########nano_pipe_init###############");

	nni_mtx_init(&p->lk);
	nano_lmq_init(&p->rlmq, sock->conf->msq_len);
	nni_aio_init(&p->aio_send, nano_pipe_send_cb, p);
	// TODO move keepalive monitor to transport layer?
	nni_aio_init(&p->aio_timer, nano_pipe_timer_cb, p);
	nni_aio_init(&p->aio_recv, nano_pipe_recv_cb, p);

	// NNI_LIST_INIT(&p->sendq, nano_ctx, sqnode);

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
	// TODO check peer protocol ver
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
	rv = nano_session_restore(p, s, reason);
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
	// nni_lmq_flush(&p->rlmq);
	nano_lmq_flush_with_cb(&p->rlmq, (nano_lmq_free) nni_msg_free,
	    (nano_lmq_get_sub_msg) pub_extra_get_msg);

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
	nano_sessiondb_clean(p);
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
	// pub disconnect event
	if ((ctx = nni_list_first(&s->recvq)) != NULL) {
		msg =
		    nano_msg_notify_disconnect(p->conn_param, p->reason_code);
		if (msg == NULL) {
			nni_mtx_unlock(&s->lk);
			return;
		}
		nni_msg_set_conn_param(msg, p->conn_param);
		nni_msg_set_cmd_type(msg, CMD_DISCONNECT_EV);
		aio       = ctx->raio;
		ctx->raio = NULL;
		nni_list_remove(&s->recvq, ctx);
		nni_mtx_unlock(&s->lk);
		nni_aio_set_msg(aio, msg);
		nni_aio_finish_sync(aio, 0, nni_msg_len(msg));
		return;
	} else {
		debug_msg("Warning: no ctx left!! faied to send disconnect "
		          "notification");
	}
	nni_mtx_unlock(&s->lk);
}

static void
nano_pipe_send_cb(void *arg)
{
	nano_pipe *p = arg;
	pub_extra *extra;

	debug_msg(
	    "################ nano_pipe_send_cb %d ################", p->id);
	// retry here
	if (nni_aio_result(&p->aio_send) != 0) {
		nni_msg_free(nni_aio_get_msg(&p->aio_send));
		nni_aio_set_msg(&p->aio_send, NULL);
		nni_pipe_close(p->pipe);
		return;
	}
	nni_mtx_lock(&p->lk);

	nni_aio_set_packetid(&p->aio_send, 0);
	int rv = nano_lmq_getq(&p->rlmq, (void **) &extra);
	if (rv == 0) {
		nni_msg *msg = (nni_msg *) pub_extra_get_msg(extra);
		debug_msg("get nng_msg from pub_extra: %p", msg);
		nni_aio_set_prov_extra(&p->aio_send, 0, extra);
		nni_aio_set_msg(&p->aio_send, msg);

		debug_msg("rlmq msg resending! %ld msgs left\n",
		    nano_lmq_len(&p->rlmq));
		nni_pipe_send(p->pipe, &p->aio_send);
		nni_mtx_unlock(&p->lk);
		return;
	} else {
		debug_msg("nano_lmq_getq error: %d", rv);
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
	nni_msg *msg;

	if (nni_aio_begin(aio) != 0) {
		return;
	}
	debug_msg("nano_ctx_recv start %p", ctx);
	nni_mtx_lock(&s->lk);
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
	nano_pipe_db *   pipe_db;
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
		goto unsub;
	case CMD_SUBSCRIBE:
		// TODO only cache topic hash when it is above qos 1/2
		nni_mtx_lock(&p->lk);
		cparam         = p->conn_param;
		pipe_db        = nano_msg_get_subtopic(msg, p->pipedb_root,
                    cparam); // TODO potential memleak when sub failed
		p->pipedb_root = pipe_db;
		for (; pipe_db != NULL; pipe_db = pipe_db->next) {
			nni_id_set(
			    &npipe->nano_db, DJBHash(pipe_db->topic), pipe_db);
		}
		nni_mtx_unlock(&p->lk);

		// __attribute__((fallthrough))
	unsub:
		if (cparam->pro_ver == PROTOCOL_VERSION_v5) {
			len = get_var_integer(ptr + 2, &len_of_varint);
			nni_msg_set_payload_ptr(
			    msg, ptr + 2 + len + len_of_varint);
		} else {
			nni_msg_set_payload_ptr(msg, ptr + 2);
		}
		// TODO remove topic from pipe_db
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

	// ctx->pp_len = len;		//TODO Rewrite mqtt header length
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
