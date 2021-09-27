//
// Copyright 2020 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
// Copyright 2019 Devolutions <info@devolutions.net>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "core/nng_impl.h"
#include "core/sockimpl.h"
#include "supplemental/websocket/websocket.h"

#include <nng/supplemental/tls/tls.h>
#include <nng/transport/ws/websocket.h>

#include "nng/nng_debug.h"
#include "nng/protocol/mqtt/mqtt.h"
#include "nng/protocol/mqtt/mqtt_parser.h"

typedef struct ws_dialer   ws_dialer;
typedef struct ws_listener ws_listener;
typedef struct ws_pipe     ws_pipe;

struct ws_dialer {
	uint16_t           peer; // remote protocol
	nni_list           aios;
	nni_mtx            mtx;
	nni_aio *          connaio;
	nng_stream_dialer *dialer;
	bool               started;
};

struct ws_listener {
	uint16_t             peer; // remote protocol
	nni_list             aios;
	nni_mtx              mtx;
	nni_aio *            accaio;
	nng_stream_listener *listener;
	bool                 started;
};

struct ws_pipe {
	nni_mtx     mtx;
	bool        closed;
	uint8_t     txlen[NANO_MIN_PACKET_LEN];
	uint16_t    peer;
	size_t      gotrxhead;
	size_t      wantrxhead;
	nni_msg *   tmp_msg;
	nni_aio *   user_txaio;
	nni_aio *   user_rxaio;
	nni_aio *   ep_aio;
	nni_aio *   txaio;
	nni_aio *   rxaio;
	nni_aio *   qsaio;
	nni_pipe *  npipe;
	conn_param *ws_param;
	nng_stream *ws;
};

static void
wstran_pipe_send_cb(void *arg)
{
	ws_pipe *p = arg;
	nni_aio *taio;
	nni_aio *uaio;

	nni_mtx_lock(&p->mtx);
	taio          = p->txaio;
	uaio          = p->user_txaio;
	p->user_txaio = NULL;

	if (uaio != NULL) {
		int rv;
		if ((rv = nni_aio_result(taio)) != 0) {
			nni_aio_finish_error(uaio, rv);
		} else {
			nni_aio_finish(uaio, 0, 0);
		}
	}
	nni_mtx_unlock(&p->mtx);
}

static void
wstran_pipe_recv_cb(void *arg)
{
	ws_pipe *p   = arg;
	uint32_t len = 0, rv, pos = 1;
	uint8_t *ptr;
	nni_msg *smsg = NULL, *msg = NULL;
	nni_aio *raio = p->rxaio;
	nni_aio *uaio = NULL;

	nni_mtx_lock(&p->mtx);
	// only sets uaio at first time
	if (p->user_rxaio != NULL) {
		uaio = p->user_rxaio;
	}
	// process scatterd msgs
	if ((rv = nni_aio_result(raio)) != 0) {
		goto reset;
	}
	msg = nni_aio_get_msg(raio);
	ptr = nni_msg_body(msg);
	p->gotrxhead += nni_msg_len(msg);
	debug_msg("#### wstran_pipe_recv_cb got %ld msg: %p %x %ld",
	    p->gotrxhead, ptr, *ptr, nni_msg_len(msg));
	// first we collect complete Fixheader
	if (p->tmp_msg == NULL && p->gotrxhead > 0) {
		if ((rv = nni_msg_alloc(&p->tmp_msg, 0)) != 0) {
			debug_syslog("mem error %ld\n", (size_t) len);
			goto reset;
		}
	}
	// TODO use IOV instead of appending msg
	nni_msg_append(p->tmp_msg, ptr, nni_msg_len(msg));
	ptr = nni_msg_body(p->tmp_msg); // packet might be sticky?

	if (p->wantrxhead == 0) {
		if (p->gotrxhead == 1) {
			goto recv;
		}
		len = get_var_integer(ptr, &pos);
		if (*(ptr + pos - 1) >0x7f) {
			// continue to next byte of remaining length
			if (p->gotrxhead >= NNI_NANO_MAX_HEADER_SIZE) {
				// length error
				rv = NNG_EMSGSIZE;
				goto reset;
			}
		} else {
			// Fixed header finished
			p->wantrxhead = len + pos;
			nni_msg_set_cmd_type(p->tmp_msg, *ptr & 0xf0);
		}
	}
	if (p->gotrxhead >= p->wantrxhead) {
		goto done;
	}

recv:
	nni_msg_free(msg);
	nng_stream_recv(p->ws, raio);
	nni_mtx_unlock(&p->mtx);
	return;
done:
	if (uaio == NULL) {
		uaio = p->ep_aio;
	}
	if (uaio != NULL) {
		p->gotrxhead  = 0;
		p->wantrxhead = 0;
		nni_msg_free(msg);
		if (nni_msg_cmd_type(p->tmp_msg) == CMD_CONNECT) {
			// end of nego
			if (p->ws_param == NULL) {
				conn_param_alloc(&p->ws_param);
			}
			if (conn_handler(
			        nni_msg_body(p->tmp_msg), p->ws_param) != 0) {
				goto reset;
			}
			nni_msg_free(p->tmp_msg);
			p->tmp_msg = NULL;
			nni_aio_set_msg(uaio, smsg);
			nni_aio_set_output(uaio, 0, p);
			// let pipe_start_cb in protocol layer deal with CONNACK
			nni_aio_finish(uaio, 0, 0);
			nni_mtx_unlock(&p->mtx);
			return;
		} else {
			if (nni_msg_alloc(&smsg, 0) != 0) {
				goto reset;
			}
			//parse fixed header
			ws_fixed_header_adaptor(ptr, smsg);
			nni_msg_free(p->tmp_msg);
			p->tmp_msg = NULL;
			nni_msg_set_conn_param(smsg, p->ws_param);
		}

		uint8_t  qos_pac;
		uint16_t pid;
		nni_msg *qos_msg;
		if (nni_msg_cmd_type(smsg) == CMD_PUBLISH) {
			qos_pac = nni_msg_get_pub_qos(smsg);
			if (qos_pac > 0) {
				nng_aio_wait(p->qsaio);
				if (qos_pac == 1) {
					p->txlen[0] = CMD_PUBACK;
				} else if (qos_pac == 2) {
					p->txlen[0] = CMD_PUBREC;
				}
				p->txlen[1] = 0x02;
				pid         = nni_msg_get_pub_pid(smsg);
				NNI_PUT16(p->txlen + 2, pid);
				nni_msg_alloc(&qos_msg, 0);
				nni_msg_header_append(qos_msg, p->txlen, 4);
				nni_aio_set_msg(p->qsaio, qos_msg);
				nng_stream_send(p->ws, p->qsaio);
			}
		} else if (nni_msg_cmd_type(smsg) == CMD_PUBREC) {
			nng_aio_wait(p->qsaio);
			p->txlen[0] = 0X62;
			p->txlen[1] = 0x02;
			memcpy(p->txlen + 2, nni_msg_body(smsg), 2);
			nni_msg_alloc(&qos_msg, 0);
			nni_msg_header_append(qos_msg, p->txlen, 4);
			nni_aio_set_msg(p->qsaio, qos_msg);
			nng_stream_send(p->ws, p->qsaio);
		} else if (nni_msg_cmd_type(smsg) == CMD_PUBREL) {
			nng_aio_wait(p->qsaio);
			p->txlen[0] = CMD_PUBCOMP;
			p->txlen[1] = 0x02;
			memcpy(p->txlen + 2, nni_msg_body(smsg), 2);
			nni_msg_alloc(&qos_msg, 0);
			nni_msg_header_append(qos_msg, p->txlen, 4);
			nni_aio_set_msg(p->qsaio, qos_msg);
			nng_stream_send(p->ws, p->qsaio);
		}

		nni_aio_set_msg(uaio, smsg);
		nni_aio_set_output(uaio, 0, p);
		nni_aio_finish(uaio, 0, nni_msg_len(smsg));
		p->tmp_msg = NULL;
	} else {
		goto reset;
	}
	nni_mtx_unlock(&p->mtx);
	return;
reset:
	p->gotrxhead  = 0;
	p->wantrxhead = 0;
	nng_stream_close(p->ws);
	if (uaio != NULL) {
		nni_aio_finish_error(uaio, rv);
	} else if (p->ep_aio != NULL) {
		nni_aio_finish_error(p->ep_aio, rv);
	}
	if (p->tmp_msg != NULL) {
		smsg = p->tmp_msg;
		nni_msg_free(smsg);
		p->tmp_msg = NULL;
	}
	if (p->ws_param != NULL) {
		conn_param_free(p->ws_param);
	}
	nni_mtx_unlock(&p->mtx);
	return;
}

static void
wstran_pipe_recv_cancel(nni_aio *aio, void *arg, int rv)
{
	ws_pipe *p = arg;
	nni_mtx_lock(&p->mtx);
	if (p->user_rxaio != aio) {
		nni_mtx_unlock(&p->mtx);
		return;
	}
	p->user_rxaio = NULL;
	nni_aio_abort(p->rxaio, rv);
	nni_aio_finish_error(aio, rv);
	nni_mtx_unlock(&p->mtx);
}

static void
wstran_pipe_recv(void *arg, nni_aio *aio)
{
	ws_pipe *p = arg;
	int      rv;

	if (nni_aio_begin(aio) != 0) {
		return;
	}
	nni_mtx_lock(&p->mtx);
	if ((rv = nni_aio_schedule(aio, wstran_pipe_recv_cancel, p)) != 0) {
		nni_mtx_unlock(&p->mtx);
		nni_aio_finish_error(aio, rv);
		return;
	}
	p->user_rxaio = aio;
	nng_stream_recv(p->ws, p->rxaio);
	nni_mtx_unlock(&p->mtx);
}

static void
wstran_pipe_send_cancel(nni_aio *aio, void *arg, int rv)
{
	ws_pipe *p = arg;
	nni_mtx_lock(&p->mtx);
	if (p->user_txaio != aio) {
		nni_mtx_unlock(&p->mtx);
		return;
	}
	p->user_txaio = NULL;
	nni_aio_abort(p->txaio, rv);
	nni_aio_finish_error(aio, rv);
	nni_mtx_unlock(&p->mtx);
}

static inline void
wstran_mqtt_publish(){

}

static void
wstran_pipe_send(void *arg, nni_aio *aio)
{
	ws_pipe *p = arg;
	nni_msg *msg, *smsg;
	uint8_t qos;
	int      rv;

	if (nni_aio_begin(aio) != 0) {
		return;
	}
	nni_mtx_lock(&p->mtx);
	if ((rv = nni_aio_schedule(aio, wstran_pipe_send_cancel, p)) != 0) {
		nni_mtx_unlock(&p->mtx);
		nni_aio_finish_error(aio, rv);
		return;
	}
	p->user_txaio = aio;
	msg = nni_aio_get_msg(aio);
	qos = NANO_NNI_LMQ_GET_QOS_BITS(msg);
	//qos default to 0 if the msg is not PUBLISH
	msg  = NANO_NNI_LMQ_GET_MSG_POINTER(msg);
	if (nni_msg_cmd_type(msg) == CMD_PUBLISH) {
		uint8_t *body, *header, qos_pac;
		uint8_t  varheader[2],
		    fixheader[NNI_NANO_MAX_HEADER_SIZE] = { 0 },
		    tmp[4]                              = { 0 };
		nni_pipe *pipe;
		uint16_t  pid;
		size_t    tlen, rlen;

		qos_pac = nni_msg_get_pub_qos(msg);
		qos = qos_pac > qos ? qos : qos_pac;
		if (qos_pac == 0) {
			// save time & space for QoS 0 publish
			goto send;
		}

		pipe       = p->npipe;
		body       = nni_msg_body(msg);
		header     = nni_msg_header(msg);
		NNI_GET16(body, tlen);
		memcpy(fixheader, header, nni_msg_header_len(msg));
		if (qos_pac > qos) {
			// need to modify the packets
			if (qos == 1) {
				// set qos to 1 (send qos 2 to 1)
				fixheader[0] = fixheader[0] & 0xF9;
				fixheader[0] = fixheader[0] | 0x02;
				rlen         = nni_msg_header_len(msg) - 1;
			} else {
				// set qos to 0 (send qos 2/1 to 0)
				fixheader[0] = fixheader[0] & 0xF9;
				uint32_t pos = 1;
				rlen = put_var_integer(
				    tmp, get_var_integer(header, &pos) - 2);
				memcpy(fixheader + 1, tmp, rlen);
			}
		} else {
			// send msg as it is (qos_pac)
			rlen         = nni_msg_header_len(msg) - 1;
		}
		if (qos > 0) {
			nni_msg *old;
			pid = nni_aio_get_packetid(aio);
			if (pid == 0) {
				// first time send this msg
				pid = nni_pipe_inc_packetid(pipe);
				// store msg for qos retrying
				debug_msg(
				    "* processing QoS pubmsg with pipe: %p *",
				    p);
				nni_msg_clone(msg);
				if ((old = nni_id_get(
				         pipe->nano_qos_db, pid)) != NULL) {
					// TODO packetid already exists.
					// do we need to replace old with new
					// one ? print warning to users
					nni_println(
					    "ERROR: packet id duplicates in "
					    "nano_qos_db");
					old =
					    NANO_NNI_LMQ_GET_MSG_POINTER(old);
					nni_msg_free(old);
					// nni_id_remove(&pipe->nano_qos_db,
					// pid);
				}
				old = NANO_NNI_LMQ_PACKED_MSG_QOS(msg, qos);
				nni_id_set(pipe->nano_qos_db, pid, old);
			}
			NNI_PUT16(varheader, pid);
		}
		nni_msg_alloc(&smsg, 0);
		nni_msg_header_append(smsg, fixheader, rlen + 1);
		nni_msg_append(smsg, body, tlen + 2);
		if (qos > 0) {
			//packetid
			nni_msg_append(smsg, varheader, 2);
		}
		//payload
		nni_msg_append(smsg, body + 4 + tlen, nni_msg_len(msg) - 4 - tlen);
		//duplicated msg is gonna be freed by http. so we free old one here
		nni_msg_free(msg);
		msg = smsg;
	}
// normal sending if it is not PUBLISH
send:
	nni_aio_set_msg(aio, msg);
	nni_aio_set_msg(p->txaio, msg);
	nni_aio_set_msg(aio, NULL);
	// verify connect
    if (nni_msg_cmd_type(msg) == CMD_CONNACK) {
		uint8_t *header = nni_msg_header(msg);
		if (*(header+3) != 0x00) {
			nni_pipe_close(p->npipe);
	    }
	}
	nng_stream_send(p->ws, p->txaio);
	nni_mtx_unlock(&p->mtx);
}

static void
wstran_pipe_stop(void *arg)
{
	ws_pipe *p = arg;

	nni_aio_stop(p->rxaio);
	nni_aio_stop(p->txaio);
	nni_aio_stop(p->qsaio);
}

static int
wstran_pipe_init(void *arg, nni_pipe *pipe)
{
	debug_msg("************wstran_pipe_init************");
	ws_pipe *p = arg;

	nni_pipe_set_conn_param(pipe, p->ws_param);
	p->npipe      = pipe;
	p->gotrxhead  = 0;
	p->wantrxhead = 0;
	p->ep_aio = NULL;
	return (0);
}

static void
wstran_pipe_fini(void *arg)
{
	ws_pipe *p = arg;

	nni_aio_free(p->rxaio);
	nni_aio_free(p->txaio);
	nni_aio_free(p->qsaio);

	nng_stream_free(p->ws);
	nni_msg_free(p->tmp_msg);
	nni_mtx_fini(&p->mtx);
	NNI_FREE_STRUCT(p);
}

static void
wstran_pipe_close(void *arg)
{
	ws_pipe *p = arg;

	nni_aio_close(p->rxaio);
	nni_aio_close(p->qsaio);
	nni_aio_close(p->txaio);

	nni_mtx_lock(&p->mtx);
	nng_stream_close(p->ws);
	nni_mtx_unlock(&p->mtx);
}

static int
wstran_pipe_alloc(ws_pipe **pipep, void *ws)
{
	ws_pipe *p;
	int      rv;

	if ((p = NNI_ALLOC_STRUCT(p)) == NULL) {
		return (NNG_ENOMEM);
	}
	nni_mtx_init(&p->mtx);

	// Initialize AIOs.
	if (((rv = nni_aio_alloc(&p->txaio, wstran_pipe_send_cb, p)) != 0) ||
	    ((rv = nni_aio_alloc(&p->qsaio, NULL, p)) != 0) ||
	    ((rv = nni_aio_alloc(&p->rxaio, wstran_pipe_recv_cb, p)) != 0)) {
		wstran_pipe_fini(p);
		return (rv);
	}
	p->ws = ws;

	*pipep = p;
	return (0);
}

static uint16_t
wstran_pipe_peer(void *arg)
{
	ws_pipe *p = arg;

	return (p->peer);
}

static int
ws_listener_bind(void *arg)
{
	ws_listener *l = arg;
	int          rv;

	if ((rv = nng_stream_listener_listen(l->listener)) == 0) {
		l->started = true;
	}
	return (rv);
}

static void
ws_listener_cancel(nni_aio *aio, void *arg, int rv)
{
	ws_listener *l = arg;

	nni_mtx_lock(&l->mtx);
	if (nni_aio_list_active(aio)) {
		nni_aio_list_remove(aio);
		nni_aio_finish_error(aio, rv);
	}
	nni_mtx_unlock(&l->mtx);
}

static void
wstran_listener_accept(void *arg, nni_aio *aio)
{
	ws_listener *l = arg;
	int          rv;

	// We already bound, so we just need to look for an available
	// pipe (created by the handler), and match it.
	// Otherwise we stick the AIO in the accept list.
	if (nni_aio_begin(aio) != 0) {
		return;
	}
	nni_mtx_lock(&l->mtx);
	if ((rv = nni_aio_schedule(aio, ws_listener_cancel, l)) != 0) {
		nni_mtx_unlock(&l->mtx);
		nni_aio_finish_error(aio, rv);
		return;
	}
	nni_list_append(&l->aios, aio);
	if (aio == nni_list_first(&l->aios)) {
		nng_stream_listener_accept(l->listener, l->accaio);
	}
	nni_mtx_unlock(&l->mtx);
}

static void
wstran_dialer_cancel(nni_aio *aio, void *arg, int rv)
{
	ws_dialer *d = arg;

	nni_mtx_lock(&d->mtx);
	if (nni_aio_list_active(aio)) {
		nni_aio_list_remove(aio);
		nni_aio_finish_error(aio, rv);
	}
	nni_mtx_unlock(&d->mtx);
}

static void
wstran_dialer_connect(void *arg, nni_aio *aio)
{
	ws_dialer *d = arg;
	int        rv;

	if (nni_aio_begin(aio) != 0) {
		return;
	}

	nni_mtx_lock(&d->mtx);
	if ((rv = nni_aio_schedule(aio, wstran_dialer_cancel, d)) != 0) {
		nni_mtx_unlock(&d->mtx);
		nni_aio_finish_error(aio, rv);
		return;
	}
	NNI_ASSERT(nni_list_empty(&d->aios));
	d->started = true;
	nni_list_append(&d->aios, aio);
	nng_stream_dialer_dial(d->dialer, d->connaio);
	nni_mtx_unlock(&d->mtx);
}

static const nni_option ws_pipe_options[] = {
	// terminate list
	{
	    .o_name = NULL,
	}
};

static int
wstran_pipe_getopt(
    void *arg, const char *name, void *buf, size_t *szp, nni_type t)
{
	ws_pipe *p = arg;
	int      rv;

	if ((rv = nni_stream_get(p->ws, name, buf, szp, t)) == NNG_ENOTSUP) {
		rv = nni_getopt(ws_pipe_options, name, p, buf, szp, t);
	}
	return (rv);
}

static nni_sp_pipe_ops ws_pipe_ops = {
	.p_init   = wstran_pipe_init,
	.p_fini   = wstran_pipe_fini,
	.p_stop   = wstran_pipe_stop,
	.p_send   = wstran_pipe_send,
	.p_recv   = wstran_pipe_recv,
	.p_close  = wstran_pipe_close,
	.p_peer   = wstran_pipe_peer,
	.p_getopt = wstran_pipe_getopt,
};

static void
wstran_dialer_fini(void *arg)
{
	ws_dialer *d = arg;

	nni_aio_stop(d->connaio);
	nng_stream_dialer_free(d->dialer);
	nni_aio_free(d->connaio);
	nni_mtx_fini(&d->mtx);
	NNI_FREE_STRUCT(d);
}

static void
wstran_listener_fini(void *arg)
{
	ws_listener *l = arg;

	nni_aio_stop(l->accaio);
	nng_stream_listener_free(l->listener);
	nni_aio_free(l->accaio);
	nni_mtx_fini(&l->mtx);
	NNI_FREE_STRUCT(l);
}

static void
wstran_connect_cb(void *arg)
{
	ws_dialer * d = arg;
	ws_pipe *   p;
	nni_aio *   caio = d->connaio;
	nni_aio *   uaio;
	int         rv;
	nng_stream *ws = NULL;

	nni_mtx_lock(&d->mtx);
	if (nni_aio_result(caio) == 0) {
		ws = nni_aio_get_output(caio, 0);
	}
	if ((uaio = nni_list_first(&d->aios)) == NULL) {
		// The client stopped caring about this!
		nng_stream_free(ws);
		nni_mtx_unlock(&d->mtx);
		return;
	}
	nni_aio_list_remove(uaio);
	NNI_ASSERT(nni_list_empty(&d->aios));
	if ((rv = nni_aio_result(caio)) != 0) {
		nni_aio_finish_error(uaio, rv);
	} else if ((rv = wstran_pipe_alloc(&p, ws)) != 0) {
		nng_stream_free(ws);
		nni_aio_finish_error(uaio, rv);
	} else {
		p->peer = d->peer;

		nni_aio_set_output(uaio, 0, p);
		nni_aio_finish(uaio, 0, 0);
	}
	nni_mtx_unlock(&d->mtx);
}

static void
wstran_dialer_close(void *arg)
{
	ws_dialer *d = arg;

	nni_aio_close(d->connaio);
	nng_stream_dialer_close(d->dialer);
}

static void
wstran_listener_close(void *arg)
{
	ws_listener *l = arg;

	nni_aio_close(l->accaio);
	nng_stream_listener_close(l->listener);
}

static void
ws_pipe_start(ws_pipe *pipe, nng_stream *conn)
{
	NNI_ARG_UNUSED(conn);
	ws_pipe *p = pipe;
	debug_msg("ws_pipe_start!");

	nng_stream_recv(p->ws, p->rxaio);
}

static void
wstran_accept_cb(void *arg)
{
	ws_listener *l    = arg;
	nni_aio *    aaio = l->accaio;
	nni_aio *    uaio;
	int          rv;

	nni_mtx_lock(&l->mtx);
	uaio = nni_list_first(&l->aios);
	if ((rv = nni_aio_result(aaio)) != 0) {
		if (uaio != NULL) {
			nni_aio_list_remove(uaio);
			nni_aio_finish_error(uaio, rv);
		}
	} else {
		nng_stream *ws = nni_aio_get_output(aaio, 0);
		if (uaio != NULL) {
			ws_pipe *p;
			// Make a pipe
			nni_aio_list_remove(uaio);
			if ((rv = wstran_pipe_alloc(&p, ws)) != 0) {
				nng_stream_close(ws);
				nni_aio_finish_error(uaio, rv);
			} else {
				p->peer = l->peer;
				ws_pipe_start(p, p->ws);
				p->ep_aio = uaio;
			}
		}
	}

	if (!nni_list_empty(&l->aios)) {
		nng_stream_listener_accept(l->listener, aaio);
	}
	nni_mtx_unlock(&l->mtx);
}

static int
wstran_dialer_init(void **dp, nng_url *url, nni_dialer *ndialer)
{
	ws_dialer *d;
	nni_sock * s = nni_dialer_sock(ndialer);
	int        rv;
	char       name[64];

	if ((d = NNI_ALLOC_STRUCT(d)) == NULL) {
		return (NNG_ENOMEM);
	}
	nni_mtx_init(&d->mtx);

	nni_aio_list_init(&d->aios);

	d->peer = nni_sock_peer_id(s);

	snprintf(name, sizeof(name), "mqtt");

	if (((rv = nni_ws_dialer_alloc(&d->dialer, url)) != 0) ||
	    ((rv = nni_aio_alloc(&d->connaio, wstran_connect_cb, d)) != 0) ||
	    ((rv = nng_stream_dialer_set_bool(
	          d->dialer, NNI_OPT_WS_MSGMODE, true)) != 0) ||
	    ((rv = nng_stream_dialer_set_string(
	          d->dialer, NNG_OPT_WS_PROTOCOL, name)) != 0)) {
		wstran_dialer_fini(d);
		return (rv);
	}

	*dp = d;
	return (0);
}

// TODO proto name modify
static int
wstran_listener_init(void **lp, nng_url *url, nni_listener *listener)
{
	ws_listener *l;
	int          rv;
	nni_sock *   s = nni_listener_sock(listener);
	char         name[64];

	if ((l = NNI_ALLOC_STRUCT(l)) == NULL) {
		return (NNG_ENOMEM);
	}
	nni_mtx_init(&l->mtx);

	nni_aio_list_init(&l->aios);

	l->peer = nni_sock_peer_id(s);

	snprintf(name, sizeof(name), "mqtt");

	if (((rv = nni_ws_listener_alloc(&l->listener, url)) != 0) ||
	    ((rv = nni_aio_alloc(&l->accaio, wstran_accept_cb, l)) != 0) ||
	    ((rv = nng_stream_listener_set_bool(
	          l->listener, NNI_OPT_WS_MSGMODE, true)) != 0) ||
	    ((rv = nng_stream_listener_set_string(
	          l->listener, NNG_OPT_WS_PROTOCOL, name)) != 0)) {
		wstran_listener_fini(l);
		return (rv);
	}
	*lp = l;
	return (0);
}

static void
wstran_init(void)
{
}

static void
wstran_fini(void)
{
}

static const nni_option wstran_ep_opts[] = {
	// terminate list
	{
	    .o_name = NULL,
	},
};

static int
wstran_dialer_getopt(
    void *arg, const char *name, void *buf, size_t *szp, nni_type t)
{
	ws_dialer *d = arg;
	int        rv;

	rv = nni_stream_dialer_get(d->dialer, name, buf, szp, t);
	if (rv == NNG_ENOTSUP) {
		rv = nni_getopt(wstran_ep_opts, name, d, buf, szp, t);
	}
	return (rv);
}

static int
wstran_dialer_setopt(
    void *arg, const char *name, const void *buf, size_t sz, nni_type t)
{
	ws_dialer *d = arg;
	int        rv;

	rv = nni_stream_dialer_set(d->dialer, name, buf, sz, t);
	if (rv == NNG_ENOTSUP) {
		rv = nni_setopt(wstran_ep_opts, name, d, buf, sz, t);
	}
	return (rv);
}

static int
wstran_listener_get(
    void *arg, const char *name, void *buf, size_t *szp, nni_type t)
{
	ws_listener *l = arg;
	int          rv;

	rv = nni_stream_listener_get(l->listener, name, buf, szp, t);
	if (rv == NNG_ENOTSUP) {
		rv = nni_getopt(wstran_ep_opts, name, l, buf, szp, t);
	}
	return (rv);
}

static int
wstran_listener_set(
    void *arg, const char *name, const void *buf, size_t sz, nni_type t)
{
	ws_listener *l = arg;
	int          rv;

	rv = nni_stream_listener_set(l->listener, name, buf, sz, t);
	if (rv == NNG_ENOTSUP) {
		rv = nni_setopt(wstran_ep_opts, name, l, buf, sz, t);
	}
	return (rv);
}

static nni_sp_dialer_ops ws_dialer_ops = {
	.d_init    = wstran_dialer_init,
	.d_fini    = wstran_dialer_fini,
	.d_connect = wstran_dialer_connect,
	.d_close   = wstran_dialer_close,
	.d_setopt  = wstran_dialer_setopt,
	.d_getopt  = wstran_dialer_getopt,
};

static nni_sp_listener_ops ws_listener_ops = {
	.l_init   = wstran_listener_init,
	.l_fini   = wstran_listener_fini,
	.l_bind   = ws_listener_bind,
	.l_accept = wstran_listener_accept,
	.l_close  = wstran_listener_close,
	.l_setopt = wstran_listener_set,
	.l_getopt = wstran_listener_get,
};

static nni_sp_tran ws_tran = {
	.tran_scheme   = "ws",
	.tran_dialer   = &ws_dialer_ops,
	.tran_listener = &ws_listener_ops,
	.tran_pipe     = &ws_pipe_ops,
	.tran_init     = wstran_init,
	.tran_fini     = wstran_fini,
};

static nni_sp_tran ws4_tran = {
	.tran_scheme   = "ws4",
	.tran_dialer   = &ws_dialer_ops,
	.tran_listener = &ws_listener_ops,
	.tran_pipe     = &ws_pipe_ops,
	.tran_init     = wstran_init,
	.tran_fini     = wstran_fini,
};

static nni_sp_tran ws6_tran = {
	.tran_scheme   = "ws6",
	.tran_dialer   = &ws_dialer_ops,
	.tran_listener = &ws_listener_ops,
	.tran_pipe     = &ws_pipe_ops,
	.tran_init     = wstran_init,
	.tran_fini     = wstran_fini,
};

#ifndef NNG_ELIDE_DEPRECATED
int
nng_ws_register(void)
{
	return (nni_init());
}

int
nng_wss_register(void)
{
	return (nni_init());
}
#endif

void
nni_sp_ws_register(void)
{
	nni_sp_tran_register(&ws_tran);
	nni_sp_tran_register(&ws4_tran);
	nni_sp_tran_register(&ws6_tran);
}

#ifdef NNG_TRANSPORT_WSS

static nni_sp_tran wss_tran = {
	.tran_scheme   = "wss",
	.tran_dialer   = &ws_dialer_ops,
	.tran_listener = &ws_listener_ops,
	.tran_pipe     = &ws_pipe_ops,
	.tran_init     = wstran_init,
	.tran_fini     = wstran_fini,
};

static nni_sp_tran wss4_tran = {
	.tran_scheme   = "wss4",
	.tran_dialer   = &ws_dialer_ops,
	.tran_listener = &ws_listener_ops,
	.tran_pipe     = &ws_pipe_ops,
	.tran_init     = wstran_init,
	.tran_fini     = wstran_fini,
};

static nni_sp_tran wss6_tran = {
	.tran_scheme   = "wss6",
	.tran_dialer   = &ws_dialer_ops,
	.tran_listener = &ws_listener_ops,
	.tran_pipe     = &ws_pipe_ops,
	.tran_init     = wstran_init,
	.tran_fini     = wstran_fini,
};

void
nni_sp_wss_register(void)
{
	nni_sp_tran_register(&wss_tran);
	nni_sp_tran_register(&wss4_tran);
	nni_sp_tran_register(&wss6_tran);
}

#endif // NNG_TRANSPORT_WSS
