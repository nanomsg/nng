// Copyright 2025 Staysail Systems, Inc. <info@staysail.tech>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "../../../core/aio.h"
#include "../../../core/defs.h"
#include "../../../core/idhash.h"
#include "../../../core/message.h"
#include "../../../core/nng_impl.h"
#include "../../../core/options.h"
#include "../../../core/pipe.h"
#include "../../../core/platform.h"
#include "../../../core/socket.h"
#include "../../../core/stats.h"
#include "../../../supplemental/tls/tls_common.h"
#include "nng/nng.h"

#include <string.h>

// Experimental DTLS transport.  Unicast only.
//
typedef struct dtls_pipe dtls_pipe;
typedef struct dtls_ep   dtls_ep;
typedef struct dtls_conn dtls_conn;

const uint8_t PROTO_VERSION = 1;

// OP code, 8 bits
enum dtls_opcode {
	OPCODE_DATA = 0,
	OPCODE_CREQ = 1,
	OPCODE_CACK = 2,
	OPCODE_DISC = 3,
};

// Disconnect reason, must be 16 bits
typedef enum dtls_disc_reason {
	DISC_CLOSED   = 0, // normal close
	DISC_TYPE     = 1, // bad SP type
	DISC_NOTCONN  = 2, // no such connection
	DISC_REFUSED  = 3, // refused by policy
	DISC_MSGSIZE  = 4, // message too large
	DISC_NEGO     = 5, // neogtiation failed
	DISC_INACTIVE = 6, // closed due to inactivity
	DISC_PROTO    = 7, // other protocol error
	DISC_NOBUF    = 8, // resources exhausted
} dtls_disc_reason;

#ifndef NNG_DTLS_TXQUEUE_LEN
#define NNG_DTLS_TXQUEUE_LEN 32
#endif

#ifndef NNG_DTLS_RXQUEUE_LEN
#define NNG_DTLS_RXQUEUE_LEN 16
#endif

// The maximum TLS record size
#define DTLS_MAX_RECORD 16384

// For DTLS we use a maximum record size of 16384,
// but we reserve some space for headers.  DTLS needs
// 13 bytes, and the transport layer needs 8 bytes.
// To leave some room for the future, we just trim to 64 bytes.
#ifndef NNG_DTLS_RECVMAX
#define NNG_DTLS_RECVMAX (DTLS_MAX_RECORD - 64)
#endif

#ifndef NNG_DTLS_REFRESH
#define NNG_DTLS_REFRESH (5 * NNI_SECOND)
#endif

#ifndef NNG_DTLS_CONNRETRY
#define NNG_DTLS_CONNRETRY (NNI_SECOND / 5)
#endif

// 64-bit protocol header
typedef struct dtls_sp_hdr {
	uint8_t  us_ver;
	uint8_t  us_op_code;
	uint16_t us_type;
	uint16_t us_params[2];
} dtls_sp_hdr;

// DTLS pipe resend (CREQ) in msec (nng_duration)
#define DTLS_PIPE_REFRESH(p) ((p)->refresh)

// DTLS pipe timeout in msec (nng_duration)
#define DTLS_PIPE_TIMEOUT(p) ((p)->refresh * 5)

struct dtls_pipe {
	dtls_ep      *ep;
	nni_pipe     *npipe;
	nng_sockaddr  peer_addr;
	uint64_t      id; // hash of peer address
	uint16_t      peer;
	uint16_t      proto;
	bool          matched; // true if have matched and given this to SP
	bool          closed;  // true if we are closed (no more send or recv!)
	bool          dialer;  // true if we are dialer
	nng_duration  refresh; // seconds, for the protocol
	nng_time      next_wake;
	nng_time      expire; // inactivity expiration time
	nng_time      next_refresh;
	nni_list_node node;
	nni_lmq       rx_mq;

	// Upper layer queues.  These are between the PIPE and SP.
	bool     send_busy; // true if send is in process
	uint16_t send_max;  // peer's max recv size
	nni_list send_aios;
	uint8_t *send_buf;
	size_t   send_bufsz;
	nng_aio  send_tls_aio;

	bool     recv_busy;
	bool     recv_rdy; // receive is done and data in recvbuf
	uint16_t recv_max; // max recv size
	nni_list recv_aios;
	uint8_t *recv_buf;
	size_t   recv_bufsz;
	nng_aio  recv_tls_aio;

	// Lower layer queues.  These are between the

	uint8_t  send_op; // usually OPCODE_DATA
	uint8_t  last_op; // last op code we sent
	uint16_t reason;  // only for disconnect

	nni_mtx lower_mtx; // protects the lower rx_q, etc.

	// This is the lower level RX buffer, which contains only
	// received ciphertext (content before passed to TLS layer for
	// decrypt).  The actual pointers may change, as we "swap"
	// buffers between the endpoint and the pipe to avoid copying.
	nni_list rx_q; // lower aio from the TLS layer

	nni_tls_conn tls;
};

struct dtls_ep {
	nng_udp        *udp;
	nni_mtx         mtx;
	uint16_t        proto;
	uint16_t        peer;
	uint16_t        af; // address family
	bool            fini;
	bool            started;
	bool            closed;
	nng_url        *url;
	const char     *host; // for dialers
	nni_aio        *useraio;
	nni_aio        *connaio;
	nni_aio         timeaio;
	nni_aio         resaio;
	bool            dialer;
	nni_listener   *nlistener;
	nni_dialer     *ndialer;
	nni_msg        *rx_payload; // current receive message
	nng_sockaddr    rx_sa;      // addr for last message
	nni_aio         tx_aio;     // aio for TX handling
	nni_aio         rx_aio;     // aio for RX handling
	nni_id_map      pipes;      // pipes (indexed by id)
	nni_sockaddr    self_sa;    // our address
	nni_sockaddr    peer_sa;    // peer address, only for dialer;
	nni_list        connaios; // aios from accept waiting for a client peer
	nni_list        connpipes; // pipes waiting to be connected
	nng_duration    refresh; // refresh interval for connections in seconds
	uint16_t        rcvmax;  // max payload, trimmed to uint16_t
	nni_resolv_item resolv;

	nng_tls_config *tlscfg;

	size_t rx_size; // size of the rx buffer
	void  *rx_buf;

	nni_stat_item st_rcv_max;
	nni_stat_item st_rcv_reorder;
	nni_stat_item st_rcv_toobig;
	nni_stat_item st_rcv_nomatch;
	nni_stat_item st_rcv_copy;
	nni_stat_item st_rcv_nocopy;
	nni_stat_item st_rcv_nobuf;
	nni_stat_item st_snd_toobig;
	nni_stat_item st_snd_nobuf;
	nni_stat_item st_peer_inactive;
	nni_stat_item st_copy_max;
};

static void dtls_ep_start(dtls_ep *);
static void dtls_resolv_cb(void *);
static void dtls_rx_cb(void *);

static void dtls_ep_match(dtls_ep *ep);
static void dtls_remove_pipe(dtls_pipe *p);

// BIO send/recv functions for use by the common TLS layer.

static void
dtls_bio_cancel(nng_aio *aio, void *arg, nng_err rv)
{
	dtls_pipe *p = arg;
	nni_mtx_lock(&p->lower_mtx);
	if (nni_aio_list_active(aio)) {
		nni_aio_list_remove(aio);
		nni_aio_finish_error(aio, rv);
	}
	nni_mtx_unlock(&p->lower_mtx);
}

static void
dtls_bio_recv_done(dtls_pipe *p)
{
	nng_aio *aio;
	nni_msg *msg;

	while ((!nni_lmq_empty(&p->rx_mq)) &&
	    ((aio = nni_list_first(&p->rx_q)) != NULL)) {

		nni_aio_list_remove(aio);
		nni_lmq_get(&p->rx_mq, &msg);

		nni_aio_finish_msg(aio, msg);
	}
}

static void
dtls_bio_recv(void *arg, nng_aio *aio)
{
	dtls_pipe *p = arg;

	nni_mtx_lock(&p->lower_mtx);
	if (!nni_aio_start(aio, dtls_bio_cancel, p)) {
		nni_mtx_unlock(&p->lower_mtx);
		return;
	}

	nni_aio_list_append(&p->rx_q, aio);
	dtls_bio_recv_done(p);
	nni_mtx_unlock(&p->lower_mtx);
}

static void
dtls_bio_send(void *arg, nng_aio *aio)
{
	dtls_pipe *p = arg;
	nni_iov    iov;
	nni_msg   *msg;

	nni_mtx_lock(&p->lower_mtx);
	if (!p->closed) {
		nni_aio_set_input(aio, 0, &p->peer_addr);
		msg         = nni_aio_get_msg(aio);
		iov.iov_buf = nni_msg_body(msg);
		iov.iov_len = nni_msg_len(msg);
		nng_aio_set_iov(aio, 1, &iov);
		nng_udp_send(p->ep->udp, aio);
	} else {
		nni_aio_finish_error(aio, NNG_ECLOSED);
	}
	nni_mtx_unlock(&p->lower_mtx);
}

static void
dtls_bio_free(void *arg)
{
	NNI_ARG_UNUSED(arg);
}

static void
dtls_bio_close(void *arg)
{
	NNI_ARG_UNUSED(arg);
}

static void
dtls_bio_stop(void *arg)
{
	dtls_pipe *p = arg;
	nni_aio_stop(&p->recv_tls_aio);
	nni_aio_stop(&p->send_tls_aio);
}

static nni_tls_bio_ops dtls_bio_ops = {
	.bio_send  = dtls_bio_send,
	.bio_recv  = dtls_bio_recv,
	.bio_close = dtls_bio_close,
	.bio_stop  = dtls_bio_stop,
	.bio_free  = dtls_bio_free,
};

static void
dtls_tran_init(void)
{
}

static void
dtls_tran_fini(void)
{
}

//
// Upper layer functions - moving data between TLS and SP.
// TLS acts as kind of a stream for us, so we only see the
// data that is meant for us, but we will send and receive
// control messages that are not just data payloads.
//

static void dtls_pipe_send_cancel(nng_aio *, void *, nng_err);
static void dtls_pipe_send_tls(dtls_pipe *);
static void dtls_pipe_send_tls_cb(void *arg);

static void
dtls_pipe_send(void *arg, nni_aio *aio)
{
	dtls_pipe *p = arg;
	dtls_ep   *ep;
	nng_msg   *msg;
	size_t     count = 0;
	size_t     sndmax;

	msg = nni_aio_get_msg(aio);
	ep  = p->ep;

	if (msg != NULL) {
		count = nni_msg_len(msg) + nni_msg_header_len(msg);
	}

	nni_mtx_lock(&ep->mtx);
	sndmax = p->send_max;
	if (!nni_aio_start(aio, dtls_pipe_send_cancel, p)) {
		nni_aio_set_msg(aio, NULL);
		nni_msg_free(msg);
		nni_mtx_unlock(&ep->mtx);
		return;
	}

	nni_aio_reset(aio);
	if ((nni_msg_len(msg) + nni_msg_header_len(msg)) > sndmax) {
		// rather failing this with an error, we just drop it
		// on the floor. this is on the sender, so there isn't
		// a compelling need to disconnect the pipe, since it
		// we're not being "ill-behaved" to our peer.
		nni_stat_inc(&ep->st_snd_toobig, 1);
		nni_mtx_unlock(&ep->mtx);
		nni_aio_finish(aio, 0, count);
		nni_msg_free(msg);
		return;
	}

	nni_aio_list_append(&p->send_aios, aio);
	dtls_pipe_send_tls(p);
	nni_mtx_unlock(&ep->mtx);
}

static void
dtls_pipe_send_cancel(nng_aio *aio, void *arg, nng_err err)
{
	dtls_pipe *p = arg;
	nni_mtx_lock(&p->ep->mtx);
	if (nni_aio_list_active(aio)) {
		nni_aio_list_remove(aio);
		nni_aio_finish_error(aio, err);
	}
	nni_mtx_unlock(&p->ep->mtx);
}

// Lower layer send/recv functions, used by the pipe layer.

static void
dtls_pipe_send_tls(dtls_pipe *p)
{
	nni_aio     *aio;
	nng_msg     *msg;
	uint8_t      opcode;
	nng_iov      iov;
	dtls_sp_hdr *hdr = (void *) p->send_buf;

	if (p->send_busy || p->closed) {
		return;
	}

	opcode = p->send_op;
	// reset the last op
	p->send_op = OPCODE_DATA;

	hdr->us_ver     = PROTO_VERSION;
	hdr->us_op_code = opcode;
	NNI_PUT16LE(&hdr->us_type, p->proto);
	hdr->us_params[0] = 0;
	hdr->us_params[1] = 0;

	iov.iov_buf = hdr;
	iov.iov_len = sizeof(*hdr);

	switch (opcode) {
	case OPCODE_DATA:
		for (;;) {
			if ((aio = nni_list_first(&p->send_aios)) == NULL) {
				// no work for us!
				return;
			}
			nni_aio_list_remove(aio);
			msg = nni_aio_get_msg(aio);
			if (nni_msg_header_len(msg) + nni_msg_len(msg) +
			        sizeof(*hdr) >
			    p->send_bufsz) {
				nng_msg_free(msg);
				nni_aio_finish_error(aio, NNG_EMSGSIZE);
				continue;
			}
			break; // for loop
		}

		size_t   len  = nni_msg_header_len(msg);
		uint8_t *data = (void *) (hdr + 1);
		memcpy(data, nni_msg_header(msg), len);
		data += len;
		memcpy(data, nni_msg_body(msg), nni_msg_len(msg));
		len += nni_msg_len(msg);

		NNI_PUT16LE(&hdr->us_params[0], (uint16_t) len);
		iov.iov_len += len;

		nni_msg_free(msg);
		nni_aio_set_msg(aio, NULL);
		nni_aio_finish(aio, 0, len);
		break;

	case OPCODE_CREQ:
	case OPCODE_CACK:
		NNI_PUT16LE(&hdr->us_params[0], p->recv_max);
		NNI_PUT16LE(&hdr->us_params[1], p->refresh);
		break;

	case OPCODE_DISC:
		NNI_PUT16LE(&hdr->us_params[0], p->reason);
		break;
	default:
		NNI_ASSERT(false); // this should never happen!
		// fall back to sending a disconnect
		hdr->us_op_code = OPCODE_DISC;
		NNI_PUT16LE(&hdr->us_params[0], DISC_PROTO);
	}

	p->last_op   = opcode;
	p->send_busy = true;
	nni_aio_set_iov(&p->send_tls_aio, 1, &iov);
	nni_tls_send(&p->tls, &p->send_tls_aio);
}

static void
dtls_pipe_send_tls_cb(void *arg)
{
	dtls_pipe *p = arg;

	nni_mtx_lock(&p->ep->mtx);

	p->send_busy = false;
	if (p->closed) {
		nni_mtx_unlock(&p->ep->mtx);
		return;
	}
	if (nni_aio_result(&p->send_tls_aio) != NNG_OK) {
		nni_pipe_close(p->npipe);
		nni_mtx_unlock(&p->ep->mtx);
		return;
	}
	dtls_pipe_send_tls(p);
	nni_mtx_unlock(&p->ep->mtx);
}

// RECV SIDE

static void dtls_pipe_recv_cancel(nni_aio *, void *, nng_err);
static void dtls_pipe_recv_tls(dtls_pipe *);

static void
dtls_pipe_recv(void *arg, nni_aio *aio)
{
	dtls_pipe *p  = arg;
	dtls_ep   *ep = p->ep;

	nni_aio_reset(aio);
	nni_mtx_lock(&ep->mtx);
	if (p->closed) {
		nni_mtx_unlock(&ep->mtx);
		nni_aio_finish_error(aio, NNG_ECLOSED);
		return;
	}
	if (!nni_aio_start(aio, dtls_pipe_recv_cancel, p)) {
		nni_mtx_unlock(&ep->mtx);
		return;
	}

	nni_list_append(&p->recv_aios, aio);
	dtls_pipe_recv_tls(p);
	nni_mtx_unlock(&ep->mtx);
}

static void
dtls_pipe_recv_cancel(nni_aio *aio, void *arg, nng_err rv)
{
	dtls_pipe *p  = arg;
	dtls_ep   *ep = p->ep;

	nni_mtx_lock(&ep->mtx);
	if (!nni_aio_list_active(aio)) {
		nni_mtx_unlock(&ep->mtx);
		return;
	}
	nni_aio_list_remove(aio);
	nni_mtx_unlock(&ep->mtx);
	nni_aio_finish_error(aio, rv);
}

static void
dtls_pipe_recv_tls_start(dtls_pipe *p)
{
	nng_iov iov;
	if (p->recv_busy || p->closed) {
		return;
	}
	p->recv_busy = true;
	iov.iov_buf  = p->recv_buf;
	iov.iov_len  = p->recv_bufsz;

	nni_aio_set_iov(&p->recv_tls_aio, 1, &iov);
	nni_tls_recv(&p->tls, &p->recv_tls_aio);
}

static void
dtls_pipe_recv_tls(dtls_pipe *p)
{
	nng_aio *aio = nni_list_first(&p->recv_aios);
	size_t   len;
	nng_msg *msg;
	nng_err  rv;

	if (aio == NULL) {
		return;
	}
	if (!p->recv_rdy) {
		dtls_pipe_recv_tls_start(p);
		return;
	}

	p->recv_rdy = false;

	nni_aio_list_remove(aio);
	len = nng_aio_count(&p->recv_tls_aio);
	NNI_ASSERT(len >= sizeof(dtls_sp_hdr));
	len -= sizeof(dtls_sp_hdr);

	if ((rv = nni_msg_alloc(&msg, len)) != NNG_OK) {
		nni_aio_finish_error(aio, rv);
		return;
	}

	memcpy(nng_msg_body(msg), p->recv_buf + sizeof(dtls_sp_hdr), len);
	nni_aio_finish_msg(aio, msg);
}

static void
dtls_pipe_recv_tls_cb(void *arg)
{
	dtls_pipe   *p   = arg;
	dtls_ep     *ep  = p->ep;
	dtls_sp_hdr *hdr = (void *) p->recv_buf;
	nng_aio     *aio = &p->recv_tls_aio;
	uint16_t     proto;
	uint16_t     refresh;
	uint16_t     rcvmax;
	nng_err      rv;

	nni_mtx_lock(&ep->mtx);
	p->recv_busy = false;

	if ((rv = nni_aio_result(aio)) != NNG_OK) {

		// If we didn't connect yet, issue an error so the peer can see
		// a connection failure (e.g. if we failed the TLS handshake.)
		if (p->dialer && !p->matched) {
			nni_aio *caio;
			if ((caio = nni_list_first(&ep->connaios)) != NULL) {
				nni_aio_list_remove(caio);
				nni_aio_finish_error(caio, rv);
			}
		}

		// Bump a bad receive stat (e.g. someone may have sent us
		// garbage.)  We do not acknowledge or handle garbage frames
		// sent to an open session.
		nni_pipe_close(p->npipe);
		nni_mtx_unlock(&ep->mtx);
		return;
	}

	// We had a "good" receive (TLS passed at least) from the peer.

	if (nni_aio_count(aio) < sizeof(*hdr)) {
		// Runt frame.
		p->send_op = OPCODE_DISC;
		p->reason  = DISC_PROTO;
		goto bad;
	}

	if (nni_aio_count(aio) > sizeof(*hdr) + p->recv_max) {
		p->send_op = OPCODE_DISC;
		p->reason  = DISC_MSGSIZE;
		goto bad;
	}

	if (hdr->us_ver != PROTO_VERSION) {
		// Bad protocol version
		p->send_op = OPCODE_DISC;
		p->reason  = DISC_PROTO;
		goto bad;
	}
	NNI_GET16LE(&hdr->us_type, proto);
	if (proto != p->peer) {
		// Bad SP protocol type
		p->send_op = OPCODE_DISC;
		p->reason  = DISC_TYPE;
		goto bad;
	}

	p->expire = nni_clock() + DTLS_PIPE_TIMEOUT(p);

	if (!p->matched) {
		p->matched = true;
		nni_list_append(&p->ep->connpipes, p);
		dtls_ep_match(p->ep);
	}

	switch (hdr->us_op_code) {
	case OPCODE_CREQ:
		if (p->dialer) {
			// dialers don't accept requests
			goto bad;
		}
		NNI_GET16LE(&hdr->us_params[0], rcvmax);
		NNI_GET16LE(&hdr->us_params[1], refresh);
		if ((refresh > 0) && ((refresh * NNI_SECOND) < p->refresh)) {
			p->refresh = refresh * NNI_SECOND;
		}
		if ((rcvmax > 0) && (rcvmax < NNG_DTLS_RECVMAX)) {
			p->send_max = rcvmax;
		}
		// schedule the CACK reply
		p->send_op = OPCODE_CACK;
		break;

	case OPCODE_CACK:
		if (!p->dialer) {
			goto bad;
		}
		NNI_GET16LE(&hdr->us_params[0], rcvmax);
		NNI_GET16LE(&hdr->us_params[0], refresh);

		if ((refresh > 0) && ((refresh * NNI_SECOND) < p->refresh)) {
			p->refresh = refresh * NNI_SECOND;
		}
		if ((rcvmax > 0) && (rcvmax < NNG_DTLS_RECVMAX)) {
			p->send_max = rcvmax;
		}
		break;

	case OPCODE_DISC:
		p->closed = true;
		nni_mtx_unlock(&ep->mtx);
		nni_pipe_close(p->npipe);
		return;

	case OPCODE_DATA:
		p->recv_rdy = true;
		dtls_pipe_recv_tls(p);
		nni_mtx_unlock(&ep->mtx);
		return;
	}
bad:
	if (p->send_op != OPCODE_DATA) {
		dtls_pipe_send_tls(p);
	}
	dtls_pipe_recv_tls_start(p);
	nni_mtx_unlock(&ep->mtx);
}

static void
dtls_pipe_close(void *arg)
{
	dtls_pipe *p  = arg;
	dtls_ep   *ep = p->ep;
	nni_aio   *aio;

	nni_mtx_lock(&ep->mtx);
	while ((aio = nni_list_first(&p->recv_aios)) != NULL) {
		nni_aio_list_remove(aio);
		nni_aio_finish_error(aio, NNG_ECLOSED);
	}
	while ((aio = nni_list_first(&p->send_aios)) != NULL) {
		nni_aio_list_remove(aio);
		nni_aio_finish_error(aio, NNG_ECLOSED);
	}
	if (p->matched) {
		p->send_op = OPCODE_DISC;
		p->reason  = DISC_CLOSED;
		dtls_pipe_send_tls(p);
	}
	p->closed = true;
	nni_mtx_unlock(&ep->mtx);
}

static nng_err dtls_add_pipe(dtls_ep *ep, dtls_pipe *p);

static void
dtls_pipe_stop(void *arg)
{
	dtls_pipe *p  = arg;
	dtls_ep   *ep = p->ep;

	dtls_pipe_close(arg);

	nni_tls_stop(&p->tls);

	nni_mtx_lock(&ep->mtx);
	dtls_remove_pipe(p);
	nni_list_node_remove(&p->node);
	nni_mtx_unlock(&ep->mtx);
}

static int
dtls_pipe_alloc(dtls_ep *ep, dtls_pipe **pp, const nng_sockaddr *sa)
{
	dtls_pipe *p;
	nng_err    rv;

	if (ep->dialer) {
		rv = nni_pipe_alloc_dialer((void **) &p, ep->ndialer);
	} else {
		rv = nni_pipe_alloc_listener((void *) &p, ep->nlistener);
	}
	if (rv != NNG_OK) {
		nng_log_err("NNG-DTLS-PIPE-ALLOC-FAIL",
		    "Failed allocating pipe for DTLS: %s", nng_strerror(rv));
		return (rv);
	}
	p->dialer    = ep->dialer;
	p->ep        = ep;
	p->proto     = ep->proto;
	p->peer      = ep->peer;
	p->peer_addr = *sa;
	p->id        = nng_sockaddr_hash(sa);
	p->refresh   = ep->refresh;
	p->send_max  = NNG_DTLS_RECVMAX;
	p->recv_max  = ep->rcvmax;
	*pp          = p;

	if (((rv = nni_tls_init(&p->tls, ep->tlscfg, true)) != NNG_OK) ||
	    ((rv = nni_tls_start(&p->tls, &dtls_bio_ops, p, sa)) != NNG_OK) ||
	    ((rv = dtls_add_pipe(ep, p)) != NNG_OK)) {
		nni_pipe_close(p->npipe);
		nng_log_err("NNG-DTLS-PIPE-ADD-FAIL",
		    "Failed adding pipe for DTLS: %s", nng_strerror(rv));
		return (rv);
	}

	// We need to start a receiver on the pipe.
	dtls_pipe_recv_tls_start(p);

	// Also start TLS up and running.
	switch (nni_tls_run(&p->tls)) {
	case NNG_OK:
	case NNG_EAGAIN:
		break;
	default:
		nni_pipe_close(p->npipe);
		break;
	}

	// wake the timer so it knows to resubmit
	nni_aio_abort(&ep->timeaio, NNG_ETIMEDOUT);

	return (NNG_OK);
}

static size_t
dtls_pipe_size(void)
{
	return (NNI_ALIGN_UP(sizeof(dtls_pipe)) +
	    NNI_ALIGN_UP(nni_tls_engine_conn_size()));
}

static int
dtls_pipe_init(void *arg, nni_pipe *npipe)
{
	dtls_pipe *p = arg;
	p->npipe     = npipe;

	size_t bufsz = DTLS_MAX_RECORD; // TODO: Make this a tunable.

	if ((p->recv_buf = nni_alloc(bufsz)) == NULL) {
		return (NNG_ENOMEM);
	}
	if ((p->send_buf = nni_alloc(bufsz)) == NULL) {
		return (NNG_ENOMEM);
	}
	p->recv_bufsz = bufsz;
	p->send_bufsz = bufsz;
	nni_mtx_init(&p->lower_mtx);
	nni_aio_init(&p->recv_tls_aio, dtls_pipe_recv_tls_cb, p);
	nni_aio_init(&p->send_tls_aio, dtls_pipe_send_tls_cb, p);
	nni_aio_list_init(&p->rx_q);
	nni_aio_list_init(&p->recv_aios);
	nni_aio_list_init(&p->send_aios);
	nni_lmq_init(&p->rx_mq, NNG_DTLS_RXQUEUE_LEN);

	return (0);
}

static void
dtls_pipe_fini(void *arg)
{
	dtls_pipe *p = arg;
	nng_msg   *m;

	nni_tls_fini(&p->tls);
	nni_aio_fini(&p->recv_tls_aio);
	nni_aio_fini(&p->send_tls_aio);
	if (p->recv_buf != NULL) {
		nni_free(p->recv_buf, p->recv_bufsz);
	}
	if (p->send_buf != NULL) {
		nni_free(p->send_buf, p->send_bufsz);
	}
	nni_mtx_lock(&p->lower_mtx);
	while (!nni_lmq_empty(&p->rx_mq)) {
		nni_lmq_get(&p->rx_mq, &m);
		nni_msg_free(m);
	}
	nni_mtx_unlock(&p->lower_mtx);
	nni_mtx_fini(&p->lower_mtx);
	nni_lmq_fini(&p->rx_mq);
	NNI_ASSERT(nni_list_empty(&p->recv_aios));
	NNI_ASSERT(nni_list_empty(&p->send_aios));
}

static dtls_pipe *
dtls_find_pipe(dtls_ep *ep, const nng_sockaddr *peer_addr)
{
	uint64_t   id = nng_sockaddr_hash(peer_addr);
	dtls_pipe *p;

	// we'll keep incrementing id until we conclusively match
	// or we get a NULL.  This is another level of rehashing, but
	// it keeps us from having to look up.
	for (;;) {
		if ((p = nni_id_get(&ep->pipes, id)) == NULL) {
			return (NULL);
		}
		if (nng_sockaddr_equal(&p->peer_addr, peer_addr)) {
			return (p);
		}
		id++;
		if (id == 0) {
			id = 1;
		}
	}
}

static void
dtls_remove_pipe(dtls_pipe *p)
{
	// ep locked
	dtls_ep *ep      = p->ep;
	uint64_t id      = p->id;
	bool     matched = p->matched;
	if (id == 0) {
		return;
	}
	p->id = 0;
	for (;;) {
		dtls_pipe *srch;
		if ((srch = nni_id_get(&ep->pipes, id)) == NULL) {
			break;
		}
		if (srch == p) {
			nni_id_remove(&ep->pipes, id);
			break;
		}
		id++;
		if (id == 0) {
			id = 1;
		}
	}
	if (!matched) {
		nni_pipe_rele(p->npipe);
	}
}

static nng_err
dtls_add_pipe(dtls_ep *ep, dtls_pipe *p)
{
	// Id must be part of the hash
	uint64_t id = p->id;
	while (nni_id_get(&ep->pipes, id) != NULL) {
		id++;
		if (id == 0) {
			id = 1;
		}
	}
	p->id = id;
	return (nni_id_set(&ep->pipes, id, p));
}

static void
dtls_start_rx(dtls_ep *ep)
{
	nni_iov iov;

	iov.iov_buf = ep->rx_buf;
	iov.iov_len = ep->rx_size;

	nni_aio_reset(&ep->rx_aio);
	nni_aio_set_input(&ep->rx_aio, 0, &ep->rx_sa);
	nni_aio_set_iov(&ep->rx_aio, 1, &iov);
	nng_udp_recv(ep->udp, &ep->rx_aio);
}

static void
dtls_rx_cb(void *arg)
{
	dtls_ep   *ep = arg;
	dtls_pipe *p;
	nni_aio   *aio = &ep->rx_aio;
	nng_err    rv;
	nni_msg   *msg;

	nni_mtx_lock(&ep->mtx);
	if ((rv = nni_aio_result(aio)) != NNG_OK) {
		// something bad happened on RX... which is unexpected.
		// sleep a little bit and hope for recovery.
		switch (nni_aio_result(aio)) {
		case NNG_ECLOSED:
		case NNG_ECANCELED:
		case NNG_ESTOPPED:
			nni_mtx_unlock(&ep->mtx);
			return;
		case NNG_ETIMEDOUT:
		case NNG_EAGAIN:
		case NNG_EINTR:
		default:
			goto fail;
		}
	}

	// If this came from another host, and we are a dialer, we discard.
	// Dialers only talk to the party they explicitly dialed.
	if (ep->dialer && !nng_sockaddr_equal(&ep->rx_sa, &ep->peer_sa)) {
		goto fail;
	}

	if ((p = dtls_find_pipe(ep, &ep->rx_sa)) == NULL) {
		if (dtls_pipe_alloc(ep, &p, &ep->rx_sa) != NNG_OK) {
			goto fail;
		}
	}
	if (p->closed) {
		goto fail;
	}
	NNI_ASSERT(p != NULL);

	size_t len = nni_aio_count(aio);
	if (nni_msg_alloc(&msg, len) != NNG_OK) {
		// TODO BUMP A NO RECV ALLOC STAT
		goto fail;
	}
	memcpy(nni_msg_body(msg), ep->rx_buf, len);
	nni_pipe_hold(p->npipe);
	nni_mtx_unlock(&ep->mtx);

	nni_mtx_lock(&p->lower_mtx);

	if (nni_lmq_put(&p->rx_mq, msg) != NNG_OK) {
		// TODO: BUMP TXQ FULL STAT
		nng_msg_free(msg);
	}
	dtls_bio_recv_done(p);
	nni_mtx_unlock(&p->lower_mtx);

	// Run the TLS state machine.
	switch (nni_tls_run(&p->tls)) {
	case NNG_OK:
	case NNG_EAGAIN:
		break;
	default:
		nni_pipe_close(p->npipe);
	}
	nni_pipe_rele(p->npipe);

	nni_mtx_lock(&ep->mtx);
	dtls_start_rx(ep);
	nni_mtx_unlock(&ep->mtx);
	return;

fail:
	// start another receive
	dtls_start_rx(ep);

	nni_mtx_unlock(&ep->mtx);
}

static uint16_t
dtls_pipe_peer(void *arg)
{
	dtls_pipe *p = arg;

	return (p->peer);
}

static nng_err
dtls_pipe_get_recvmax(void *arg, void *v, size_t *szp, nni_type t)
{
	dtls_pipe *p  = arg;
	dtls_ep   *ep = p->ep;
	nng_err    rv;
	nni_mtx_lock(&ep->mtx);
	rv = nni_copyout_size(p->recv_max, v, szp, t);
	nni_mtx_unlock(&ep->mtx);
	return (rv);
}

static nni_option dtls_pipe_options[] = {
	{
	    .o_name = NNG_OPT_RECVMAXSZ,
	    .o_get  = dtls_pipe_get_recvmax,
	},
	{
	    .o_name = NULL,
	},
};

static nng_err
dtls_pipe_getopt(
    void *arg, const char *name, void *buf, size_t *szp, nni_type t)
{
	dtls_pipe *p = arg;

	return (nni_getopt(dtls_pipe_options, name, p, buf, szp, t));
}

static nng_err
dtls_pipe_peer_cert(void *arg, nng_tls_cert **certp)
{
	dtls_pipe *p = arg;

	return (nni_tls_peer_cert(&p->tls, certp));
}
static const nng_sockaddr *
dtls_pipe_peer_addr(void *arg)
{
	dtls_pipe *p = arg;
	return (&p->peer_addr);
}

static const nng_sockaddr *
dtls_pipe_self_addr(void *arg)
{
	dtls_pipe *p = arg;
	return (&p->ep->self_sa);
}

static void
dtls_ep_fini(void *arg)
{
	dtls_ep *ep = arg;

	if (ep->tlscfg != NULL) {
		nng_tls_config_free(ep->tlscfg);
	}
	nni_aio_fini(&ep->timeaio);
	nni_aio_fini(&ep->resaio);
	nni_aio_fini(&ep->tx_aio);
	nni_aio_fini(&ep->rx_aio);

	if (ep->udp != NULL) {
		nng_udp_close(ep->udp);
	}
	if (ep->rx_size != 0) {
		nni_free(ep->rx_buf, ep->rx_size);
	}

	nni_msg_free(ep->rx_payload); // safe even if msg is null
	nni_id_map_fini(&ep->pipes);
	nni_mtx_fini(&ep->mtx);
}

static void
dtls_ep_close(void *arg)
{
	dtls_ep   *ep = arg;
	nni_aio   *aio;
	dtls_pipe *p;
	uint64_t   key;
	uint32_t   cursor;

	nni_aio_close(&ep->resaio);
	nni_aio_close(&ep->rx_aio);
	nni_aio_close(&ep->timeaio);

	// leave tx open so we can send disconnects

	nni_mtx_lock(&ep->mtx);
	ep->closed = true;
	while ((aio = nni_list_first(&ep->connaios)) != NULL) {
		nni_aio_list_remove(aio);
		nni_aio_finish_error(aio, NNG_ECONNABORTED);
	}
	cursor = 0;
	key    = 0;
	while (nni_id_visit(&ep->pipes, &key, (void **) &p, &cursor)) {
		nni_pipe_close(p->npipe);
	}
	nni_mtx_unlock(&ep->mtx);
}

static void
dtls_ep_stop(void *arg)
{
	dtls_ep *ep = arg;

	nni_aio_stop(&ep->resaio);
	nni_aio_stop(&ep->rx_aio);
	nni_aio_stop(&ep->timeaio);

	nni_mtx_lock(&ep->mtx);
	ep->fini    = true;
	ep->started = false;
	nni_mtx_unlock(&ep->mtx);
}

// timer handler - sends out additional creqs as needed,
// reaps stale connections, and handles linger.
static void
dtls_timer_cb(void *arg)
{
	dtls_ep   *ep = arg;
	dtls_pipe *p;
	nng_err    rv;

	nni_mtx_lock(&ep->mtx);
	rv = nni_aio_result(&ep->timeaio);
	switch (rv) {
	case NNG_ECLOSED:
	case NNG_ECANCELED:
	case NNG_ESTOPPED:
		nni_mtx_unlock(&ep->mtx);
		return;
	default:
		if (ep->closed) {
			nni_mtx_unlock(&ep->mtx);
			return;
		}
		break;
	}

	uint32_t     cursor  = 0;
	nni_time     now     = nni_clock();
	nng_duration refresh = NNG_DURATION_INFINITE;

	while (nni_id_visit(&ep->pipes, NULL, (void **) &p, &cursor)) {

		if (p->closed) {
			continue;
		}
		NNI_ASSERT(p->refresh > 0);
		if (p->expire > 0 && now > p->expire) {
			char buf[128];
			nng_log_info("NNG-DTLS-INACTIVE",
			    "Pipe peer %s timed out due to inactivity",
			    nng_str_sockaddr(&p->peer_addr, buf, sizeof(buf)));

			nni_stat_inc(&ep->st_peer_inactive, 1);
			nni_pipe_close(p->npipe);
			continue;
		}

		if (p->dialer && now > p->next_refresh) {
			p->send_op      = OPCODE_CREQ;
			p->next_refresh = now + p->refresh;
			dtls_pipe_send_tls(p);
		}
		if (refresh == NNG_DURATION_INFINITE && p->refresh > 0) {
			refresh = p->refresh;
		} else if ((p->refresh > 0) && (p->refresh < refresh)) {
			refresh = p->refresh;
		}
	}
	nni_sleep_aio(refresh, &ep->timeaio);

	nni_mtx_unlock(&ep->mtx);
}

static nng_err
dtls_ep_init(
    dtls_ep *ep, nng_url *url, nni_sock *sock, nni_dialer *d, nni_listener *l)
{
	nni_mtx_init(&ep->mtx);
	nni_id_map_init(&ep->pipes, 1, 0xFFFFFFFF, true);
	NNI_LIST_INIT(&ep->connpipes, dtls_pipe, node);
	nni_aio_list_init(&ep->connaios);

	nni_aio_init(&ep->rx_aio, dtls_rx_cb, ep);
	nni_aio_init(&ep->timeaio, dtls_timer_cb, ep);
	nni_aio_init(&ep->resaio, dtls_resolv_cb, ep);

	if (strcmp(url->u_scheme, "dtls") == 0) {
		ep->af = NNG_AF_UNSPEC;
	} else if (strcmp(url->u_scheme, "dtls4") == 0) {
		ep->af = NNG_AF_INET;
	} else if (strcmp(url->u_scheme, "dtls6") == 0) {
		ep->af = NNG_AF_INET6;
	} else {
		return (NNG_EADDRINVAL);
	}

	ep->self_sa.s_family = ep->af;
	ep->proto            = nni_sock_proto_id(sock);
	ep->peer             = nni_sock_peer_id(sock);
	ep->url              = url;
	ep->refresh          = NNG_DTLS_REFRESH; // one minute by default
	ep->rcvmax           = NNG_DTLS_RECVMAX;

	// receive buffer plus some extra for UDP and TLS headers
	if ((ep->rx_buf = nni_alloc(DTLS_MAX_RECORD)) == NULL) {
		return (NNG_ENOMEM);
	}
	ep->rx_size = DTLS_MAX_RECORD;

	NNI_STAT_LOCK(rcv_max_info, "rcv_max", "maximum receive size",
	    NNG_STAT_LEVEL, NNG_UNIT_BYTES);
	NNI_STAT_LOCK(rcv_nomatch_info, "rcv_nomatch",
	    "messages without a matching connection", NNG_STAT_COUNTER,
	    NNG_UNIT_MESSAGES);
	NNI_STAT_LOCK(rcv_toobig_info, "rcv_toobig",
	    "received messages rejected because too big", NNG_STAT_COUNTER,
	    NNG_UNIT_MESSAGES);
	NNI_STAT_LOCK(rcv_nobuf_info, "rcv_nobuf",
	    "received messages dropped no buffer", NNG_STAT_COUNTER,
	    NNG_UNIT_MESSAGES);
	NNI_STAT_LOCK(snd_toobig_info, "snd_toobig",
	    "sent messages rejected because too big", NNG_STAT_COUNTER,
	    NNG_UNIT_MESSAGES);
	NNI_STAT_LOCK(snd_nobuf_info, "snd_nobuf",
	    "sent messages dropped no buffer", NNG_STAT_COUNTER,
	    NNG_UNIT_MESSAGES);
	NNI_STAT_LOCK(peer_inactive_info, "peer_inactive",
	    "connections closed due to inactive peer", NNG_STAT_COUNTER,
	    NNG_UNIT_EVENTS);

	nni_stat_init_lock(&ep->st_rcv_max, &rcv_max_info, &ep->mtx);
	nni_stat_init_lock(&ep->st_rcv_toobig, &rcv_toobig_info, &ep->mtx);
	nni_stat_init_lock(&ep->st_rcv_nomatch, &rcv_nomatch_info, &ep->mtx);
	nni_stat_init_lock(&ep->st_rcv_nobuf, &rcv_nobuf_info, &ep->mtx);
	nni_stat_init_lock(&ep->st_snd_toobig, &snd_toobig_info, &ep->mtx);
	nni_stat_init_lock(&ep->st_snd_nobuf, &snd_nobuf_info, &ep->mtx);
	nni_stat_init_lock(
	    &ep->st_peer_inactive, &peer_inactive_info, &ep->mtx);

	if (l) {
		NNI_ASSERT(d == NULL);
		nni_listener_add_stat(l, &ep->st_rcv_max);

		nni_listener_add_stat(l, &ep->st_rcv_toobig);
		nni_listener_add_stat(l, &ep->st_rcv_nomatch);
		nni_listener_add_stat(l, &ep->st_rcv_nobuf);
		nni_listener_add_stat(l, &ep->st_snd_toobig);
		nni_listener_add_stat(l, &ep->st_snd_nobuf);
	}
	if (d) {
		NNI_ASSERT(l == NULL);
		nni_dialer_add_stat(d, &ep->st_rcv_max);
		nni_dialer_add_stat(d, &ep->st_rcv_toobig);
		nni_dialer_add_stat(d, &ep->st_rcv_nomatch);
		nni_dialer_add_stat(d, &ep->st_rcv_nobuf);
		nni_dialer_add_stat(d, &ep->st_snd_toobig);
		nni_dialer_add_stat(d, &ep->st_snd_nobuf);
	}

	// schedule our timer callback - forever for now
	// adjusted automatically as we add pipes or other
	// actions which require earlier wakeup.
	nni_sleep_aio(NNG_DURATION_INFINITE, &ep->timeaio);
	// nni_sleep_aio(100, &ep->timeaio);

	return (NNG_OK);
}

static nng_err
dtls_check_url(nng_url *url, bool listen)
{
	// Check for invalid URL components.
	if ((strlen(url->u_path) != 0) && (strcmp(url->u_path, "/") != 0)) {
		return (NNG_EADDRINVAL);
	}
	if ((url->u_fragment != NULL) || (url->u_userinfo != NULL) ||
	    (url->u_query != NULL)) {
		return (NNG_EADDRINVAL);
	}
	if (!listen) {
		if ((strlen(url->u_hostname) == 0) || (url->u_port == 0)) {
			return (NNG_EADDRINVAL);
		}
	}
	return (NNG_OK);
}

static nng_err
dtls_dialer_init(void *arg, nng_url *url, nni_dialer *ndialer)
{
	dtls_ep  *ep = arg;
	nng_err   rv;
	nni_sock *sock = nni_dialer_sock(ndialer);

	if ((rv = dtls_check_url(url, false)) != NNG_OK) {
		return (rv);
	}

	ep->ndialer = ndialer;
	if ((rv = dtls_ep_init(ep, url, sock, ndialer, NULL)) != NNG_OK) {
		return (rv);
	}

	return (NNG_OK);
}

static nng_err
dtls_listener_init(void *arg, nng_url *url, nni_listener *nlistener)
{
	dtls_ep  *ep = arg;
	nng_err   rv;
	nni_sock *sock = nni_listener_sock(nlistener);

	ep->nlistener = nlistener;
	if ((rv = dtls_ep_init(ep, url, sock, NULL, nlistener)) != NNG_OK) {
		return (rv);
	}
	// Check for invalid URL components.
	if (((rv = dtls_check_url(url, true)) != NNG_OK) ||
	    ((rv = nni_url_to_address(&ep->self_sa, url)) != NNG_OK)) {
		return (rv);
	}

	return (NNG_OK);
}

static void
dtls_ep_cancel(nni_aio *aio, void *arg, nng_err rv)
{
	dtls_ep *ep = arg;
	nni_mtx_lock(&ep->mtx);
	if (nni_aio_list_active(aio)) {
		nni_aio_list_remove(aio);
		nni_aio_finish_error(aio, rv);
		nni_aio_abort(&ep->resaio, rv);
	}
	nni_mtx_unlock(&ep->mtx);
}

static void
dtls_resolv_cb(void *arg)
{
	dtls_ep   *ep = arg;
	dtls_pipe *p;
	nni_aio   *aio;
	nng_err    rv;

	nni_mtx_lock(&ep->mtx);
	if ((aio = nni_list_first(&ep->connaios)) == NULL) {
		nni_mtx_unlock(&ep->mtx);
		return;
	}
	if (ep->closed) {
		nni_aio_list_remove(aio);
		nni_aio_finish_error(aio, NNG_ECLOSED);
		nni_mtx_unlock(&ep->mtx);
		return;
	}
	if ((rv = nni_aio_result(&ep->resaio)) != NNG_OK) {
		nni_aio_list_remove(aio);
		nni_aio_finish_error(aio, rv);
		nni_mtx_unlock(&ep->mtx);
		nng_log_warn("NNG-RESOLV", "Failed resolving IP address: %s",
		    nng_strerror(rv));
		return;
	}

	// Choose the right port to bind to. The family must match.
	if (ep->self_sa.s_family == NNG_AF_UNSPEC) {
		ep->self_sa.s_family = ep->peer_sa.s_family;
	}

	// Close the socket if it was open, because we need to
	// start with a fresh port.
	if (ep->udp != NULL) {
		nng_udp_close(ep->udp);
		ep->udp = NULL;
	}

	if ((rv = nng_udp_open(&ep->udp, &ep->self_sa)) != NNG_OK) {
		nni_aio_list_remove(aio);
		nni_aio_finish_error(aio, rv);
		nni_mtx_unlock(&ep->mtx);
		return;
	}

	if ((rv = dtls_pipe_alloc(ep, &p, &ep->peer_sa)) != NNG_OK) {
		nni_aio_list_remove(aio);
		nni_aio_finish_error(aio, rv);
		nni_mtx_unlock(&ep->mtx);
		return;
	}
	dtls_ep_start(ep);

	// Send out the connection request.  We don't complete
	// the user aio until we confirm a connection, so that
	// we can supply details like maximum receive message size
	// and the protocol the peer is using.
	p->send_op = OPCODE_CREQ;
	dtls_pipe_send_tls(p);
	nni_mtx_unlock(&ep->mtx);
}

static void
dtls_ep_connect(void *arg, nni_aio *aio)
{
	dtls_ep *ep = arg;

	nni_mtx_lock(&ep->mtx);
	if (!nni_aio_start(aio, dtls_ep_cancel, ep)) {
		nni_mtx_unlock(&ep->mtx);
		return;
	}
	if (ep->closed) {
		nni_aio_finish_error(aio, NNG_ECLOSED);
		nni_mtx_unlock(&ep->mtx);
		return;
	}
	if (!nni_list_empty(&ep->connaios)) {
		nni_aio_finish_error(aio, NNG_EBUSY);
		nni_mtx_unlock(&ep->mtx);
		return;
	}
	ep->dialer = true;
	NNI_ASSERT(nni_list_empty(&ep->connaios));
	nni_list_append(&ep->connaios, aio);

	if (ep->started) {
		nni_mtx_unlock(&ep->mtx);
		return;
	}

	// lookup the IP address
	memset(&ep->resolv, 0, sizeof(ep->resolv));
	ep->resolv.ri_family  = ep->af;
	ep->resolv.ri_host    = ep->url->u_hostname;
	ep->resolv.ri_port    = ep->url->u_port;
	ep->resolv.ri_passive = false;
	ep->resolv.ri_sa      = &ep->peer_sa;
	nni_aio_set_timeout(&ep->resaio, NNI_SECOND * 5);
	nni_resolv(&ep->resolv, &ep->resaio);

	// wake up for retries
	nni_aio_abort(&ep->timeaio, NNG_EINTR);

	nni_mtx_unlock(&ep->mtx);
}

static nng_err
dtls_ep_get_port(void *arg, void *buf, size_t *szp, nni_type t)
{
	dtls_ep     *ep = arg;
	nng_sockaddr sa;
	int          port;
	uint8_t     *paddr;

	nni_mtx_lock(&ep->mtx);
	if (ep->udp != NULL) {
		(void) nng_udp_sockname(ep->udp, &sa);
	} else {
		sa = ep->self_sa;
	}
	switch (sa.s_family) {
	case NNG_AF_INET:
		paddr = (void *) &sa.s_in.sa_port;
		break;

	case NNG_AF_INET6:
		paddr = (void *) &sa.s_in6.sa_port;
		break;

	default:
		paddr = NULL;
		break;
	}
	nni_mtx_unlock(&ep->mtx);

	if (paddr == NULL) {
		return (NNG_ESTATE);
	}

	NNI_GET16(paddr, port);
	return (nni_copyout_int(port, buf, szp, t));
}

static nng_err
dtls_ep_get_recvmaxsz(void *arg, void *v, size_t *szp, nni_opt_type t)
{
	dtls_ep *ep = arg;
	nng_err  rv;

	nni_mtx_lock(&ep->mtx);
	rv = nni_copyout_size(ep->rcvmax, v, szp, t);
	nni_mtx_unlock(&ep->mtx);
	return (rv);
}

static nng_err
dtls_ep_set_recvmaxsz(void *arg, const void *v, size_t sz, nni_opt_type t)
{
	dtls_ep *ep = arg;
	size_t   val;
	nng_err  rv;
	if ((rv = nni_copyin_size(&val, v, sz, 0, NNG_DTLS_RECVMAX, t)) == 0) {
		if ((val == 0) || (val > NNG_DTLS_RECVMAX)) {
			val = NNG_DTLS_RECVMAX;
		}
		nni_mtx_lock(&ep->mtx);
		if (ep->started) {
			nni_mtx_unlock(&ep->mtx);
			return (NNG_EBUSY);
		}
		ep->rcvmax = (uint16_t) val;
		nni_stat_set_value(&ep->st_rcv_max, val);
		nni_mtx_unlock(&ep->mtx);
	}
	return (rv);
}

static nng_err
dtls_ep_set_tls(void *arg, nng_tls_config *cfg)
{
	dtls_ep *ep = arg;
	nni_mtx_lock(&ep->mtx);
	if (ep->started) {
		nni_mtx_unlock(&ep->mtx);
		return (NNG_EBUSY);
	}
	nng_tls_config *old = ep->tlscfg;
	ep->tlscfg          = cfg;
	nng_tls_config_hold(cfg);
	if (old != NULL) {
		nng_tls_config_free(old);
	}
	nni_mtx_unlock(&ep->mtx);
	return (NNG_OK);
}

static nng_err
dtls_ep_get_tls(void *arg, nng_tls_config **cfgp)
{
	dtls_ep *ep = arg;
	nni_mtx_lock(&ep->mtx);
	*cfgp = ep->tlscfg;
	nni_mtx_unlock(&ep->mtx);
	return (NNG_OK);
}

// this just looks for pipes waiting for an aio, and aios waiting for
// a connection, and matches them together.
static void
dtls_ep_match(dtls_ep *ep)
{
	nng_aio   *aio = nni_list_first(&ep->connaios);
	dtls_pipe *p   = nni_list_first(&ep->connpipes);

	if ((aio == NULL) || (p == NULL)) {
		return;
	}

	nni_aio_list_remove(aio);
	nni_list_remove(&ep->connpipes, p);
	nni_aio_set_output(aio, 0, p->npipe);
	nni_aio_finish(aio, 0, 0);
}

static void
dtls_ep_start(dtls_ep *ep)
{
	ep->started = true;
	dtls_start_rx(ep);
}

static nng_err
dtls_ep_bind(void *arg, nng_url *url)
{
	dtls_ep *ep = arg;
	nng_err  rv;

	nni_mtx_lock(&ep->mtx);
	if (ep->started) {
		nni_mtx_unlock(&ep->mtx);
		return (NNG_EBUSY);
	}

	rv = nng_udp_open(&ep->udp, &ep->self_sa);
	if (rv != NNG_OK) {
		nni_mtx_unlock(&ep->mtx);
		return (rv);
	}
	nng_sockaddr sa;
	nng_udp_sockname(ep->udp, &sa);
	url->u_port = nng_sockaddr_port(&sa);
	dtls_ep_start(ep);
	nni_mtx_unlock(&ep->mtx);

	return (rv);
}

static void
dtls_ep_accept(void *arg, nni_aio *aio)
{
	dtls_ep *ep = arg;

	nni_aio_reset(aio);
	nni_mtx_lock(&ep->mtx);
	if (ep->closed) {
		nni_aio_finish_error(aio, NNG_ECLOSED);
		nni_mtx_unlock(&ep->mtx);
		return;
	}
	if (!nni_aio_start(aio, dtls_ep_cancel, ep)) {
		nni_mtx_unlock(&ep->mtx);
		return;
	}
	nni_aio_list_append(&ep->connaios, aio);
	dtls_ep_match(ep);
	nni_mtx_unlock(&ep->mtx);
}

static nni_sp_pipe_ops dtls_pipe_ops = {
	.p_size      = dtls_pipe_size,
	.p_init      = dtls_pipe_init,
	.p_fini      = dtls_pipe_fini,
	.p_stop      = dtls_pipe_stop,
	.p_send      = dtls_pipe_send,
	.p_recv      = dtls_pipe_recv,
	.p_close     = dtls_pipe_close,
	.p_peer      = dtls_pipe_peer,
	.p_getopt    = dtls_pipe_getopt,
	.p_peer_cert = dtls_pipe_peer_cert,
	.p_peer_addr = dtls_pipe_peer_addr,
	.p_self_addr = dtls_pipe_self_addr,
};

static const nni_option dtls_ep_opts[] = {
	{
	    .o_name = NNG_OPT_RECVMAXSZ,
	    .o_get  = dtls_ep_get_recvmaxsz,
	    .o_set  = dtls_ep_set_recvmaxsz,
	},
	{
	    .o_name = NNG_OPT_BOUND_PORT,
	    .o_get  = dtls_ep_get_port,
	},
	// terminate list
	{
	    .o_name = NULL,
	},
};

static nng_err
dtls_dialer_getopt(
    void *arg, const char *name, void *buf, size_t *szp, nni_type t)
{
	dtls_ep *ep = arg;

	return (nni_getopt(dtls_ep_opts, name, ep, buf, szp, t));
}

static nng_err
dtls_dialer_setopt(
    void *arg, const char *name, const void *buf, size_t sz, nni_type t)
{
	dtls_ep *ep = arg;

	return (nni_setopt(dtls_ep_opts, name, ep, buf, sz, t));
}

static nng_err
dtls_listener_getopt(
    void *arg, const char *name, void *buf, size_t *szp, nni_type t)
{
	dtls_ep *ep = arg;

	return (nni_getopt(dtls_ep_opts, name, ep, buf, szp, t));
}

static nng_err
dtls_listener_setopt(
    void *arg, const char *name, const void *buf, size_t sz, nni_type t)
{
	dtls_ep *ep = arg;

	return (nni_setopt(dtls_ep_opts, name, ep, buf, sz, t));
}

static nni_sp_dialer_ops dtls_dialer_ops = {
	.d_size    = sizeof(dtls_ep),
	.d_init    = dtls_dialer_init,
	.d_fini    = dtls_ep_fini,
	.d_connect = dtls_ep_connect,
	.d_close   = dtls_ep_close,
	.d_stop    = dtls_ep_stop,
	.d_set_tls = dtls_ep_set_tls,
	.d_get_tls = dtls_ep_get_tls,
	.d_getopt  = dtls_dialer_getopt,
	.d_setopt  = dtls_dialer_setopt,
};

static nni_sp_listener_ops dtls_listener_ops = {
	.l_size    = sizeof(dtls_ep),
	.l_init    = dtls_listener_init,
	.l_fini    = dtls_ep_fini,
	.l_bind    = dtls_ep_bind,
	.l_accept  = dtls_ep_accept,
	.l_close   = dtls_ep_close,
	.l_stop    = dtls_ep_stop,
	.l_set_tls = dtls_ep_set_tls,
	.l_get_tls = dtls_ep_get_tls,
	.l_getopt  = dtls_listener_getopt,
	.l_setopt  = dtls_listener_setopt,
};

static nni_sp_tran dtls_tran = {
	.tran_scheme   = "dtls",
	.tran_dialer   = &dtls_dialer_ops,
	.tran_listener = &dtls_listener_ops,
	.tran_pipe     = &dtls_pipe_ops,
	.tran_init     = dtls_tran_init,
	.tran_fini     = dtls_tran_fini,
};

static nni_sp_tran dtls4_tran = {
	.tran_scheme   = "dtls4",
	.tran_dialer   = &dtls_dialer_ops,
	.tran_listener = &dtls_listener_ops,
	.tran_pipe     = &dtls_pipe_ops,
	.tran_init     = dtls_tran_init,
	.tran_fini     = dtls_tran_fini,
};

#ifdef NNG_ENABLE_IPV6
static nni_sp_tran dtls6_tran = {
	.tran_scheme   = "dtls6",
	.tran_dialer   = &dtls_dialer_ops,
	.tran_listener = &dtls_listener_ops,
	.tran_pipe     = &dtls_pipe_ops,
	.tran_init     = dtls_tran_init,
	.tran_fini     = dtls_tran_fini,
};
#endif

void
nni_sp_dtls_register(void)
{
	nni_sp_tran_register(&dtls_tran);
	nni_sp_tran_register(&dtls4_tran);
#ifdef NNG_ENABLE_IPV6
	nni_sp_tran_register(&dtls6_tran);
#endif
}
