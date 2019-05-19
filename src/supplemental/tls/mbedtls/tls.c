//
// Copyright 2019 Staysail Systems, Inc. <info@staysail.tech>
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
#include <stdlib.h>
#include <string.h>

#include "mbedtls/version.h" // Must be first in order to pick up version

#include "mbedtls/error.h"

// mbedTLS renamed this header for 2.4.0.
#if MBEDTLS_VERSION_MAJOR > 2 || MBEDTLS_VERSION_MINOR >= 4
#include "mbedtls/net_sockets.h"
#else
#include "mbedtls/net.h"
#endif

#include "mbedtls/ssl.h"

#include "core/nng_impl.h"
#include "core/tcp.h"
#include "supplemental/tls/tls_api.h"

// Implementation note.  This implementation buffers data between the TLS
// encryption layer (mbedTLS) and the underlying TCP socket.  As a result,
// there may be some additional latency caused by buffer draining and
// refilling.  In the future we might want to investigate some kind of
// double buffer policy to allow data to flow without entering a true
// empty state.

// NNG_TLS_MAX_SEND_SIZE limits the amount of data we will buffer for sending,
// exerting backpressure if this size is exceeded.  The 16K is aligned to the
// maximum TLS record size.
#ifndef NNG_TLS_MAX_SEND_SIZE
#define NNG_TLS_MAX_SEND_SIZE 16384
#endif

// NNG_TLS_MAX_RECV_SIZE limits the amount of data we will receive in a single
// operation.  As we have to buffer data, this drives the size of our
// intermediary buffer.  The 16K is aligned to the maximum TLS record size.
#ifndef NNG_TLX_MAX_RECV_SIZE
#define NNG_TLS_MAX_RECV_SIZE 16384
#endif

typedef struct nni_tls_certkey {
	mbedtls_x509_crt   crt;
	mbedtls_pk_context key;
	nni_list_node      node;
} nni_tls_certkey;

typedef struct {
	nni_tls_common      com;
	nng_stream *        tcp;
	mbedtls_ssl_context ctx;
	nng_tls_config *    cfg; // kept so we can release it
	nni_mtx             lk;
	nni_aio *           tcp_send;
	nni_aio *           tcp_recv;
	bool                sending;
	bool                recving;
	bool                closed;
	bool                hsdone;
	bool                tls_closed; // upper TLS layer closed
	bool                tcp_closed; // underlying TCP buffer closed
	uint8_t *           sendbuf;    // send buffer
	size_t              sendlen;    // amount of data in send buffer
	size_t              sendoff;    // offset of start of send data
	uint8_t *           recvbuf;    // recv buffer
	size_t              recvlen;    // amount of data in recv buffer
	size_t              recvoff;    // offset of start of recv data
	nni_list            sends;      // upper side sends
	nni_list            recvs;      // upper recv aios
	nni_aio *           handshake;  // handshake aio (upper)
} tls;

struct nng_tls_config {
	mbedtls_ssl_config cfg_ctx;
	nni_mtx            lk;
	bool               active;
	char *             server_name;
#ifdef NNG_TLS_USE_CTR_DRBG
	mbedtls_ctr_drbg_context rng_ctx;
	nni_mtx                  rng_lk;
#endif
	mbedtls_x509_crt ca_certs;
	mbedtls_x509_crl crl;

	nni_atomic_u64 refcnt;

	nni_list certkeys;
};

static void tls_send_cb(void *);
static void tls_recv_cb(void *);

static void tls_do_send(tls *);
static void tls_do_recv(tls *);
static void tls_do_handshake(tls *);

static int tls_net_send(void *, const unsigned char *, size_t);
static int tls_net_recv(void *, unsigned char *, size_t);

static void
tls_dbg(void *ctx, int level, const char *file, int line, const char *s)
{
	char buf[128];
	NNI_ARG_UNUSED(ctx);
	NNI_ARG_UNUSED(level);
	snprintf(buf, sizeof(buf), "%s:%04d: %s", file, line, s);
	nni_plat_println(buf);
}

static int
tls_get_entropy(void *arg, unsigned char *buf, size_t len)
{
	NNI_ARG_UNUSED(arg);
	while (len) {
		uint32_t x = nni_random();
		size_t   n;

		n = len < sizeof(x) ? len : sizeof(x);
		memcpy(buf, &x, n);
		len -= n;
		buf += n;
	}
	return (0);
}

static int
tls_random(void *arg, unsigned char *buf, size_t sz)
{
#ifdef NNG_TLS_USE_CTR_DRBG
	int             rv;
	nng_tls_config *cfg = arg;
	NNI_ARG_UNUSED(arg);

	nni_mtx_lock(&cfg->rng_lk);
	rv = mbedtls_ctr_drbg_random(&cfg->rng_ctx, buf, sz);
	nni_mtx_unlock(&cfg->rng_lk);
	return (rv);
#else
	return (tls_get_entropy(arg, buf, sz));
#endif
}

void
nni_tls_config_fini(nng_tls_config *cfg)
{
	nni_tls_certkey *ck;

	if (cfg != NULL) {
		if (nni_atomic_dec64_nv(&cfg->refcnt) != 0) {
			return;
		}

		mbedtls_ssl_config_free(&cfg->cfg_ctx);
#ifdef NNG_TLS_USE_CTR_DRBG
		mbedtls_ctr_drbg_free(&cfg->rng_ctx);
#endif
		mbedtls_x509_crt_free(&cfg->ca_certs);
		mbedtls_x509_crl_free(&cfg->crl);
		if (cfg->server_name) {
			nni_strfree(cfg->server_name);
		}
		while ((ck = nni_list_first(&cfg->certkeys))) {
			nni_list_remove(&cfg->certkeys, ck);
			mbedtls_x509_crt_free(&ck->crt);
			mbedtls_pk_free(&ck->key);

			NNI_FREE_STRUCT(ck);
		}
		nni_mtx_fini(&cfg->lk);
		NNI_FREE_STRUCT(cfg);
	}
}

int
nni_tls_config_init(nng_tls_config **cpp, enum nng_tls_mode mode)
{
	nng_tls_config *cfg;
	int             rv;
	int             sslmode;
	int             authmode;

	if ((cfg = NNI_ALLOC_STRUCT(cfg)) == NULL) {
		return (NNG_ENOMEM);
	}
	nni_atomic_init64(&cfg->refcnt);
	nni_atomic_inc64(&cfg->refcnt);
	nni_mtx_init(&cfg->lk);
	if (mode == NNG_TLS_MODE_SERVER) {
		sslmode  = MBEDTLS_SSL_IS_SERVER;
		authmode = MBEDTLS_SSL_VERIFY_NONE;
	} else {
		sslmode  = MBEDTLS_SSL_IS_CLIENT;
		authmode = MBEDTLS_SSL_VERIFY_REQUIRED;
	}

	NNI_LIST_INIT(&cfg->certkeys, nni_tls_certkey, node);
	mbedtls_ssl_config_init(&cfg->cfg_ctx);
	mbedtls_x509_crt_init(&cfg->ca_certs);
	mbedtls_x509_crl_init(&cfg->crl);

	rv = mbedtls_ssl_config_defaults(&cfg->cfg_ctx, sslmode,
	    MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
	if (rv != 0) {
		nni_tls_config_fini(cfg);
		return (rv);
	}

	mbedtls_ssl_conf_authmode(&cfg->cfg_ctx, authmode);

	// We *require* TLS v1.2 or newer, which is also known as SSL v3.3.
	mbedtls_ssl_conf_min_version(&cfg->cfg_ctx,
	    MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3);

#ifdef NNG_TLS_USE_CTR_DRBG
	mbedtls_ctr_drbg_init(&cfg->rng_ctx);
	rv = mbedtls_ctr_drbg_seed(
	    &cfg->rng_ctx, tls_get_entropy, NULL, NULL, 0);
	if (rv != 0) {
		nni_tls_config_fini(cfg);
		return (rv);
	}
#endif
	mbedtls_ssl_conf_rng(&cfg->cfg_ctx, tls_random, cfg);

	mbedtls_ssl_conf_dbg(&cfg->cfg_ctx, tls_dbg, cfg);

	*cpp = cfg;
	return (0);
}

void
nni_tls_config_hold(nng_tls_config *cfg)
{
	nni_atomic_inc64(&cfg->refcnt);
}

// tls_mkerr converts an mbed error to an NNG error.  In all cases
// we just encode with NNG_ETRANERR.
static struct {
	int tls;
	int nng;
} tls_errs[] = {
	{ MBEDTLS_ERR_SSL_NO_CLIENT_CERTIFICATE, NNG_EPEERAUTH },
	{ MBEDTLS_ERR_SSL_CA_CHAIN_REQUIRED, NNG_EPEERAUTH },
	{ MBEDTLS_ERR_SSL_PEER_VERIFY_FAILED, NNG_EPEERAUTH },
	{ MBEDTLS_ERR_SSL_NO_USABLE_CIPHERSUITE, NNG_EPEERAUTH },
	{ MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY, NNG_ECONNREFUSED },
	{ MBEDTLS_ERR_SSL_ALLOC_FAILED, NNG_ENOMEM },
	{ MBEDTLS_ERR_SSL_TIMEOUT, NNG_ETIMEDOUT },
	{ MBEDTLS_ERR_SSL_CONN_EOF, NNG_ECLOSED },
	// terminator
	{ 0, 0 },
};

static int
tls_mkerr(int err)
{
	for (int i = 0; tls_errs[i].tls != 0; i++) {
		if (tls_errs[i].tls == err) {
			return (tls_errs[i].nng);
		}
	}
	return (NNG_ECRYPTO);
}

// The common code should call this only after it has released
// it's upper layer stuff.
static void
tls_free(void *arg)
{
	tls *tls = arg;

	// Shut it all down first.
	if (tls != NULL) {
		if (tls->tcp != NULL) {
			nng_stream_close(tls->tcp);
		}
		nni_aio_stop(tls->tcp_send);
		nni_aio_stop(tls->tcp_recv);
		nni_aio_fini(tls->com.aio);

		// And finalize / free everything.
		nng_stream_free(tls->tcp);
		nni_aio_fini(tls->tcp_send);
		nni_aio_fini(tls->tcp_recv);
		mbedtls_ssl_free(&tls->ctx);
		nng_tls_config_free(tls->com.cfg);

		if (tls->recvbuf != NULL) {
			nni_free(tls->recvbuf, NNG_TLS_MAX_RECV_SIZE);
		}
		if (tls->sendbuf != NULL) {
			nni_free(tls->sendbuf, NNG_TLS_MAX_RECV_SIZE);
		}
		nni_mtx_fini(&tls->lk);
		memset(tls, 0xff, sizeof(*tls));
		NNI_FREE_STRUCT(tls);
	}
}

int
nni_tls_start(nng_stream *arg, nng_stream *tcp)
{
	tls *           tp  = (void *) arg;
	nng_tls_config *cfg = tp->com.cfg;
	int             rv;

	if ((tp->recvbuf = nni_zalloc(NNG_TLS_MAX_RECV_SIZE)) == NULL) {
		return (NNG_ENOMEM);
	}
	if ((tp->sendbuf = nni_zalloc(NNG_TLS_MAX_SEND_SIZE)) == NULL) {
		return (NNG_ENOMEM);
	}

	nni_mtx_lock(&cfg->lk);
	// No more changes allowed to config.
	cfg->active = true;
	nni_mtx_unlock(&cfg->lk);

	mbedtls_ssl_init(&tp->ctx);
	mbedtls_ssl_set_bio(&tp->ctx, tp, tls_net_send, tls_net_recv, NULL);

	if ((rv = mbedtls_ssl_setup(&tp->ctx, &cfg->cfg_ctx)) != 0) {
		return (tls_mkerr(rv));
	}

	if (cfg->server_name) {
		mbedtls_ssl_set_hostname(&tp->ctx, cfg->server_name);
	}

	tp->tcp = tcp;

	if (((rv = nni_aio_init(&tp->tcp_send, tls_send_cb, tp)) != 0) ||
	    ((rv = nni_aio_init(&tp->tcp_recv, tls_recv_cb, tp)) != 0)) {
		return (rv);
	}

	nni_mtx_lock(&tp->lk);
	// Kick off a handshake operation.
	tls_do_handshake(tp);
	nni_mtx_unlock(&tp->lk);

	return (0);
}

static void
tls_cancel(nni_aio *aio, void *arg, int rv)
{
	tls *tp = arg;
	nni_mtx_lock(&tp->lk);
	if (nni_aio_list_active(aio)) {
		nni_aio_list_remove(aio);
		nni_aio_finish_error(aio, rv);
	}
	nni_mtx_unlock(&tp->lk);
}

// tls_send_cb is called when the underlying TCP send completes.
static void
tls_send_cb(void *ctx)
{
	tls *    tp  = ctx;
	nni_aio *aio = tp->tcp_send;

	nni_mtx_lock(&tp->lk);
	if (nni_aio_result(aio) != 0) {
		nng_stream_close(tp->tcp);
		tp->tcp_closed = true;
	} else {
		size_t n = nni_aio_count(aio);
		NNI_ASSERT(tp->sendlen >= n);
		tp->sendlen -= n;
		if (tp->sendlen) {
			nni_iov iov;
			tp->sendoff += n;
			iov.iov_buf = tp->sendbuf + tp->sendoff;
			iov.iov_len = tp->sendlen;
			nni_aio_set_iov(aio, 1, &iov);
			nni_aio_set_timeout(aio, NNG_DURATION_INFINITE);
			nng_stream_send(tp->tcp, aio);
			nni_mtx_unlock(&tp->lk);
			return;
		}
		tp->sendoff = 0;
		tp->sending = false;
	}

	tls_do_handshake(tp);
	if (tp->hsdone) {
		tls_do_send(tp);
		tls_do_recv(tp);
	}
	nni_mtx_unlock(&tp->lk);
}

static void
tls_recv_start(tls *tp)
{
	nni_aio *aio;
	nni_iov  iov;

	if (tp->recving || tp->tcp_closed) {
		return;
	}
	// If we already have data, wait for that to be consumed before
	// doing another read.
	if (tp->recvlen != 0) {
		return;
	}

	tp->recving = 1;
	tp->recvoff = 0;
	aio         = tp->tcp_recv;
	iov.iov_buf = tp->recvbuf;
	iov.iov_len = NNG_TLS_MAX_RECV_SIZE;
	nni_aio_set_iov(aio, 1, &iov);
	nni_aio_set_timeout(tp->tcp_recv, NNG_DURATION_INFINITE);
	nng_stream_recv(tp->tcp, aio);
}

static void
tls_recv_cb(void *ctx)
{
	tls *    tp  = ctx;
	nni_aio *aio = tp->tcp_recv;

	nni_mtx_lock(&tp->lk);
	tp->recving = false;
	if (nni_aio_result(aio) != 0) {
		// Close the underlying TCP channel, but permit data we
		// already received to continue to be received.
		nng_stream_close(tp->tcp);
		tp->tcp_closed = true;
	} else {
		NNI_ASSERT(tp->recvlen == 0);
		NNI_ASSERT(tp->recvoff == 0);
		tp->recvlen = nni_aio_count(aio);
	}

	// If we were closed (above), the upper layer will detect and
	// react properly.  Otherwise the upper layer will consume
	// data.
	tls_do_handshake(tp);
	if (tp->hsdone) {
		tls_do_recv(tp);
		tls_do_send(tp);
	}

	nni_mtx_unlock(&tp->lk);
}

// This handles the bottom half send (i.e. sending over TCP).
// We always accept a chunk of data, to a limit, if the bottom
// sender is not busy.  Then we handle that in the background.
// If the sender *is* busy, we return MBEDTLS_ERR_SSL_WANT_WRITE.
// The chunk size we accept is 64k at a time, which prevents
// ridiculous over queueing.  This is always called with the pipe
// lock held, and never blocks.
static int
tls_net_send(void *ctx, const unsigned char *buf, size_t len)
{
	tls *   tp = ctx;
	nni_iov iov;

	if (len > NNG_TLS_MAX_SEND_SIZE) {
		len = NNG_TLS_MAX_SEND_SIZE;
	}

	// We should already be running with the pipe lock held,
	// as we are running in that context.

	if (tp->sending) {
		return (MBEDTLS_ERR_SSL_WANT_WRITE);
	}
	if (tp->tcp_closed) {
		return (MBEDTLS_ERR_NET_SEND_FAILED);
	}

	tp->sending = 1;
	tp->sendlen = len;
	tp->sendoff = 0;
	memcpy(tp->sendbuf, buf, len);
	iov.iov_buf = tp->sendbuf;
	iov.iov_len = len;
	nni_aio_set_iov(tp->tcp_send, 1, &iov);
	nni_aio_set_timeout(tp->tcp_send, NNG_DURATION_INFINITE);
	nng_stream_send(tp->tcp, tp->tcp_send);
	return (len);
}

static int
tls_net_recv(void *ctx, unsigned char *buf, size_t len)
{
	tls *tp = ctx;

	// We should already be running with the pipe lock held,
	// as we are running in that context.

	if (tp->recvlen == 0) {
		if (tp->tcp_closed) {
			// The underlying TCP transport has closed, and we
			// have no more data in our receive buffer.
			return (MBEDTLS_ERR_NET_RECV_FAILED);
		}
		len = MBEDTLS_ERR_SSL_WANT_READ;
	} else {
		if (len > tp->recvlen) {
			len = tp->recvlen;
		}
		memcpy(buf, tp->recvbuf + tp->recvoff, len);
		tp->recvoff += len;
		tp->recvlen -= len;
	}

	tls_recv_start(tp);
	return ((int) len);
}

static void
tls_send(void *arg, nni_aio *aio)
{
	int  rv;
	tls *tp = arg;

	if (nni_aio_begin(aio) != 0) {
		return;
	}
	nni_mtx_lock(&tp->lk);
	if (tp->tls_closed) {
		nni_mtx_unlock(&tp->lk);
		nni_aio_finish_error(aio, NNG_ECLOSED);
		return;
	}
	if ((rv = nni_aio_schedule(aio, tls_cancel, tp)) != 0) {
		nni_mtx_unlock(&tp->lk);
		nni_aio_finish_error(aio, rv);
		return;
	}
	nni_list_append(&tp->sends, aio);
	tls_do_send(tp);
	nni_mtx_unlock(&tp->lk);
}

static void
tls_recv(void *arg, nni_aio *aio)
{
	int  rv;
	tls *tp = arg;

	if (nni_aio_begin(aio) != 0) {
		return;
	}
	nni_mtx_lock(&tp->lk);
	if (tp->tls_closed) {
		nni_mtx_unlock(&tp->lk);
		nni_aio_finish_error(aio, NNG_ECLOSED);
		return;
	}
	if ((rv = nni_aio_schedule(aio, tls_cancel, tp)) != 0) {
		nni_mtx_unlock(&tp->lk);
		nni_aio_finish_error(aio, rv);
		return;
	}

	nni_list_append(&tp->recvs, aio);
	tls_do_recv(tp);
	nni_mtx_unlock(&tp->lk);
}

static int
tls_get_verified(void *arg, void *buf, size_t *szp, nni_type t)
{
	tls *tp = arg;
	bool v  = (mbedtls_ssl_get_verify_result(&tp->ctx) == 0);

	return (nni_copyout_bool(v, buf, szp, t));
}

static const nni_option tls_options[] = {
	{
	    .o_name = NNG_OPT_TLS_VERIFIED,
	    .o_get  = tls_get_verified,
	},
	{
	    .o_name = NULL,
	},
};

static int
tls_setx(void *arg, const char *name, const void *buf, size_t sz, nni_type t)
{
	tls *       tp = arg;
	int         rv;
	nng_stream *tcp;

	tcp = (tp != NULL) ? tp->tcp : NULL;

	if ((rv = nni_stream_setx(tcp, name, buf, sz, t)) != NNG_ENOTSUP) {
		return (rv);
	}
	return (nni_setopt(tls_options, name, tp, buf, sz, t));
}

static int
tls_getx(void *arg, const char *name, void *buf, size_t *szp, nni_type t)
{
	tls *tp = arg;
	int  rv;

	if ((rv = nni_stream_getx(tp->tcp, name, buf, szp, t)) !=
	    NNG_ENOTSUP) {
		return (rv);
	}
	return (nni_getopt(tls_options, name, tp, buf, szp, t));
}

static void
tls_do_handshake(tls *tp)
{
	int      rv;
	nni_aio *aio;

	if (tp->hsdone || tp->tls_closed) {
		return;
	}
	rv = mbedtls_ssl_handshake(&tp->ctx);
	switch (rv) {
	case MBEDTLS_ERR_SSL_WANT_WRITE:
	case MBEDTLS_ERR_SSL_WANT_READ:
		// We have underlying I/O to complete first.  We will
		// be called again by a callback later.
		return;
	case 0:
		// The handshake is done, yay!
		tp->hsdone = true;
		return;

	default:
		// some other error occurred, this causes us to tear it down
		nng_stream_close(tp->tcp);
		tp->tls_closed = true;
		tp->tcp_closed = true;
		rv             = tls_mkerr(rv);

		while (((aio = nni_list_first(&tp->recvs)) != NULL) ||
		    ((aio = nni_list_first(&tp->sends)) != NULL)) {
			nni_aio_list_remove(aio);
			nni_aio_finish_error(aio, rv);
		}
	}
}

// tls_do_send is called to try to send more data if we have not
// yet completed the I/O.  It also completes any transactions that
// *have* completed.  It must be called with the lock held.
static void
tls_do_send(tls *tp)
{
	nni_aio *aio;

	while ((aio = nni_list_first(&tp->sends)) != NULL) {
		int      n;
		uint8_t *buf = NULL;
		size_t   len = 0;
		nni_iov *iov;
		unsigned niov;

		nni_aio_get_iov(aio, &niov, &iov);

		for (unsigned i = 0; i < niov; i++) {
			if (iov[i].iov_len != 0) {
				buf = iov[i].iov_buf;
				len = iov[i].iov_len;
				break;
			}
		}
		if (len == 0 || buf == NULL) {
			nni_aio_list_remove(aio);
			nni_aio_finish_error(aio, NNG_EINVAL);
			continue;
		}

		n = mbedtls_ssl_write(&tp->ctx, buf, len);

		if ((n == MBEDTLS_ERR_SSL_WANT_WRITE) ||
		    (n == MBEDTLS_ERR_SSL_WANT_READ)) {
			// Cannot send any more data right now, wait
			// for callback.
			return;
		}
		// Some other error occurred... this is not good.
		// Want better diagnostics.
		nni_aio_list_remove(aio);
		if (n < 0) {
			nni_aio_finish_error(aio, tls_mkerr(n));
		} else {
			nni_aio_finish(aio, 0, n);
		}
	}
}

static void
tls_do_recv(tls *tp)
{
	nni_aio *aio;

	while ((aio = nni_list_first(&tp->recvs)) != NULL) {
		int      n;
		uint8_t *buf = NULL;
		size_t   len = 0;
		nni_iov *iov;
		unsigned niov;

		nni_aio_get_iov(aio, &niov, &iov);

		for (unsigned i = 0; i < niov; i++) {
			if (iov[i].iov_len != 0) {
				buf = iov[i].iov_buf;
				len = iov[i].iov_len;
				break;
			}
		}
		if (len == 0 || buf == NULL) {
			nni_aio_list_remove(aio);
			nni_aio_finish_error(aio, NNG_EINVAL);
			continue;
		}
		n = mbedtls_ssl_read(&tp->ctx, buf, len);

		if ((n == MBEDTLS_ERR_SSL_WANT_READ) ||
		    (n == MBEDTLS_ERR_SSL_WANT_WRITE)) {
			// Cannot receive any more data right now, wait
			// for callback.
			return;
		}

		nni_aio_list_remove(aio);

		if (n < 0) {
			nni_aio_finish_error(aio, tls_mkerr(n));
		} else {
			nni_aio_finish(aio, 0, n);
		}
	}
}

static void
tls_close(void *arg)
{
	tls *    tp = arg;
	nni_aio *aio;

	nni_aio_close(tp->tcp_send);
	nni_aio_close(tp->tcp_recv);

	nni_mtx_lock(&tp->lk);
	tp->tls_closed = true;

	while (((aio = nni_list_first(&tp->sends)) != NULL) ||
	    ((aio = nni_list_first(&tp->recvs)) != NULL)) {
		nni_aio_list_remove(aio);
		nni_aio_finish_error(aio, NNG_ECLOSED);
	}

	if (tp->hsdone) {
		// This may succeed, or it may fail.  Either way we
		// don't care. Implementations that depend on
		// close-notify to mean anything are broken by design,
		// just like RFC.  Note that we do *NOT* close the TCP
		// connection at this point.
		(void) mbedtls_ssl_close_notify(&tp->ctx);
	} else {
		nng_stream_close(tp->tcp);
	}
	nni_mtx_unlock(&tp->lk);
}

// This allocates a TLS structure, that can be used by the caller.
// The reason we have this API is so that the base structure can be
// embedded in the parent structure.
int
nni_tls_alloc(nng_stream **tlsp)
{
	tls *tp;

	if ((tp = NNI_ALLOC_STRUCT(tp)) == NULL) {
		return (NNG_ENOMEM);
	}
	nni_aio_list_init(&tp->sends);
	nni_aio_list_init(&tp->recvs);
	nni_mtx_init(&tp->lk);
	tp->com.ops.s_close = tls_close;
	tp->com.ops.s_free  = tls_free;
	tp->com.ops.s_send  = tls_send;
	tp->com.ops.s_recv  = tls_recv;
	tp->com.ops.s_getx  = tls_getx;
	tp->com.ops.s_setx  = tls_setx;

	*tlsp = (void *) tp;
	return (0);
}

int
nng_tls_config_server_name(nng_tls_config *cfg, const char *name)
{
	int rv;
	nni_mtx_lock(&cfg->lk);
	if (cfg->active) {
		nni_mtx_unlock(&cfg->lk);
		return (NNG_ESTATE);
	}
	if (cfg->server_name) {
		nni_strfree(cfg->server_name);
	}
	cfg->server_name = nni_strdup(name);
	rv               = cfg->server_name == NULL ? NNG_ENOMEM : 0;
	nni_mtx_unlock(&cfg->lk);
	return (rv);
}

int
nng_tls_config_auth_mode(nng_tls_config *cfg, nng_tls_auth_mode mode)
{
	nni_mtx_lock(&cfg->lk);
	if (cfg->active) {
		nni_mtx_unlock(&cfg->lk);
		return (NNG_ESTATE);
	}
	switch (mode) {
	case NNG_TLS_AUTH_MODE_NONE:
		mbedtls_ssl_conf_authmode(
		    &cfg->cfg_ctx, MBEDTLS_SSL_VERIFY_NONE);
		break;
	case NNG_TLS_AUTH_MODE_OPTIONAL:
		mbedtls_ssl_conf_authmode(
		    &cfg->cfg_ctx, MBEDTLS_SSL_VERIFY_OPTIONAL);
		break;
	case NNG_TLS_AUTH_MODE_REQUIRED:
		mbedtls_ssl_conf_authmode(
		    &cfg->cfg_ctx, MBEDTLS_SSL_VERIFY_REQUIRED);
		break;
	default:
		nni_mtx_unlock(&cfg->lk);
		return (NNG_EINVAL);
	}
	nni_mtx_unlock(&cfg->lk);
	return (0);
}

int
nng_tls_config_ca_chain(
    nng_tls_config *cfg, const char *certs, const char *crl)
{
	size_t         len;
	const uint8_t *pem;
	int            rv;

	// Certs and CRL are in PEM data, with terminating NUL byte.
	nni_mtx_lock(&cfg->lk);
	if (cfg->active) {
		rv = NNG_ESTATE;
		goto err;
	}
	pem = (const uint8_t *) certs;
	len = strlen(certs) + 1;
	if ((rv = mbedtls_x509_crt_parse(&cfg->ca_certs, pem, len)) != 0) {
		rv = tls_mkerr(rv);
		goto err;
	}
	if (crl != NULL) {
		pem = (const uint8_t *) crl;
		len = strlen(crl) + 1;
		if ((rv = mbedtls_x509_crl_parse(&cfg->crl, pem, len)) != 0) {
			rv = tls_mkerr(rv);
			goto err;
		}
	}

	mbedtls_ssl_conf_ca_chain(&cfg->cfg_ctx, &cfg->ca_certs, &cfg->crl);

err:
	nni_mtx_unlock(&cfg->lk);
	return (rv);
}

int
nng_tls_config_own_cert(
    nng_tls_config *cfg, const char *cert, const char *key, const char *pass)
{
	size_t           len;
	const uint8_t *  pem;
	nni_tls_certkey *ck;
	int              rv;

	if ((ck = NNI_ALLOC_STRUCT(ck)) == NULL) {
		return (NNG_ENOMEM);
	}
	mbedtls_x509_crt_init(&ck->crt);
	mbedtls_pk_init(&ck->key);

	pem = (const uint8_t *) cert;
	len = strlen(cert) + 1;
	if ((rv = mbedtls_x509_crt_parse(&ck->crt, pem, len)) != 0) {
		rv = tls_mkerr(rv);
		goto err;
	}

	pem = (const uint8_t *) key;
	len = strlen(key) + 1;
	rv  = mbedtls_pk_parse_key(&ck->key, pem, len, (const uint8_t *) pass,
            pass != NULL ? strlen(pass) : 0);
	if (rv != 0) {
		rv = tls_mkerr(rv);
		goto err;
	}

	nni_mtx_lock(&cfg->lk);
	if (cfg->active) {
		nni_mtx_unlock(&cfg->lk);
		rv = NNG_ESTATE;
		goto err;
	}
	rv = mbedtls_ssl_conf_own_cert(&cfg->cfg_ctx, &ck->crt, &ck->key);
	if (rv != 0) {
		nni_mtx_unlock(&cfg->lk);
		rv = tls_mkerr(rv);
		goto err;
	}

	// Save this structure so we can free it with the context.
	nni_list_append(&cfg->certkeys, ck);
	nni_mtx_unlock(&cfg->lk);
	return (0);

err:
	mbedtls_x509_crt_free(&ck->crt);
	mbedtls_pk_free(&ck->key);
	NNI_FREE_STRUCT(ck);
	return (rv);
}

int
nng_tls_config_ca_file(nng_tls_config *cfg, const char *path)
{
	int    rv;
	void * fdata;
	size_t fsize;
	char * pem;
	// Note that while mbedTLS supports its own file methods, we want
	// to avoid depending on that because it might not have been
	// included, so we use our own.  We have to read the file, and
	// then allocate a buffer that has an extra byte so we can
	// ensure NUL termination.  The file named by path may contain
	// both a ca chain, and crl chain, or just a ca chain.
	if ((rv = nni_file_get(path, &fdata, &fsize)) != 0) {
		return (rv);
	}
	if ((pem = nni_zalloc(fsize + 1)) == NULL) {
		nni_free(fdata, fsize);
		return (NNG_ENOMEM);
	}
	memcpy(pem, fdata, fsize);
	nni_free(fdata, fsize);
	if (strstr(pem, "-----BEGIN X509 CRL-----") != NULL) {
		rv = nng_tls_config_ca_chain(cfg, pem, pem);
	} else {
		rv = nng_tls_config_ca_chain(cfg, pem, NULL);
	}
	nni_free(pem, fsize + 1);
	return (rv);
}

int
nng_tls_config_cert_key_file(
    nng_tls_config *cfg, const char *path, const char *pass)
{
	int    rv;
	void * fdata;
	size_t fsize;
	char * pem;

	// Note that while mbedTLS supports its own file methods, we want
	// to avoid depending on that because it might not have been
	// included, so we use our own.  We have to read the file, and
	// then allocate a buffer that has an extra byte so we can
	// ensure NUL termination.  The file named by path must contain
	// both our certificate, and our private key.  The password
	// may be NULL if the key is not encrypted.
	if ((rv = nni_file_get(path, &fdata, &fsize)) != 0) {
		return (rv);
	}
	if ((pem = nni_zalloc(fsize + 1)) == NULL) {
		nni_free(fdata, fsize);
		return (NNG_ENOMEM);
	}
	memcpy(pem, fdata, fsize);
	nni_free(fdata, fsize);
	rv = nng_tls_config_own_cert(cfg, pem, pem, pass);
	nni_free(pem, fsize + 1);
	return (rv);
}

int
nng_tls_config_alloc(nng_tls_config **cfgp, nng_tls_mode mode)
{
	return (nni_tls_config_init(cfgp, mode));
}

void
nng_tls_config_free(nng_tls_config *cfg)
{
	nni_tls_config_fini(cfg);
}

void
nng_tls_config_hold(nng_tls_config *cfg)
{
	nni_tls_config_hold(cfg);
}
