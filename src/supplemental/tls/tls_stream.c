//
// Copyright 2025 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
// Copyright 2019 Devolutions <info@devolutions.net>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../core/nng_impl.h"

#include "nng/nng.h"
#include "tls_common.h"
#include "tls_engine.h"
#include "tls_stream.h"

static void
tls_bio_stream_free(void *bio)
{
	nng_stream_free(bio);
}

static void
tls_bio_stream_stop(void *bio)
{
	nng_stream_stop(bio);
}

static void
tls_bio_stream_close(void *bio)
{
	nng_stream_close(bio);
}

static void
tls_bio_stream_send(void *bio, nng_aio *aio)
{
	nng_stream_send(bio, aio);
}

static void
tls_bio_stream_recv(void *bio, nng_aio *aio)
{
	nng_stream_recv(bio, aio);
}

static const nni_tls_bio_ops tls_stream_bio = {
	.bio_send  = tls_bio_stream_send,
	.bio_recv  = tls_bio_stream_recv,
	.bio_free  = tls_bio_stream_free,
	.bio_stop  = tls_bio_stream_stop,
	.bio_close = tls_bio_stream_close,
};

static void
tls_stream_reap(void *arg)
{
	tls_stream *ts = arg;

	nni_tls_fini(&ts->conn);
	NNI_FREE_STRUCT(ts);
}

static nni_reap_list tls_stream_reap_list = {
	.rl_offset = offsetof(tls_stream, reap),
	.rl_func   = tls_stream_reap,
};

void
nni_tls_stream_free(void *arg)
{
	tls_stream *ts = arg;

	nni_reap(&tls_stream_reap_list, ts);
}

static void
tls_stream_stop(void *arg)
{
	tls_stream *ts = arg;
	nni_tls_stop(&ts->conn);
}

static void
tls_stream_close(void *arg)
{
	tls_stream *ts = arg;
	nni_tls_close(&ts->conn);
}

static void
tls_stream_send(void *arg, nng_aio *aio)
{
	tls_stream *ts = arg;
	nni_tls_send(&ts->conn, aio);
}

static void
tls_stream_recv(void *arg, nng_aio *aio)
{
	tls_stream *ts = arg;
	nni_tls_recv(&ts->conn, aio);
}

static void
tls_stream_conn_cb(void *arg)
{
	tls_stream         *ts = arg;
	nng_stream         *bio;
	int                 rv;
	const nng_sockaddr *sa;

	if ((rv = nni_aio_result(&ts->conn_aio)) != 0) {
		nni_aio_finish_error(ts->user_aio, rv);
		nni_tls_stream_free(ts);
		return;
	}

	bio = nni_aio_get_output(&ts->conn_aio, 0);
	sa  = nng_stream_peer_addr(bio);

	if ((rv = nni_tls_start(&ts->conn, &tls_stream_bio, bio, sa)) != 0) {
		// NB: if this fails, it *will* have set the bio either way.
		// So nni_tls_stream_free will also free the bio.
		nni_aio_finish_error(ts->user_aio, rv);
		nni_tls_stream_free(ts);
		return;
	}

	nni_aio_set_output(ts->user_aio, 0, &ts->stream);
	nni_aio_finish(ts->user_aio, 0, 0);
}

static nng_err tls_stream_get(
    void *arg, const char *name, void *buf, size_t *szp, nni_type t);
static const nng_sockaddr *tls_stream_self_addr(void *arg);
static const nng_sockaddr *tls_stream_peer_addr(void *arg);
static nng_err             tls_stream_peer_cert(void *arg, nng_tls_cert **);

int
nni_tls_stream_alloc(tls_stream **tsp, nng_tls_config *cfg, nng_aio *user_aio)
{
	tls_stream *ts;
	size_t      size;
	int         rv;

	size = NNI_ALIGN_UP(sizeof(*ts)) +
	    NNI_ALIGN_UP(nni_tls_engine_conn_size());

	if ((ts = nni_zalloc(size)) == NULL) {
		return (NNG_ENOMEM);
	}

	ts->user_aio = user_aio;

	// NB: free is exposed for benefit of dialer/listener
	ts->stream.s_free      = nni_tls_stream_free;
	ts->stream.s_close     = tls_stream_close;
	ts->stream.s_stop      = tls_stream_stop;
	ts->stream.s_send      = tls_stream_send;
	ts->stream.s_recv      = tls_stream_recv;
	ts->stream.s_get       = tls_stream_get;
	ts->stream.s_self_addr = tls_stream_self_addr;
	ts->stream.s_peer_addr = tls_stream_peer_addr;
	ts->stream.s_peer_cert = tls_stream_peer_cert;

	nni_aio_init(&ts->conn_aio, tls_stream_conn_cb, ts);

	if ((rv = nni_tls_init(&ts->conn, cfg, false)) != 0) {
		nni_tls_stream_free(ts);
		return (rv);
	}

	*tsp = ts;
	return (0);
}

static nng_err
tls_get_verified(void *arg, void *buf, size_t *szp, nni_type t)
{
	tls_stream *ts = arg;

	return (nni_copyout_bool(nni_tls_verified(&ts->conn), buf, szp, t));
}

static nng_err
tls_get_peer_cn(void *arg, void *buf, size_t *szp, nni_type t)
{
	NNI_ARG_UNUSED(szp);

	if (t != NNI_TYPE_STRING) {
		return (NNG_EBADTYPE);
	}

	tls_stream *ts = arg;
	*(char **) buf = (char *) nni_tls_peer_cn(&ts->conn);
	return (NNG_OK);
}

static nng_err
tls_stream_peer_cert(void *arg, nng_tls_cert **certp)
{
	tls_stream *ts = arg;
	return (nni_tls_peer_cert(&ts->conn, certp));
}

static const nni_option tls_stream_options[] = {
	{
	    .o_name = NNG_OPT_TLS_VERIFIED,
	    .o_get  = tls_get_verified,
	},
	{
	    .o_name = NNG_OPT_TLS_PEER_CN,
	    .o_get  = tls_get_peer_cn,
	},
	{
	    .o_name = NULL,
	},
};

static nng_err
tls_stream_get(void *arg, const char *name, void *buf, size_t *szp, nni_type t)
{
	tls_stream *ts = arg;
	nng_err     rv;

	if ((rv = nni_stream_get(ts->conn.bio, name, buf, szp, t)) !=
	    NNG_ENOTSUP) {
		return (rv);
	}
	return (nni_getopt(tls_stream_options, name, ts, buf, szp, t));
}

static const nng_sockaddr *
tls_stream_self_addr(void *arg)
{
	tls_stream *ts = arg;
	return (nng_stream_self_addr(ts->conn.bio));
}

static const nng_sockaddr *
tls_stream_peer_addr(void *arg)
{
	tls_stream *ts = arg;
	return (nng_stream_peer_addr(ts->conn.bio));
}
