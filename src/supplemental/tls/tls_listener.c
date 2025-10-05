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

#include "tls_common.h"
#include "tls_engine.h"
#include "tls_stream.h"

typedef struct {
	nng_stream_listener  ops;
	nng_stream_listener *l;
	nng_tls_config      *cfg;
	bool                 started;
	nni_mtx              lk;
} tls_listener;

static void
tls_listener_close(void *arg)
{
	tls_listener *l = arg;
	nng_stream_listener_close(l->l);
}

static void
tls_listener_stop(void *arg)
{
	tls_listener *l = arg;
	nng_stream_listener_close(l->l);
}

static void
tls_listener_free(void *arg)
{
	tls_listener *l;
	if ((l = arg) != NULL) {
		tls_listener_close(l);
		nng_tls_config_free(l->cfg);
		nng_stream_listener_free(l->l);
		nni_mtx_fini(&l->lk);
		NNI_FREE_STRUCT(l);
	}
}

static nng_err
tls_listener_listen(void *arg)
{
	tls_listener *l = arg;
	nni_mtx_lock(&l->lk);
	l->started = true;
	nni_mtx_unlock(&l->lk);
	return (nng_stream_listener_listen(l->l));
}

// Listener cancel is called when the user has indicated that they no longer
// want to wait for the connection to establish.
static void
tls_listener_cancel(nni_aio *aio, void *arg, nng_err rv)
{
	tls_stream *ts = arg;

	NNI_ARG_UNUSED(aio);

	// Just pass this down.  If the connection is already done, this
	// will have no effect.
	nni_aio_abort(&ts->conn_aio, rv);
}

static void
tls_listener_accept(void *arg, nng_aio *aio)
{
	tls_listener *l = arg;
	int           rv;
	tls_stream   *ts;

	nni_aio_reset(aio);
	if ((rv = nni_tls_stream_alloc(&ts, l->cfg, aio)) != 0) {
		nni_aio_finish_error(aio, rv);
		return;
	}

	if (!nni_aio_start(aio, tls_listener_cancel, ts)) {
		nni_tls_stream_free(ts);
		return;
	}

	nng_stream_listener_accept(l->l, &ts->conn_aio);
}

static nng_err
tls_listener_set_tls(void *arg, nng_tls_config *cfg)
{
	tls_listener   *l = arg;
	nng_tls_config *old;
	if (cfg == NULL) {
		return (NNG_EINVAL);
	}
	nng_tls_config_hold(cfg);

	nni_mtx_lock(&l->lk);
	if (l->started) {
		nni_mtx_unlock(&l->lk);
		nng_tls_config_free(cfg);
		return (NNG_EBUSY);
	}
	old    = l->cfg;
	l->cfg = cfg;
	nni_mtx_unlock(&l->lk);

	nng_tls_config_free(old);
	return (NNG_OK);
}

static nng_err
tls_listener_get_tls(void *arg, nng_tls_config **cfg)
{
	tls_listener *l = arg;
	nni_mtx_lock(&l->lk);
	*cfg = l->cfg;
	nni_mtx_unlock(&l->lk);
	return (NNG_OK);
}

static nng_err
tls_listener_get(
    void *arg, const char *name, void *buf, size_t *szp, nni_type t)
{
	tls_listener *l = arg;

	return (nni_stream_listener_get(l->l, name, buf, szp, t));
}

static nng_err
tls_listener_set(
    void *arg, const char *name, const void *buf, size_t sz, nni_type t)
{
	tls_listener *l = arg;

	return (nni_stream_listener_set(l->l, name, buf, sz, t));
}

nng_err
nni_tls_listener_alloc(nng_stream_listener **lp, const nng_url *url)
{
	tls_listener *l;
	nng_err       rv;
	nng_url       my_url;

	memcpy(&my_url, url, sizeof(my_url));

	if (strncmp(my_url.u_scheme, "tls+", 4) == 0) {
		my_url.u_scheme += 4;
	}

	if ((l = NNI_ALLOC_STRUCT(l)) == NULL) {
		return (NNG_ENOMEM);
	}
	nni_mtx_init(&l->lk);

	if ((rv = nng_stream_listener_alloc_url(&l->l, &my_url)) != NNG_OK) {
		nni_mtx_fini(&l->lk);
		NNI_FREE_STRUCT(l);
		return (rv);
	}
	if ((rv = nng_tls_config_alloc(&l->cfg, NNG_TLS_MODE_SERVER)) !=
	    NNG_OK) {
		nng_stream_listener_free(l->l);
		nni_mtx_fini(&l->lk);
		NNI_FREE_STRUCT(l);
		return (rv);
	}
	l->ops.sl_free    = tls_listener_free;
	l->ops.sl_close   = tls_listener_close;
	l->ops.sl_stop    = tls_listener_stop;
	l->ops.sl_accept  = tls_listener_accept;
	l->ops.sl_listen  = tls_listener_listen;
	l->ops.sl_get     = tls_listener_get;
	l->ops.sl_set     = tls_listener_set;
	l->ops.sl_get_tls = tls_listener_get_tls;
	l->ops.sl_set_tls = tls_listener_set_tls;
	*lp               = (void *) l;
	return (0);
}
