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
	nng_stream_dialer  ops;
	nng_stream_dialer *d; // underlying TCP dialer
	nng_tls_config    *cfg;
	bool               started;
	nni_mtx            lk; // protects the config
} tls_dialer;

static void
tls_dialer_close(void *arg)
{
	tls_dialer *d = arg;
	nng_stream_dialer_close(d->d);
}

static void
tls_dialer_free(void *arg)
{
	tls_dialer *d;
	if ((d = arg) != NULL) {
		nng_stream_dialer_free(d->d);
		nng_tls_config_free(d->cfg);
		nni_mtx_fini(&d->lk);
		NNI_FREE_STRUCT(d);
	}
}

static void
tls_dialer_stop(void *arg)
{
	tls_dialer *d = arg;

	nng_stream_dialer_stop(d->d);
}

// Dialer cancel is called when the user has indicated that they no longer
// want to wait for the connection to establish.
static void
tls_dialer_cancel(nni_aio *aio, void *arg, nng_err rv)
{
	tls_stream *ts = arg;

	NNI_ARG_UNUSED(aio);

	// Just pass this down.  If the connection is already done, this
	// will have no effect.
	nni_aio_abort(&ts->conn_aio, rv);
}

static void
tls_dialer_dial(void *arg, nng_aio *aio)
{
	tls_dialer *d = arg;
	tls_stream *ts;
	int         rv;

	nni_aio_reset(aio);
	if ((rv = nni_tls_stream_alloc(&ts, d->cfg, aio)) != 0) {
		nni_aio_finish_error(aio, rv);
		return;
	}

	if (!nni_aio_start(aio, tls_dialer_cancel, ts)) {
		nni_tls_stream_free(ts);
		return;
	}
	nni_mtx_lock(&d->lk);
	d->started = true;
	nni_mtx_unlock(&d->lk);

	nng_stream_dialer_dial(d->d, &ts->conn_aio);
}

static nng_err
tls_dialer_set_tls(void *arg, nng_tls_config *cfg)
{
	tls_dialer     *d = arg;
	nng_tls_config *old;
	if (cfg == NULL) {
		return (NNG_EINVAL);
	}

	nng_tls_config_hold(cfg);

	nni_mtx_lock(&d->lk);
	if (d->started) {
		nni_mtx_unlock(&d->lk);
		nng_tls_config_free(cfg);
		return (NNG_EBUSY);
	}
	old    = d->cfg;
	d->cfg = cfg;
	nni_mtx_unlock(&d->lk);

	nng_tls_config_free(old);
	return (NNG_OK);
}

static nng_err
tls_dialer_get_tls(void *arg, nng_tls_config **cfg)
{
	tls_dialer *d = arg;
	nni_mtx_lock(&d->lk);
	*cfg = d->cfg;
	nni_mtx_unlock(&d->lk);
	return (NNG_OK);
}

static nng_err
tls_dialer_get(void *arg, const char *name, void *buf, size_t *szp, nni_type t)
{
	tls_dialer *d = arg;

	return (nni_stream_dialer_get(d->d, name, buf, szp, t));
}

static nng_err
tls_dialer_set(
    void *arg, const char *name, const void *buf, size_t sz, nni_type t)
{
	tls_dialer *d = arg;

	return (nni_stream_dialer_set(d->d, name, buf, sz, t));
}

nng_err
nni_tls_dialer_alloc(nng_stream_dialer **dp, const nng_url *url)
{
	tls_dialer *d;
	nng_err     rv;
	nng_url     my_url;

	memcpy(&my_url, url, sizeof(my_url));
	if (strncmp(my_url.u_scheme, "tls+", 4) == 0) {
		my_url.u_scheme += 4;
	}

	if ((d = NNI_ALLOC_STRUCT(d)) == NULL) {
		return (NNG_ENOMEM);
	}
	nni_mtx_init(&d->lk);

	if ((rv = nng_stream_dialer_alloc_url(&d->d, &my_url)) != NNG_OK) {
		nni_mtx_fini(&d->lk);
		NNI_FREE_STRUCT(d);
		return (rv);
	}
	if ((rv = nng_tls_config_alloc(&d->cfg, NNG_TLS_MODE_CLIENT)) !=
	    NNG_OK) {
		nng_stream_dialer_free(d->d);
		nni_mtx_fini(&d->lk);
		NNI_FREE_STRUCT(d);
		return (rv);
	}

	// Set the expected outbound hostname
	nng_tls_config_server_name(d->cfg, url->u_hostname);

	d->ops.sd_close   = tls_dialer_close;
	d->ops.sd_free    = tls_dialer_free;
	d->ops.sd_stop    = tls_dialer_stop;
	d->ops.sd_dial    = tls_dialer_dial;
	d->ops.sd_get     = tls_dialer_get;
	d->ops.sd_set     = tls_dialer_set;
	d->ops.sd_get_tls = tls_dialer_get_tls;
	d->ops.sd_set_tls = tls_dialer_set_tls;

	*dp = (void *) d;
	return (rv);
}
