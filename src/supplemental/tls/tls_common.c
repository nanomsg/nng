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

#include "core/nng_impl.h"
#include "core/tcp.h"
#include "supplemental/tls/tls_api.h"

#include <nng/supplemental/tls/tls.h>

// This file contains common code for TLS, and is only compiled if we
// have TLS configured in the system.  In particular, this provides the
// parts of TLS support that are invariant relative to different TLS
// libraries, such as dialer and listener support.

typedef struct {
	nng_stream_dialer  ops;
	nng_stream_dialer *d; // underlying TCP dialer
	nng_tls_config *   cfg;
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

// For dialing, we need to have our own completion callback, instead of
// the user's completion callback.

static void
tls_conn_cb(void *arg)
{
	nng_stream *    tls = arg;
	nni_tls_common *com = arg;
	nng_stream *    tcp;
	int             rv;

	if ((rv = nni_aio_result(com->aio)) != 0) {
		nni_aio_finish_error(com->uaio, rv);
		nng_stream_free(tls);
		return;
	}

	tcp = nni_aio_get_output(com->aio, 0);

	if ((rv = nni_tls_start(tls, tcp)) != 0) {
		nni_aio_finish_error(com->uaio, rv);
		nng_stream_free(tcp);
		nng_stream_free(tls);
		return;
	}

	nni_aio_set_output(com->uaio, 0, tls);
	nni_aio_finish(com->uaio, 0, 0);
}

// Dialer cancel is called when the user has indicated that they no longer
// want to wait for the connection to establish.
static void
tls_conn_cancel(nni_aio *aio, void *arg, int rv)
{
	nni_tls_common *com = arg;
	NNI_ASSERT(com->uaio == aio);
	// Just pass this down.  If the connection is already done, this
	// will have no effect.
	nni_aio_abort(com->aio, rv);
}

static void
tls_dialer_dial(void *arg, nng_aio *aio)
{
	tls_dialer *    d = arg;
	int             rv;
	nng_stream *    tls;
	nni_tls_common *com;

	if (nni_aio_begin(aio) != 0) {
		return;
	}
	if ((rv = nni_tls_alloc(&tls)) != 0) {
		nni_aio_finish_error(aio, rv);
		return;
	}

	com = (void *) tls;
	if ((rv = nni_aio_init(&com->aio, tls_conn_cb, tls)) != 0) {
		nni_aio_finish_error(aio, rv);
		nng_stream_free(tls);
		return;
	}
	com->uaio = aio;

	// Save a copy of the TLS configuration.  This way we don't have
	// to ensure that the dialer outlives the connection, because the
	// only shared data is the configuration which is reference counted.
	nni_mtx_lock(&d->lk);
	com->cfg = d->cfg;
	nng_tls_config_hold(com->cfg);
	nni_mtx_unlock(&d->lk);

	if ((rv = nni_aio_schedule(aio, tls_conn_cancel, tls)) != 0) {
		nni_aio_finish_error(aio, rv);
		nng_stream_free(tls);
		return;
	}

	nng_stream_dialer_dial(d->d, com->aio);
}

static int
tls_check_string(const void *v, size_t sz, nni_opt_type t)
{
	if ((t != NNI_TYPE_OPAQUE) && (t != NNI_TYPE_STRING)) {
		return (NNG_EBADTYPE);
	}
	if (nni_strnlen(v, sz) >= sz) {
		return (NNG_EINVAL);
	}
	return (0);
}

static int
tls_dialer_set_config(void *arg, const void *buf, size_t sz, nni_type t)
{
	int             rv;
	nng_tls_config *cfg;
	tls_dialer *    d = arg;
	nng_tls_config *old;

	if ((rv = nni_copyin_ptr((void **) &cfg, buf, sz, t)) != 0) {
		return (rv);
	}
	if (cfg == NULL) {
		return (NNG_EINVAL);
	}
	nng_tls_config_hold(cfg);

	nni_mtx_lock(&d->lk);
	old    = d->cfg;
	d->cfg = cfg;
	nni_mtx_unlock(&d->lk);

	nng_tls_config_free(old);
	return (0);
}

static int
tls_dialer_get_config(void *arg, void *buf, size_t *szp, nni_type t)
{
	tls_dialer *    d = arg;
	nng_tls_config *cfg;
	int             rv;
	nni_mtx_lock(&d->lk);
	if ((cfg = d->cfg) != NULL) {
		nng_tls_config_hold(cfg);
	}
	if ((rv = nni_copyout_ptr(cfg, buf, szp, t)) != 0) {
		nng_tls_config_free(cfg);
	}
	nni_mtx_unlock(&d->lk);
	return (rv);
}

static int
tls_dialer_set_server_name(void *arg, const void *buf, size_t sz, nni_type t)
{
	tls_dialer *d = arg;
	int         rv;
	if ((rv = tls_check_string(buf, sz, t)) == 0) {
		nni_mtx_lock(&d->lk);
		rv = nng_tls_config_server_name(d->cfg, buf);
		nni_mtx_unlock(&d->lk);
	}
	return (rv);
}

static int
tls_dialer_set_auth_mode(void *arg, const void *buf, size_t sz, nni_type t)
{
	int         mode;
	int         rv;
	tls_dialer *d = arg;

	rv = nni_copyin_int(&mode, buf, sz, NNG_TLS_AUTH_MODE_NONE,
	    NNG_TLS_AUTH_MODE_REQUIRED, t);
	if (rv == 0) {
		nni_mtx_lock(&d->lk);
		rv = nng_tls_config_auth_mode(d->cfg, mode);
		nni_mtx_unlock(&d->lk);
	}
	return (rv);
}

static int
tls_dialer_set_ca_file(void *arg, const void *buf, size_t sz, nni_opt_type t)
{
	tls_dialer *d = arg;
	int         rv;

	if ((rv = tls_check_string(buf, sz, t)) == 0) {
		nni_mtx_lock(&d->lk);
		rv = nng_tls_config_ca_file(d->cfg, buf);
		nni_mtx_unlock(&d->lk);
	}
	return (rv);
}

static int
tls_dialer_set_cert_key_file(
    void *arg, const void *buf, size_t sz, nni_opt_type t)
{
	tls_dialer *d = arg;
	int         rv;

	if ((rv = tls_check_string(buf, sz, t)) == 0) {
		nni_mtx_lock(&d->lk);
		rv = nng_tls_config_cert_key_file(d->cfg, buf, NULL);
		nni_mtx_unlock(&d->lk);
	}
	return (rv);
}

static const nni_option tls_dialer_opts[] = {
	{
	    .o_name = NNG_OPT_TLS_CONFIG,
	    .o_get  = tls_dialer_get_config,
	    .o_set  = tls_dialer_set_config,
	},
	{
	    .o_name = NNG_OPT_TLS_SERVER_NAME,
	    .o_set  = tls_dialer_set_server_name,
	},
	{
	    .o_name = NNG_OPT_TLS_CA_FILE,
	    .o_set  = tls_dialer_set_ca_file,
	},
	{
	    .o_name = NNG_OPT_TLS_CERT_KEY_FILE,
	    .o_set  = tls_dialer_set_cert_key_file,
	},
	{
	    .o_name = NNG_OPT_TLS_AUTH_MODE,
	    .o_set  = tls_dialer_set_auth_mode,
	},
	{
	    .o_name = NULL,
	},
};

static int
tls_dialer_getx(
    void *arg, const char *name, void *buf, size_t *szp, nni_type t)
{
	tls_dialer *d = arg;
	int         rv;

	rv = nni_stream_dialer_getx(d->d, name, buf, szp, t);
	if (rv == NNG_ENOTSUP) {
		rv = nni_getopt(tls_dialer_opts, name, d, buf, szp, t);
	}
	return (rv);
}

static int
tls_dialer_setx(
    void *arg, const char *name, const void *buf, size_t sz, nni_type t)
{
	tls_dialer *d = arg;
	int         rv;

	rv = nni_stream_dialer_setx(d->d, name, buf, sz, t);
	if (rv == NNG_ENOTSUP) {
		rv = nni_setopt(tls_dialer_opts, name, d, buf, sz, t);
	}
	return (rv);
}

int
nni_tls_dialer_alloc(nng_stream_dialer **dp, const nng_url *url)
{
	tls_dialer *d;
	int         rv;
	nng_url     myurl;

	memcpy(&myurl, url, sizeof(myurl));
	myurl.u_scheme = url->u_scheme + strlen("tls+");

	if ((rv = nni_init()) != 0) {
		return (rv);
	}
	if ((d = NNI_ALLOC_STRUCT(d)) == NULL) {
		return (NNG_ENOMEM);
	}
	nni_mtx_init(&d->lk);

	if ((rv = nng_stream_dialer_alloc_url(&d->d, &myurl)) != 0) {
		nni_mtx_fini(&d->lk);
		NNI_FREE_STRUCT(d);
		return (rv);
	}
	if ((rv = nng_tls_config_alloc(&d->cfg, NNG_TLS_MODE_CLIENT)) != 0) {
		nng_stream_dialer_free(d->d);
		nni_mtx_fini(&d->lk);
		NNI_FREE_STRUCT(d);
		return (rv);
	}

	// Set the expected outbound hostname
	nng_tls_config_server_name(d->cfg, url->u_hostname);

	d->ops.sd_close = tls_dialer_close;
	d->ops.sd_free  = tls_dialer_free;
	d->ops.sd_dial  = tls_dialer_dial;
	d->ops.sd_getx  = tls_dialer_getx;
	d->ops.sd_setx  = tls_dialer_setx;
	*dp             = (void *) d;
	return (rv);
}

typedef struct {
	nng_stream_listener  ops;
	nng_stream_listener *l;
	nng_tls_config *     cfg;
	nni_mtx              lk;
} tls_listener;

static void
tls_listener_close(void *arg)
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

static int
tls_listener_listen(void *arg)
{
	tls_listener *l = arg;
	return (nng_stream_listener_listen(l->l));
}

static void
tls_listener_accept(void *arg, nng_aio *aio)
{
	tls_listener *  l = arg;
	int             rv;
	nng_stream *    tls;
	nni_tls_common *com;

	if (nni_aio_begin(aio) != 0) {
		return;
	}
	if ((rv = nni_tls_alloc(&tls)) != 0) {
		nni_aio_finish_error(aio, rv);
		return;
	}
	com = (void *) tls;
	if ((rv = nni_aio_init(&com->aio, tls_conn_cb, tls)) != 0) {
		nni_aio_finish_error(aio, rv);
		nng_stream_free(tls);
		return;
	}
	com->uaio = aio;

	// Save a copy of the TLS configuration.  This way we don't have
	// to ensure that the dialer outlives the connection, because the
	// only shared data is the configuration which is reference counted.
	nni_mtx_lock(&l->lk);
	com->cfg = l->cfg;
	nng_tls_config_hold(com->cfg);
	nni_mtx_unlock(&l->lk);

	if ((rv = nni_aio_schedule(aio, tls_conn_cancel, tls)) != 0) {
		nni_aio_finish_error(aio, rv);
		nng_stream_free(tls);
		return;
	}

	nng_stream_listener_accept(l->l, com->aio);
}

static int
tls_listener_set_config(void *arg, const void *buf, size_t sz, nni_type t)
{
	int             rv;
	nng_tls_config *cfg;
	tls_listener *  l = arg;
	nng_tls_config *old;

	if ((rv = nni_copyin_ptr((void **) &cfg, buf, sz, t)) != 0) {
		return (rv);
	}
	if (cfg == NULL) {
		return (NNG_EINVAL);
	}

	nng_tls_config_hold(cfg);

	nni_mtx_lock(&l->lk);
	old    = l->cfg;
	l->cfg = cfg;
	nni_mtx_unlock(&l->lk);

	nng_tls_config_free(old);

	return (0);
}

static int
tls_listener_get_config(void *arg, void *buf, size_t *szp, nni_type t)
{
	tls_listener *  l = arg;
	nng_tls_config *cfg;
	int             rv;
	nni_mtx_lock(&l->lk);
	if ((cfg = l->cfg) != NULL) {
		nng_tls_config_hold(cfg);
	}
	if ((rv = nni_copyout_ptr(cfg, buf, szp, t)) != 0) {
		nng_tls_config_free(cfg);
	}
	nni_mtx_unlock(&l->lk);
	return (rv);
}

static int
tls_listener_set_server_name(void *arg, const void *buf, size_t sz, nni_type t)
{
	tls_listener *l = arg;
	int           rv;
	if ((rv = tls_check_string(buf, sz, t)) == 0) {
		nni_mtx_lock(&l->lk);
		rv = nng_tls_config_server_name(l->cfg, buf);
		nni_mtx_unlock(&l->lk);
	}
	return (rv);
}

static int
tls_listener_set_auth_mode(void *arg, const void *buf, size_t sz, nni_type t)
{
	int           mode;
	int           rv;
	tls_listener *l = arg;

	rv = nni_copyin_int(&mode, buf, sz, NNG_TLS_AUTH_MODE_NONE,
	    NNG_TLS_AUTH_MODE_REQUIRED, t);
	if (rv == 0) {
		nni_mtx_lock(&l->lk);
		rv = nng_tls_config_auth_mode(l->cfg, mode);
		nni_mtx_unlock(&l->lk);
	}
	return (rv);
}

static int
tls_listener_set_ca_file(void *arg, const void *buf, size_t sz, nni_opt_type t)
{
	tls_listener *l = arg;
	int           rv;

	if ((rv = tls_check_string(buf, sz, t)) == 0) {
		nni_mtx_lock(&l->lk);
		rv = nng_tls_config_ca_file(l->cfg, buf);
		nni_mtx_unlock(&l->lk);
	}
	return (rv);
}

static int
tls_listener_set_cert_key_file(
    void *arg, const void *buf, size_t sz, nni_opt_type t)
{
	tls_listener *l = arg;
	int           rv;

	if ((rv = tls_check_string(buf, sz, t)) == 0) {
		nni_mtx_lock(&l->lk);
		rv = nng_tls_config_cert_key_file(l->cfg, buf, NULL);
		nni_mtx_unlock(&l->lk);
	}
	return (rv);
}

static const nni_option tls_listener_opts[] = {
	{
	    .o_name = NNG_OPT_TLS_CONFIG,
	    .o_get  = tls_listener_get_config,
	    .o_set  = tls_listener_set_config,
	},
	{
	    .o_name = NNG_OPT_TLS_SERVER_NAME,
	    .o_set  = tls_listener_set_server_name,
	},
	{
	    .o_name = NNG_OPT_TLS_CA_FILE,
	    .o_set  = tls_listener_set_ca_file,
	},
	{
	    .o_name = NNG_OPT_TLS_CERT_KEY_FILE,
	    .o_set  = tls_listener_set_cert_key_file,
	},
	{
	    .o_name = NNG_OPT_TLS_AUTH_MODE,
	    .o_set  = tls_listener_set_auth_mode,
	},
	{
	    .o_name = NULL,
	},
};

static int
tls_listener_getx(
    void *arg, const char *name, void *buf, size_t *szp, nni_type t)
{
	int           rv;
	tls_listener *l = arg;

	rv = nni_stream_listener_getx(l->l, name, buf, szp, t);
	if (rv == NNG_ENOTSUP) {
		rv = nni_getopt(tls_listener_opts, name, l, buf, szp, t);
	}
	return (rv);
}

static int
tls_listener_setx(
    void *arg, const char *name, const void *buf, size_t sz, nni_type t)
{
	int           rv;
	tls_listener *l = arg;

	rv = nni_stream_listener_setx(l->l, name, buf, sz, t);
	if (rv == NNG_ENOTSUP) {
		rv = nni_setopt(tls_listener_opts, name, l, buf, sz, t);
	}
	return (rv);
}

int
nni_tls_listener_alloc(nng_stream_listener **lp, const nng_url *url)
{
	tls_listener *l;
	int           rv;
	nng_url       myurl;

	memcpy(&myurl, url, sizeof(myurl));
	myurl.u_scheme = url->u_scheme + strlen("tls+");

	if ((rv = nni_init()) != 0) {
		return (rv);
	}
	if ((l = NNI_ALLOC_STRUCT(l)) == NULL) {
		return (NNG_ENOMEM);
	}
	nni_mtx_init(&l->lk);

	if ((rv = nng_stream_listener_alloc_url(&l->l, &myurl)) != 0) {
		nni_mtx_fini(&l->lk);
		NNI_FREE_STRUCT(l);
		return (rv);
	}
	if ((rv = nng_tls_config_alloc(&l->cfg, NNG_TLS_MODE_SERVER)) != 0) {
		nng_stream_listener_free(l->l);
		nni_mtx_fini(&l->lk);
		NNI_FREE_STRUCT(l);
		return (rv);
	}
	l->ops.sl_free   = tls_listener_free;
	l->ops.sl_close  = tls_listener_close;
	l->ops.sl_accept = tls_listener_accept;
	l->ops.sl_listen = tls_listener_listen;
	l->ops.sl_getx   = tls_listener_getx;
	l->ops.sl_setx   = tls_listener_setx;
	*lp              = (void *) l;
	return (0);
}

// The following checks exist for socket configuration, when we need to
// configure an option on a socket before any transport is configured
// underneath.

static int
tls_check_config(const void *buf, size_t sz, nni_type t)
{
	int             rv;
	nng_tls_config *cfg;

	if ((rv = nni_copyin_ptr((void **) &cfg, buf, sz, t)) != 0) {
		return (rv);
	}
	if (cfg == NULL) {
		return (NNG_EINVAL);
	}
	return (0);
}

static int
tls_check_auth_mode(const void *buf, size_t sz, nni_type t)
{
	int mode;
	int rv;

	rv = nni_copyin_int(&mode, buf, sz, NNG_TLS_AUTH_MODE_NONE,
	    NNG_TLS_AUTH_MODE_REQUIRED, t);
	return (rv);
}

static const nni_chkoption tls_chkopts[] = {
	{
	    .o_name  = NNG_OPT_TLS_CONFIG,
	    .o_check = tls_check_config,
	},
	{
	    .o_name  = NNG_OPT_TLS_SERVER_NAME,
	    .o_check = tls_check_string,
	},
	{
	    .o_name  = NNG_OPT_TLS_CA_FILE,
	    .o_check = tls_check_string,
	},
	{
	    .o_name  = NNG_OPT_TLS_CERT_KEY_FILE,
	    .o_check = tls_check_string,
	},
	{
	    .o_name  = NNG_OPT_TLS_AUTH_MODE,
	    .o_check = tls_check_auth_mode,
	},
	{
	    .o_name = NULL,
	},
};

int
nni_tls_checkopt(const char *name, const void *data, size_t sz, nni_type t)
{
	int rv;

	rv = nni_chkopt(tls_chkopts, name, data, sz, t);
	if (rv == NNG_ENOTSUP) {
		rv = nni_stream_checkopt("tcp", name, data, sz, t);
	}
	return (rv);
}
