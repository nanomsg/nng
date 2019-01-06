//
// Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
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
#include "supplemental/tls/tls_api.h"

#include <nng/supplemental/tcp/tcp.h>
#include <nng/supplemental/tls/tls.h>

// This file contains common code for TLS, and is only compiled if we
// have TLS configured in the system.  In particular, this provides the
// parts of TLS support that are invariant relative to different TLS
// libraries, such as dialer and listener support.

struct nng_tls_s {
	nni_tls *       c;
	nni_aio *       aio;  // system aio for connect/accept
	nni_aio *       uaio; // user aio for connect/accept
	nng_tls_config *cfg;
};

// We use a union and share an "endpoint" for both dialers and listeners.
// This allows us to reuse the bulk of the code for things like option
// handlers for both dialers and listeners.
typedef union tls_tcp_ep_u {
	nni_tcp_dialer *  d;
	nni_tcp_listener *l;
} tls_tcp_ep;

typedef struct nng_tls_ep_s {
	tls_tcp_ep      tcp;
	nng_tls_config *cfg;
	nni_mtx         lk;
} tls_ep;

void
nng_tls_close(nng_tls *tls)
{
	nni_tls_close(tls->c);
}

void
nng_tls_free(nng_tls *tls)
{
	if (tls != NULL) {
		nni_tls_fini(tls->c);
		nni_aio_fini(tls->aio);
		nng_tls_config_free(tls->cfg);
		NNI_FREE_STRUCT(tls);
	}
}

void
nng_tls_send(nng_tls *tls, nng_aio *aio)
{
	nni_tls_send(tls->c, aio);
}

void
nng_tls_recv(nng_tls *tls, nng_aio *aio)
{
	nni_tls_recv(tls->c, aio);
}

int
nni_tls_get(nng_tls *tls, const char *name, void *buf, size_t *szp, nni_type t)
{
	return (nni_tls_getopt(tls->c, name, buf, szp, t));
}

int
nni_tls_set(
    nng_tls *tls, const char *name, const void *buf, size_t sz, nni_type t)
{
	return (nni_tls_setopt(tls->c, name, buf, sz, t));
}

int
nng_tls_getopt(nng_tls *tls, const char *name, void *buf, size_t *szp)
{
	return (nni_tls_getopt(tls->c, name, buf, szp, NNI_TYPE_OPAQUE));
}

int
nng_tls_setopt(nng_tls *tls, const char *name, const void *buf, size_t sz)
{
	return (nni_tls_setopt(tls->c, name, buf, sz, NNI_TYPE_OPAQUE));
}

int
nng_tls_dialer_alloc(nng_tls_dialer **dp)
{
	tls_ep *ep;
	int     rv;

	if ((rv = nni_init()) != 0) {
		return (rv);
	}
	if ((ep = NNI_ALLOC_STRUCT(ep)) == NULL) {
		return (NNG_ENOMEM);
	}
	nni_mtx_init(&ep->lk);

	if ((rv = nni_tcp_dialer_init(&ep->tcp.d)) != 0) {
		nni_mtx_fini(&ep->lk);
		NNI_FREE_STRUCT(ep);
		return (rv);
	}
	if ((rv = nng_tls_config_alloc(&ep->cfg, NNG_TLS_MODE_CLIENT)) != 0) {
		nni_tcp_dialer_fini(ep->tcp.d);
		nni_mtx_fini(&ep->lk);
		NNI_FREE_STRUCT(ep);
		return (rv);
	}
	*dp = (void *) ep;
	return (rv);
}

void
nng_tls_dialer_close(nng_tls_dialer *d)
{
	tls_ep *ep = (void *) d;
	nni_tcp_dialer_close(ep->tcp.d);
}

void
nng_tls_dialer_free(nng_tls_dialer *d)
{
	tls_ep *ep = (void *) d;
	if (ep != NULL) {
		nni_tcp_dialer_fini(ep->tcp.d);
		nng_tls_config_free(ep->cfg);
		nni_mtx_fini(&ep->lk);
		NNI_FREE_STRUCT(ep);
	}
}

// For dialing, we need to have our own completion callback, instead of
// the user's completion callback.

static void
tls_conn_cb(void *arg)
{
	nng_tls *     tls = arg;
	nni_tcp_conn *tcp;
	int           rv;

	if ((rv = nni_aio_result(tls->aio)) != 0) {
		nni_aio_finish_error(tls->uaio, rv);
		nng_tls_free(tls);
		return;
	}

	tcp = nni_aio_get_output(tls->aio, 0);

	rv = nni_tls_init(&tls->c, tls->cfg, tcp);
	if (rv != 0) {
		nni_aio_finish_error(tls->uaio, rv);
		nni_tcp_conn_fini(tcp);
		nng_tls_free(tls);
		return;
	}

	nni_aio_set_output(tls->uaio, 0, tls);
	nni_aio_finish(tls->uaio, 0, 0);
}

// Dialer cancel is called when the user has indicated that they no longer
// want to wait for the connection to establish.
static void
tls_conn_cancel(nni_aio *aio, void *arg, int rv)
{
	nng_tls *tls = arg;
	NNI_ASSERT(tls->uaio == aio);
	// Just pass this down.  If the connection is already done, this
	// will have no effect.
	nni_aio_abort(tls->aio, rv);
}

void
nng_tls_dialer_dial(nng_tls_dialer *d, const nng_sockaddr *sa, nng_aio *aio)
{
	int      rv;
	nng_tls *tls;
	tls_ep * ep = (void *) d;

	if (nni_aio_begin(aio) != 0) {
		return;
	}
	if ((tls = NNI_ALLOC_STRUCT(tls)) == NULL) {
		nni_aio_finish_error(aio, NNG_ENOMEM);
		return;
	}
	if ((rv = nni_aio_init(&tls->aio, tls_conn_cb, tls)) != 0) {
		nni_aio_finish_error(aio, rv);
		NNI_FREE_STRUCT(tls);
		return;
	}
	tls->uaio = aio;

	// Save a copy of the TLS configuration.  This way we don't have
	// to ensure that the dialer outlives the connection, because the
	// only shared data is the configuration which is reference counted.
	nni_mtx_lock(&ep->lk);
	tls->cfg = ep->cfg;
	nng_tls_config_hold(tls->cfg);
	nni_mtx_unlock(&ep->lk);

	if ((rv = nni_aio_schedule(aio, tls_conn_cancel, tls)) != 0) {
		nni_aio_finish_error(aio, rv);
		nng_tls_free(tls);
		return;
	}

	nni_tcp_dialer_dial(ep->tcp.d, sa, tls->aio);
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
tls_ep_set_config(void *arg, const void *buf, size_t sz, nni_type t)
{
	int             rv;
	nng_tls_config *cfg;
	tls_ep *        ep;

	if ((rv = nni_copyin_ptr((void **) &cfg, buf, sz, t)) != 0) {
		return (rv);
	}
	if (cfg == NULL) {
		return (NNG_EINVAL);
	}
	if ((ep = arg) != NULL) {
		nng_tls_config *old;

		nni_mtx_lock(&ep->lk);
		old = ep->cfg;
		nng_tls_config_hold(cfg);
		ep->cfg = cfg;
		nni_mtx_unlock(&ep->lk);
		if (old != NULL) {
			nng_tls_config_free(old);
		}
	}
	return (0);
}

static int
tls_ep_get_config(void *arg, void *buf, size_t *szp, nni_type t)
{
	tls_ep *        ep = arg;
	nng_tls_config *cfg;
	int             rv;
	nni_mtx_lock(&ep->lk);
	if ((cfg = ep->cfg) != NULL) {
		nng_tls_config_hold(cfg);
	}
	if ((rv = nni_copyout_ptr(cfg, buf, szp, t)) != 0) {
		nng_tls_config_free(cfg);
	}
	nni_mtx_unlock(&ep->lk);
	return (rv);
}

static int
tls_ep_set_server_name(void *arg, const void *buf, size_t sz, nni_type t)
{
	tls_ep *ep = arg;
	int     rv;
	if ((rv = tls_check_string(buf, sz, t)) != 0) {
		return (rv);
	}
	if ((ep = arg) != NULL) {
		nni_mtx_lock(&ep->lk);
		rv = nng_tls_config_server_name(ep->cfg, buf);
		nni_mtx_unlock(&ep->lk);
	}
	return (rv);
}

static int
tls_ep_set_auth_mode(void *arg, const void *buf, size_t sz, nni_type t)
{
	int     mode;
	int     rv;
	tls_ep *ep;

	rv = nni_copyin_int(&mode, buf, sz, NNG_TLS_AUTH_MODE_NONE,
	    NNG_TLS_AUTH_MODE_REQUIRED, t);
	if ((rv == 0) && ((ep = arg) != NULL)) {
		nni_mtx_lock(&ep->lk);
		rv = nng_tls_config_auth_mode(ep->cfg, mode);
		nni_mtx_unlock(&ep->lk);
	}
	return (rv);
}

static int
tls_ep_set_ca_file(void *arg, const void *buf, size_t sz, nni_opt_type t)
{
	tls_ep *ep;
	int     rv;

	if (((rv = tls_check_string(buf, sz, t)) == 0) &&
	    ((ep = arg) != NULL)) {
		nni_mtx_lock(&ep->lk);
		rv = nng_tls_config_ca_file(ep->cfg, buf);
		nni_mtx_unlock(&ep->lk);
	}
	return (rv);
}

static int
tls_ep_set_cert_key_file(void *arg, const void *buf, size_t sz, nni_opt_type t)
{
	tls_ep *ep;
	int     rv;

	if (((rv = tls_check_string(buf, sz, t)) == 0) &&
	    ((ep = arg) != NULL)) {
		nni_mtx_lock(&ep->lk);
		rv = nng_tls_config_cert_key_file(ep->cfg, buf, NULL);
		nni_mtx_unlock(&ep->lk);
	}
	return (rv);
}

static const nni_option tls_ep_opts[] = {
	{
	    .o_name = NNG_OPT_TLS_CONFIG,
	    .o_get  = tls_ep_get_config,
	    .o_set  = tls_ep_set_config,
	},
	{
	    .o_name = NNG_OPT_TLS_SERVER_NAME,
	    .o_set  = tls_ep_set_server_name,
	},
	{
	    .o_name = NNG_OPT_TLS_CA_FILE,
	    .o_set  = tls_ep_set_ca_file,
	},
	{
	    .o_name = NNG_OPT_TLS_CERT_KEY_FILE,
	    .o_set  = tls_ep_set_cert_key_file,
	},
	{
	    .o_name = NNG_OPT_TLS_AUTH_MODE,
	    .o_set  = tls_ep_set_auth_mode,
	},
	{
	    .o_name = NULL,
	},
};

// private version of getopt and setopt take the type
int
nni_tls_dialer_getopt(
    nng_tls_dialer *d, const char *name, void *buf, size_t *szp, nni_type t)
{
	int     rv;
	tls_ep *ep = (void *) d;

	rv = nni_tcp_dialer_getopt(ep->tcp.d, name, buf, szp, t);
	if (rv == NNG_ENOTSUP) {
		rv = nni_getopt(tls_ep_opts, name, ep, buf, szp, t);
	}
	return (rv);
}

int
nni_tls_dialer_setopt(nng_tls_dialer *d, const char *name, const void *buf,
    size_t sz, nni_type t)
{
	int     rv;
	tls_ep *ep = (void *) d;

	rv = nni_tcp_dialer_setopt(
	    ep != NULL ? ep->tcp.d : NULL, name, buf, sz, t);
	if (rv == NNG_ENOTSUP) {
		rv = nni_setopt(tls_ep_opts, name, ep, buf, sz, t);
	}
	return (rv);
}

// public versions of option handlers here

int
nng_tls_dialer_getopt(
    nng_tls_dialer *d, const char *name, void *buf, size_t *szp)
{
	return (nni_tls_dialer_getopt(d, name, buf, szp, NNI_TYPE_OPAQUE));
}

int
nng_tls_dialer_setopt(
    nng_tls_dialer *d, const char *name, const void *buf, size_t sz)
{
	return (nni_tls_dialer_setopt(d, name, buf, sz, NNI_TYPE_OPAQUE));
}

void
nng_tls_listener_close(nng_tls_listener *l)
{
	tls_ep *ep = (void *) l;
	nni_tcp_listener_close(ep->tcp.l);
}

void
nng_tls_listener_free(nng_tls_listener *l)
{
	tls_ep *ep = (void *) l;
	if (ep != NULL) {
		nng_tls_listener_close(l);
		nng_tls_config_free(ep->cfg);
		nni_mtx_fini(&ep->lk);
		NNI_FREE_STRUCT(ep);
	}
}

int
nng_tls_listener_alloc(nng_tls_listener **lp)
{
	tls_ep *ep;
	int     rv;

	if ((rv = nni_init()) != 0) {
		return (rv);
	}
	if ((ep = NNI_ALLOC_STRUCT(ep)) == NULL) {
		return (NNG_ENOMEM);
	}
	nni_mtx_init(&ep->lk);

	if ((rv = nni_tcp_listener_init(&ep->tcp.l)) != 0) {
		nni_mtx_fini(&ep->lk);
		NNI_FREE_STRUCT(ep);
		return (rv);
	}
	if ((rv = nng_tls_config_alloc(&ep->cfg, NNG_TLS_MODE_SERVER)) != 0) {
		nni_tcp_listener_fini(ep->tcp.l);
		nni_mtx_fini(&ep->lk);
		NNI_FREE_STRUCT(ep);
		return (rv);
	}
	*lp = (void *) ep;
	return (0);
}

int
nng_tls_listener_listen(nng_tls_listener *l, nng_sockaddr *sa)
{
	tls_ep *ep = (void *) l;
	return (nni_tcp_listener_listen(ep->tcp.l, sa));
}

void
nng_tls_listener_accept(nng_tls_listener *l, nng_aio *aio)
{
	int      rv;
	nng_tls *tls;
	tls_ep * ep = (void *) l;

	if (nni_aio_begin(aio) != 0) {
		return;
	}
	if ((tls = NNI_ALLOC_STRUCT(tls)) == NULL) {
		nni_aio_finish_error(aio, NNG_ENOMEM);
		return;
	}
	if ((rv = nni_aio_init(&tls->aio, tls_conn_cb, tls)) != 0) {
		nni_aio_finish_error(aio, rv);
		NNI_FREE_STRUCT(tls);
		return;
	}
	tls->uaio = aio;

	// Save a copy of the TLS configuration.  This way we don't have
	// to ensure that the dialer outlives the connection, because the
	// only shared data is the configuration which is reference counted.
	nni_mtx_lock(&ep->lk);
	tls->cfg = ep->cfg;
	nng_tls_config_hold(tls->cfg);
	nni_mtx_unlock(&ep->lk);

	if ((rv = nni_aio_schedule(aio, tls_conn_cancel, tls)) != 0) {
		nni_aio_finish_error(aio, rv);
		nng_tls_free(tls);
		return;
	}

	nni_tcp_listener_accept(ep->tcp.l, tls->aio);
}

int
nni_tls_listener_getopt(
    nng_tls_listener *l, const char *name, void *buf, size_t *szp, nni_type t)
{
	int     rv;
	tls_ep *ep = (void *) l;

	rv = nni_tcp_listener_getopt(ep->tcp.l, name, buf, szp, t);
	if (rv == NNG_ENOTSUP) {
		rv = nni_getopt(tls_ep_opts, name, ep, buf, szp, t);
	}
	return (rv);
}

int
nni_tls_listener_setopt(nng_tls_listener *l, const char *name, const void *buf,
    size_t sz, nni_type t)
{
	int     rv;
	tls_ep *ep = (void *) l;

	rv = nni_tcp_listener_setopt(
	    ep != NULL ? ep->tcp.l : NULL, name, buf, sz, t);
	if (rv == NNG_ENOTSUP) {
		rv = nni_setopt(tls_ep_opts, name, ep, buf, sz, t);
	}
	return (rv);
}

// public versions of option handlers here

int
nng_tls_listener_getopt(
    nng_tls_listener *l, const char *name, void *buf, size_t *szp)
{
	return (nni_tls_listener_getopt(l, name, buf, szp, NNI_TYPE_OPAQUE));
}

int
nng_tls_listener_setopt(
    nng_tls_listener *l, const char *name, const void *buf, size_t sz)
{
	return (nni_tls_listener_setopt(l, name, buf, sz, NNI_TYPE_OPAQUE));
}
