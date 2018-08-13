//
// Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <ctype.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "core/nng_impl.h"
#include "supplemental/tls/tls.h"
#include "supplemental/tls/tls_api.h"

#include "http_api.h"

struct nng_http_client {
	nni_list        aios;
	nni_mtx         mtx;
	bool            closed;
	bool            resolving;
	nng_tls_config *tls;
	nni_aio *       aio;
	nng_sockaddr    sa;
	nni_tcp_dialer *dialer;
	char *          host;
	char *          port;
	nni_url *       url;
};

static void
http_dial_start(nni_http_client *c)
{
	nni_aio *aio;

	if ((aio = nni_list_first(&c->aios)) == NULL) {
		return;
	}
	c->resolving = true;
	nni_aio_set_input(c->aio, 0, &c->sa);
	nni_tcp_resolv(c->host, c->port, NNG_AF_UNSPEC, 0, c->aio);
}

static void
http_dial_cb(void *arg)
{
	nni_http_client *c = arg;
	nni_aio *        aio;
	int              rv;
	nni_tcp_conn *   tcp;
	nni_http_conn *  conn;

	nni_mtx_lock(&c->mtx);
	rv = nni_aio_result(c->aio);

	if ((aio = nni_list_first(&c->aios)) == NULL) {
		// User abandoned request, and no residuals left.
		nni_mtx_unlock(&c->mtx);
		if ((rv == 0) && !c->resolving) {
			tcp = nni_aio_get_output(c->aio, 0);
			nni_tcp_conn_fini(tcp);
		}
		return;
	}

	if (rv != 0) {
		nni_aio_list_remove(aio);
		http_dial_start(c);
		nni_mtx_unlock(&c->mtx);
		nni_aio_finish_error(aio, rv);
		return;
	}

	if (c->resolving) {
		// This was a DNS lookup -- advance to normal TCP connect.
		c->resolving = false;
		nni_tcp_dialer_dial(c->dialer, &c->sa, c->aio);
		nni_mtx_unlock(&c->mtx);
		return;
	}

	nni_aio_list_remove(aio);
	tcp = nni_aio_get_output(c->aio, 0);
	NNI_ASSERT(tcp != NULL);

	if (c->tls != NULL) {
		rv = nni_http_conn_init_tls(&conn, c->tls, tcp);
	} else {
		rv = nni_http_conn_init_tcp(&conn, tcp);
	}
	http_dial_start(c);
	nni_mtx_unlock(&c->mtx);

	if (rv != 0) {
		// the conn_init function will have already discard tcp.
		nni_aio_finish_error(aio, rv);
		return;
	}

	nni_aio_set_output(aio, 0, conn);
	nni_aio_finish(aio, 0, 0);
}

void
nni_http_client_fini(nni_http_client *c)
{
	nni_aio_fini(c->aio);
	nni_tcp_dialer_fini(c->dialer);
	nni_mtx_fini(&c->mtx);
#ifdef NNG_SUPP_TLS
	if (c->tls != NULL) {
		nni_tls_config_fini(c->tls);
	}
#endif
	nni_strfree(c->host);
	nni_strfree(c->port);

	NNI_FREE_STRUCT(c);
}

int
nni_http_client_init(nni_http_client **cp, const nni_url *url)
{
	int              rv;
	nni_http_client *c;

	if (strlen(url->u_hostname) == 0) {
		// We require a valid hostname.
		return (NNG_EADDRINVAL);
	}
	if ((strcmp(url->u_scheme, "http") != 0) &&
#ifdef NNG_SUPP_TLS
	    (strcmp(url->u_scheme, "https") != 0) &&
	    (strcmp(url->u_scheme, "wss") != 0) &&
#endif
	    (strcmp(url->u_scheme, "ws") != 0)) {
		return (NNG_EADDRINVAL);
	}

	if ((c = NNI_ALLOC_STRUCT(c)) == NULL) {
		return (NNG_ENOMEM);
	}
	nni_mtx_init(&c->mtx);
	nni_aio_list_init(&c->aios);
	if (((c->host = nni_strdup(url->u_hostname)) == NULL) ||
	    ((strlen(url->u_port) != 0) &&
	        ((c->port = nni_strdup(url->u_port)) == NULL))) {
		nni_http_client_fini(c);
		return (NNG_ENOMEM);
	}

#ifdef NNG_SUPP_TLS
	if ((strcmp(url->u_scheme, "https") == 0) ||
	    (strcmp(url->u_scheme, "wss") == 0)) {
		rv = nni_tls_config_init(&c->tls, NNG_TLS_MODE_CLIENT);
		if (rv != 0) {
			nni_http_client_fini(c);
			return (rv);
		}
		// Take the server name right from the client URL. We only
		// consider the name, as the port is never part of the
		// certificate.
		rv = nng_tls_config_server_name(c->tls, url->u_hostname);
		if (rv != 0) {
			nni_http_client_fini(c);
			return (rv);
		}

		// Note that the application has to supply the location of
		// certificates.  We could probably use a default based
		// on environment or common locations used by OpenSSL, but
		// as there is no way to *unload* the cert file, lets not
		// do that.  (We might want to consider a mode to reset.)
	}
#endif

	if (((rv = nni_tcp_dialer_init(&c->dialer)) != 0) ||
	    ((rv = nni_aio_init(&c->aio, http_dial_cb, c)) != 0)) {
		nni_http_client_fini(c);
		return (rv);
	}

	*cp = c;
	return (0);
}

int
nni_http_client_set_tls(nni_http_client *c, struct nng_tls_config *tls)
{
#ifdef NNG_SUPP_TLS
	struct nng_tls_config *old;
	nni_mtx_lock(&c->mtx);
	old    = c->tls;
	c->tls = tls;
	if (tls != NULL) {
		nni_tls_config_hold(tls);
	}
	nni_mtx_unlock(&c->mtx);
	if (old != NULL) {
		nni_tls_config_fini(old);
	}
	return (0);
#else
	NNI_ARG_UNUSED(c);
	NNI_ARG_UNUSED(tls);
	return (NNG_EINVAL);
#endif
}

int
nni_http_client_get_tls(nni_http_client *c, struct nng_tls_config **tlsp)
{
#ifdef NNG_SUPP_TLS
	nni_mtx_lock(&c->mtx);
	if (c->tls == NULL) {
		nni_mtx_unlock(&c->mtx);
		return (NNG_EINVAL);
	}
	*tlsp = c->tls;
	nni_mtx_unlock(&c->mtx);
	return (0);
#else
	NNI_ARG_UNUSED(c);
	NNI_ARG_UNUSED(tlsp);
	return (NNG_ENOTSUP);
#endif
}

static void
http_dial_cancel(nni_aio *aio, int rv)
{
	nni_http_client *c = nni_aio_get_prov_data(aio);
	nni_mtx_lock(&c->mtx);
	if (nni_aio_list_active(aio)) {
		nni_aio_list_remove(aio);
		nni_aio_finish_error(aio, rv);
	}
	if (nni_list_empty(&c->aios)) {
		nni_aio_abort(c->aio, rv);
	}
	nni_mtx_unlock(&c->mtx);
}

void
nni_http_client_connect(nni_http_client *c, nni_aio *aio)
{
	int rv;
	if (nni_aio_begin(aio) != 0) {
		return;
	}
	nni_mtx_lock(&c->mtx);
	if ((rv = nni_aio_schedule(aio, http_dial_cancel, c)) != 0) {
		nni_mtx_unlock(&c->mtx);
		nni_aio_finish_error(aio, rv);
		return;
	}
	nni_list_append(&c->aios, aio);
	if (nni_list_first(&c->aios) == aio) {
		http_dial_start(c);
	}
	nni_mtx_unlock(&c->mtx);
}
