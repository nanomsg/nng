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
	nni_list               aios;
	nni_mtx                mtx;
	bool                   closed;
	struct nng_tls_config *tls;
	nni_aio *              connaio;
	nni_plat_tcp_ep *      tep;
};

static void
http_conn_start(nni_http_client *c)
{
	nni_plat_tcp_ep_connect(c->tep, c->connaio);
}

static void
http_conn_done(void *arg)
{
	nni_http_client *  c = arg;
	nni_aio *          aio;
	int                rv;
	nni_plat_tcp_pipe *p;
	nni_http_conn *    conn;

	nni_mtx_lock(&c->mtx);
	rv = nni_aio_result(c->connaio);
	p  = rv == 0 ? nni_aio_get_output(c->connaio, 0) : NULL;
	if ((aio = nni_list_first(&c->aios)) == NULL) {
		if (p != NULL) {
			nni_plat_tcp_pipe_fini(p);
		}
		nni_mtx_unlock(&c->mtx);
		return;
	}
	nni_aio_list_remove(aio);

	if (rv != 0) {
		nni_aio_finish_error(aio, rv);
		nni_mtx_unlock(&c->mtx);
		return;
	}

	if (c->tls != NULL) {
		rv = nni_http_conn_init_tls(&conn, c->tls, p);
	} else {
		rv = nni_http_conn_init_tcp(&conn, p);
	}
	if (rv != 0) {
		nni_aio_finish_error(aio, rv);
		nni_mtx_unlock(&c->mtx);
		return;
	}

	nni_aio_set_output(aio, 0, conn);
	nni_aio_finish(aio, 0, 0);

	if (!nni_list_empty(&c->aios)) {
		http_conn_start(c);
	}
	nni_mtx_unlock(&c->mtx);
}

void
nni_http_client_fini(nni_http_client *c)
{
	nni_aio_fini(c->connaio);
	nni_plat_tcp_ep_fini(c->tep);
	nni_mtx_fini(&c->mtx);
#ifdef NNG_SUPP_TLS
	if (c->tls != NULL) {
		nni_tls_config_fini(c->tls);
	}
#endif
	NNI_FREE_STRUCT(c);
}

int
nni_http_client_init(nni_http_client **cp, const nni_url *url)
{
	int              rv;
	nni_http_client *c;
	nni_aio *        aio;
	nni_sockaddr     sa;
	char *           host;
	char *           port;

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

	// For now we are looking up the address.  We would really like
	// to do this later, but we need TcP support for this.  One
	// imagines the ability to create a tcp dialer that does the
	// necessary DNS lookups, etc. all asynchronously.
	if ((rv = nni_aio_init(&aio, NULL, NULL)) != 0) {
		return (rv);
	}
	nni_aio_set_input(aio, 0, &sa);
	host = (strlen(url->u_hostname) != 0) ? url->u_hostname : NULL;
	port = (strlen(url->u_port) != 0) ? url->u_port : NULL;
	nni_plat_tcp_resolv(host, port, NNG_AF_UNSPEC, false, aio);
	nni_aio_wait(aio);
	rv = nni_aio_result(aio);
	nni_aio_fini(aio);
	if (rv != 0) {
		return (rv);
	}

	if ((c = NNI_ALLOC_STRUCT(c)) == NULL) {
		return (NNG_ENOMEM);
	}
	nni_mtx_init(&c->mtx);
	nni_aio_list_init(&c->aios);

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

	rv = nni_plat_tcp_ep_init(&c->tep, NULL, &sa, NNI_EP_MODE_DIAL);
	if (rv != 0) {
		nni_http_client_fini(c);
		return (rv);
	}

	if ((rv = nni_aio_init(&c->connaio, http_conn_done, c)) != 0) {
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
http_connect_cancel(nni_aio *aio, int rv)
{
	nni_http_client *c = nni_aio_get_prov_data(aio);
	nni_mtx_lock(&c->mtx);
	if (nni_aio_list_active(aio)) {
		nni_aio_list_remove(aio);
		nni_aio_finish_error(aio, rv);
	}
	if (nni_list_empty(&c->aios)) {
		nni_aio_abort(c->connaio, rv);
	}
	nni_mtx_unlock(&c->mtx);
}

void
nni_http_client_connect(nni_http_client *c, nni_aio *aio)
{
	if (nni_aio_begin(aio) != 0) {
		return;
	}
	nni_mtx_lock(&c->mtx);
	nni_aio_schedule(aio, http_connect_cancel, aio);
	nni_list_append(&c->aios, aio);
	if (nni_list_first(&c->aios) == aio) {
		http_conn_start(c);
	}
	nni_mtx_unlock(&c->mtx);
}
