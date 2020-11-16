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

#include <stdint.h>
#include <string.h>

#include <nng/nng.h>

#include "core/nng_impl.h"
#include "core/tcp.h"

typedef struct {
	nng_stream_dialer ops;
	char *            host;
	char *            port;
	int               af; // address family
	bool              closed;
	nng_sockaddr      sa;
	nni_tcp_dialer *  d;      // platform dialer implementation
	nni_aio *         resaio; // resolver aio
	nni_aio *         conaio; // platform connection aio
	nni_list          conaios;
	nni_mtx           mtx;
} tcp_dialer;

static void
tcp_dial_cancel(nni_aio *aio, void *arg, int rv)
{
	tcp_dialer *d = arg;

	nni_mtx_lock(&d->mtx);
	if (nni_aio_list_active(aio)) {
		nni_aio_list_remove(aio);
		nni_aio_finish_error(aio, rv);

		if (nni_list_empty(&d->conaios)) {
			nni_aio_abort(d->conaio, NNG_ECANCELED);
			nni_aio_abort(d->resaio, NNG_ECANCELED);
		}
	}
	nni_mtx_unlock(&d->mtx);
}

static void
tcp_dial_start_next(tcp_dialer *d)
{
	if (nni_list_empty(&d->conaios)) {
		return;
	}
	nni_resolv_ip(d->host, d->port, d->af, false, &d->sa, d->resaio);
}

static void
tcp_dial_res_cb(void *arg)
{
	tcp_dialer *d = arg;
	nni_aio *   aio;
	int         rv;

	nni_mtx_lock(&d->mtx);
	if (d->closed || ((aio = nni_list_first(&d->conaios)) == NULL)) {
		// ignore this.
		while ((aio = nni_list_first(&d->conaios)) != NULL) {
			nni_list_remove(&d->conaios, aio);
			nni_aio_finish_error(aio, NNG_ECLOSED);
		}
		nni_mtx_unlock(&d->mtx);
		return;
	}

	if ((rv = nni_aio_result(d->resaio)) != 0) {
		nni_list_remove(&d->conaios, aio);
		nni_aio_finish_error(aio, rv);

		// try DNS again for next connection...
		tcp_dial_start_next(d);

	} else {
		nni_tcp_dial(d->d, &d->sa, d->conaio);
	}

	nni_mtx_unlock(&d->mtx);
}

static void
tcp_dial_con_cb(void *arg)
{
	tcp_dialer *d = arg;
	nng_aio *   aio;
	int         rv;

	nni_mtx_lock(&d->mtx);
	rv = nni_aio_result(d->conaio);
	if ((d->closed) || ((aio = nni_list_first(&d->conaios)) == NULL)) {
		if (rv == 0) {
			// Make sure we discard the underlying connection.
			nng_stream_free(nni_aio_get_output(d->conaio, 0));
			nni_aio_set_output(d->conaio, 0, NULL);
		}
		nni_mtx_unlock(&d->mtx);
		return;
	}
	nni_list_remove(&d->conaios, aio);
	if (rv != 0) {
		nni_aio_finish_error(aio, rv);
	} else {
		nni_aio_set_output(aio, 0, nni_aio_get_output(d->conaio, 0));
		nni_aio_finish(aio, 0, 0);
	}

	tcp_dial_start_next(d);
	nni_mtx_unlock(&d->mtx);
}

static void
tcp_dialer_close(void *arg)
{
	tcp_dialer *d = arg;
	nni_aio *   aio;
	nni_mtx_lock(&d->mtx);
	d->closed = true;
	while ((aio = nni_list_first(&d->conaios)) != NULL) {
		nni_list_remove(&d->conaios, aio);
		nni_aio_finish_error(aio, NNG_ECLOSED);
	}
	nni_tcp_dialer_close(d->d);
	nni_mtx_unlock(&d->mtx);
}

static void
tcp_dialer_free(void *arg)
{
	tcp_dialer *d = arg;

	if (d == NULL) {
		return;
	}

	nni_aio_stop(d->resaio);
	nni_aio_stop(d->conaio);
	nni_aio_free(d->resaio);
	nni_aio_free(d->conaio);

	if (d->d != NULL) {
		nni_tcp_dialer_close(d->d);
		nni_tcp_dialer_fini(d->d);
	}
	nni_mtx_fini(&d->mtx);
	nni_strfree(d->host);
	nni_strfree(d->port);
	NNI_FREE_STRUCT(d);
}

static void
tcp_dialer_dial(void *arg, nng_aio *aio)
{
	tcp_dialer *d = arg;
	int         rv;
	if (nni_aio_begin(aio) != 0) {
		return;
	}
	nni_mtx_lock(&d->mtx);
	if (d->closed) {
		nni_mtx_unlock(&d->mtx);
		nni_aio_finish_error(aio, NNG_ECLOSED);
		return;
	}
	if ((rv = nni_aio_schedule(aio, tcp_dial_cancel, d)) != 0) {
		nni_mtx_unlock(&d->mtx);
		nni_aio_finish_error(aio, rv);
		return;
	}
	nni_list_append(&d->conaios, aio);
	if (nni_list_first(&d->conaios) == aio) {
		tcp_dial_start_next(d);
	}
	nni_mtx_unlock(&d->mtx);
}

static int
tcp_dialer_get(
    void *arg, const char *name, void *buf, size_t *szp, nni_type t)
{
	tcp_dialer *d = arg;
	return (nni_tcp_dialer_get(d->d, name, buf, szp, t));
}

static int
tcp_dialer_set(
    void *arg, const char *name, const void *buf, size_t sz, nni_type t)
{
	tcp_dialer *d = arg;
	return (nni_tcp_dialer_set(d->d, name, buf, sz, t));
}

static int
tcp_dialer_alloc(tcp_dialer **dp)
{
	int         rv;
	tcp_dialer *d;

	if ((d = NNI_ALLOC_STRUCT(d)) == NULL) {
		return (NNG_ENOMEM);
	}

	nni_mtx_init(&d->mtx);
	nni_aio_list_init(&d->conaios);

	if (((rv = nni_aio_alloc(&d->resaio, tcp_dial_res_cb, d)) != 0) ||
	    ((rv = nni_aio_alloc(&d->conaio, tcp_dial_con_cb, d)) != 0) ||
	    ((rv = nni_tcp_dialer_init(&d->d)) != 0)) {
		tcp_dialer_free(d);
		return (rv);
	}

	d->ops.sd_close = tcp_dialer_close;
	d->ops.sd_free  = tcp_dialer_free;
	d->ops.sd_dial  = tcp_dialer_dial;
	d->ops.sd_get   = tcp_dialer_get;
	d->ops.sd_set   = tcp_dialer_set;

	*dp = d;
	return (0);
}

int
nni_tcp_dialer_alloc(nng_stream_dialer **dp, const nng_url *url)
{
	tcp_dialer *d;
	int         rv;
	const char *p;

	if ((rv = nni_init()) != 0) {
		return (rv);
	}

	if ((rv = tcp_dialer_alloc(&d)) != 0) {
		return (rv);
	}

	if (((p = url->u_port) == NULL) || (strlen(p) == 0)) {
		p = nni_url_default_port(url->u_scheme);
	}

	if ((strlen(p) == 0) || (strlen(url->u_hostname) == 0)) {
		// Dialer needs both a destination hostname and port.
		tcp_dialer_free(d);
		return (NNG_EADDRINVAL);
	}

	if (strchr(url->u_scheme, '4') != NULL) {
		d->af = NNG_AF_INET;
	} else if (strchr(url->u_scheme, '6') != NULL) {
		d->af = NNG_AF_INET6;
	} else {
		d->af = NNG_AF_UNSPEC;
	}

	if (((d->host = nng_strdup(url->u_hostname)) == NULL) ||
	    ((d->port = nng_strdup(p)) == NULL)) {
		tcp_dialer_free(d);
		return (NNG_ENOMEM);
	}

	*dp = (void *) d;
	return (0);
}

typedef struct {
	nng_stream_listener ops;
	nni_tcp_listener *  l;
	nng_sockaddr        sa;
} tcp_listener;

static void
tcp_listener_close(void *arg)
{
	tcp_listener *l = arg;
	nni_tcp_listener_close(l->l);
}

static void
tcp_listener_free(void *arg)
{
	tcp_listener *l = arg;
	nni_tcp_listener_fini(l->l);
	NNI_FREE_STRUCT(l);
}

static int
tcp_listener_listen(void *arg)
{
	tcp_listener *l = arg;
	return (nni_tcp_listener_listen(l->l, &l->sa));
}

static void
tcp_listener_accept(void *arg, nng_aio *aio)
{
	tcp_listener *l = arg;
	nni_tcp_listener_accept(l->l, aio);
}

static int
tcp_listener_get_port(void *arg, void *buf, size_t *szp, nni_type t)
{
	tcp_listener *l = arg;
	int           rv;
	nng_sockaddr  sa;
	size_t        sz;
	int           port;
	uint8_t *     paddr;

	sz = sizeof(sa);
	rv = nni_tcp_listener_get(
	    l->l, NNG_OPT_LOCADDR, &sa, &sz, NNI_TYPE_SOCKADDR);
	if (rv != 0) {
		return (rv);
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

	if (paddr == NULL) {
		return (NNG_ESTATE);
	}

	NNI_GET16(paddr, port);
	return (nni_copyout_int(port, buf, szp, t));
}

static int
tcp_listener_get(
    void *arg, const char *name, void *buf, size_t *szp, nni_type t)
{
	tcp_listener *l = arg;
	if (strcmp(name, NNG_OPT_TCP_BOUND_PORT) == 0) {
		return (tcp_listener_get_port(l, buf, szp, t));
	}
	return (nni_tcp_listener_get(l->l, name, buf, szp, t));
}

static int
tcp_listener_set(
    void *arg, const char *name, const void *buf, size_t sz, nni_type t)
{
	tcp_listener *l = arg;
	return (nni_tcp_listener_set(l->l, name, buf, sz, t));
}

static int
tcp_listener_alloc_addr(nng_stream_listener **lp, const nng_sockaddr *sa)
{
	tcp_listener *l;
	int           rv;

	if ((l = NNI_ALLOC_STRUCT(l)) == NULL) {
		return (NNG_ENOMEM);
	}
	if ((rv = nni_tcp_listener_init(&l->l)) != 0) {
		NNI_FREE_STRUCT(l);
		return (rv);
	}
	l->sa = *sa;

	l->ops.sl_free   = tcp_listener_free;
	l->ops.sl_close  = tcp_listener_close;
	l->ops.sl_listen = tcp_listener_listen;
	l->ops.sl_accept = tcp_listener_accept;
	l->ops.sl_get    = tcp_listener_get;
	l->ops.sl_set    = tcp_listener_set;

	*lp = (void *) l;
	return (0);
}

int
nni_tcp_listener_alloc(nng_stream_listener **lp, const nng_url *url)
{
	nni_aio *    aio;
	int          af;
	int          rv;
	nng_sockaddr sa;
	const char * h;

	if ((rv = nni_init()) != 0) {
		return (rv);
	}
	if (strchr(url->u_scheme, '4') != NULL) {
		af = NNG_AF_INET;
	} else if (strchr(url->u_scheme, '6') != NULL) {
		af = NNG_AF_INET6;
	} else {
		af = NNG_AF_UNSPEC;
	}

	if ((rv = nng_aio_alloc(&aio, NULL, NULL)) != 0) {
		return (rv);
	}

	h = url->u_hostname;

	// Wildcard special case, which means bind to INADDR_ANY.
	if ((h != NULL) && ((strcmp(h, "*") == 0) || (strcmp(h, "") == 0))) {
		h = NULL;
	}
	nni_resolv_ip(h, url->u_port, af, true, &sa, aio);
	nni_aio_wait(aio);

	if ((rv = nni_aio_result(aio)) != 0) {
		nni_aio_free(aio);
		return (rv);
	}
	nni_aio_free(aio);

	return (tcp_listener_alloc_addr(lp, &sa));
}
