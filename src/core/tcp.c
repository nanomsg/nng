//
// Copyright 2024 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
// Copyright 2019 Devolutions <info@devolutions.net>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "nng_impl.h"
#include "tcp.h"
#include "url.h"

typedef struct {
	nng_stream_dialer ops;
	char              host[256];
	uint16_t          port;
	int               af; // address family
	bool              closed;
	nng_sockaddr      sa;
	nni_tcp_dialer   *d;      // platform dialer implementation
	nni_aio           resaio; // resolver aio
	nni_aio           conaio; // platform connection aio
	nni_list          conaios;
	nni_mtx           mtx;
	nni_resolv_item   resolv;
} tcp_dialer;

static void
tcp_dial_cancel(nni_aio *aio, void *arg, nng_err rv)
{
	tcp_dialer *d = arg;

	nni_mtx_lock(&d->mtx);
	if (nni_aio_list_active(aio)) {
		nni_aio_list_remove(aio);
		nni_aio_finish_error(aio, rv);

		if (nni_list_empty(&d->conaios)) {
			nni_aio_abort(&d->conaio, NNG_ECANCELED);
			nni_aio_abort(&d->resaio, NNG_ECANCELED);
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
	memset(&d->resolv, 0, sizeof(d->resolv));
	d->resolv.ri_family  = d->af;
	d->resolv.ri_passive = false;
	d->resolv.ri_host    = d->host;
	d->resolv.ri_port    = d->port;
	d->resolv.ri_sa      = &d->sa;

	nni_resolv(&d->resolv, &d->resaio);
}

static void
tcp_dial_res_cb(void *arg)
{
	tcp_dialer *d = arg;
	nni_aio    *aio;
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

	if ((rv = nni_aio_result(&d->resaio)) != 0) {
		nni_list_remove(&d->conaios, aio);
		nni_aio_finish_error(aio, rv);

		// try DNS again for next connection...
		tcp_dial_start_next(d);

	} else {
		nni_tcp_dial(d->d, &d->sa, &d->conaio);
	}

	nni_mtx_unlock(&d->mtx);
}

static void
tcp_dial_con_cb(void *arg)
{
	tcp_dialer *d = arg;
	nng_aio    *aio;
	int         rv;

	nni_mtx_lock(&d->mtx);
	rv = nni_aio_result(&d->conaio);
	if ((d->closed) || ((aio = nni_list_first(&d->conaios)) == NULL)) {
		if (rv == 0) {
			// Make sure we discard the underlying connection.
			nng_stream_close(nni_aio_get_output(&d->conaio, 0));
			nng_stream_stop(nni_aio_get_output(&d->conaio, 0));
			nng_stream_free(nni_aio_get_output(&d->conaio, 0));
			nni_aio_set_output(&d->conaio, 0, NULL);
		}
		nni_mtx_unlock(&d->mtx);
		return;
	}
	nni_list_remove(&d->conaios, aio);
	if (rv != 0) {
		nni_aio_finish_error(aio, rv);
	} else {
		nni_aio_set_output(aio, 0, nni_aio_get_output(&d->conaio, 0));
		nni_aio_finish(aio, 0, 0);
	}

	tcp_dial_start_next(d);
	nni_mtx_unlock(&d->mtx);
}

static void
tcp_dialer_close(void *arg)
{
	tcp_dialer *d = arg;
	nni_aio    *aio;

	if (d != NULL) {
		nni_mtx_lock(&d->mtx);
		d->closed = true;
		while ((aio = nni_list_first(&d->conaios)) != NULL) {
			nni_list_remove(&d->conaios, aio);
			nni_aio_finish_error(aio, NNG_ECLOSED);
		}
		nni_tcp_dialer_close(d->d);
		nni_mtx_unlock(&d->mtx);
	}
}

static void
tcp_dialer_stop(void *arg)
{
	tcp_dialer *d = arg;
	if (d != NULL) {
		nni_tcp_dialer_stop(d->d);
	}
}

static void
tcp_dialer_free(void *arg)
{
	tcp_dialer *d = arg;

	if (d == NULL) {
		return;
	}

	nni_aio_stop(&d->resaio);
	nni_aio_stop(&d->conaio);
	nni_aio_fini(&d->resaio);
	nni_aio_fini(&d->conaio);

	if (d->d != NULL) {
		nni_tcp_dialer_close(d->d);
		nni_tcp_dialer_fini(d->d);
	}
	nni_mtx_fini(&d->mtx);
	NNI_FREE_STRUCT(d);
}

static void
tcp_dialer_dial(void *arg, nng_aio *aio)
{
	tcp_dialer *d = arg;

	nni_aio_reset(aio);
	nni_mtx_lock(&d->mtx);
	if (d->closed) {
		nni_mtx_unlock(&d->mtx);
		nni_aio_finish_error(aio, NNG_ECLOSED);
		return;
	}
	if (!nni_aio_start(aio, tcp_dial_cancel, d)) {
		nni_mtx_unlock(&d->mtx);
		return;
	}
	nni_list_append(&d->conaios, aio);
	if (nni_list_first(&d->conaios) == aio) {
		tcp_dial_start_next(d);
	}
	nni_mtx_unlock(&d->mtx);
}

static nng_err
tcp_dialer_get(void *arg, const char *name, void *buf, size_t *szp, nni_type t)
{
	tcp_dialer *d = arg;
	return (nni_tcp_dialer_get(d->d, name, buf, szp, t));
}

static nng_err
tcp_dialer_set(
    void *arg, const char *name, const void *buf, size_t sz, nni_type t)
{
	tcp_dialer *d = arg;
	return (nni_tcp_dialer_set(d->d, name, buf, sz, t));
}

static nng_err
tcp_dialer_alloc(tcp_dialer **dp)
{
	nng_err     rv;
	tcp_dialer *d;

	if ((d = NNI_ALLOC_STRUCT(d)) == NULL) {
		return (NNG_ENOMEM);
	}

	nni_mtx_init(&d->mtx);
	nni_aio_list_init(&d->conaios);
	nni_aio_init(&d->resaio, tcp_dial_res_cb, d);
	nni_aio_init(&d->conaio, tcp_dial_con_cb, d);

	if ((rv = nni_tcp_dialer_init(&d->d)) != NNG_OK) {
		tcp_dialer_free(d);
		return (rv);
	}

	d->ops.sd_close = tcp_dialer_close;
	d->ops.sd_free  = tcp_dialer_free;
	d->ops.sd_stop  = tcp_dialer_stop;
	d->ops.sd_dial  = tcp_dialer_dial;
	d->ops.sd_get   = tcp_dialer_get;
	d->ops.sd_set   = tcp_dialer_set;

	*dp = d;
	return (NNG_OK);
}

nng_err
nni_tcp_dialer_alloc(nng_stream_dialer **dp, const nng_url *url)
{
	tcp_dialer *d;
	int         rv;

	if ((rv = tcp_dialer_alloc(&d)) != NNG_OK) {
		return (rv);
	}

	if ((url->u_port == 0) || strlen(url->u_hostname) == 0 ||
	    strlen(url->u_hostname) >= sizeof(d->host)) {
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

	snprintf(d->host, sizeof(d->host), "%s", url->u_hostname);
	d->port = url->u_port;

	*dp = (void *) d;
	return (NNG_OK);
}
