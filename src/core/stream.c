//
// Copyright 2024 Staysail Systems, Inc. <info@staysail.tech>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

// This provides an abstraction for byte streams, allowing polymorphic
// use of them in rather flexible contexts.

#include <string.h>

#include "core/nng_impl.h"
#include <nng/supplemental/tls/tls.h>

#include "core/sockfd.h"
#include "core/tcp.h"
#include "supplemental/tls/tls_api.h"
#include "supplemental/websocket/websocket.h"

static struct {
	const char *scheme;
	int         (*dialer_alloc)(nng_stream_dialer **, const nng_url *);
	int         (*listener_alloc)(nng_stream_listener **, const nng_url *);

} stream_drivers[] = {
	{
	    .scheme         = "ipc",
	    .dialer_alloc   = nni_ipc_dialer_alloc,
	    .listener_alloc = nni_ipc_listener_alloc,
	},
#ifdef NNG_PLATFORM_POSIX
	{
	    .scheme         = "unix",
	    .dialer_alloc   = nni_ipc_dialer_alloc,
	    .listener_alloc = nni_ipc_listener_alloc,
	},
#endif
#ifdef NNG_HAVE_ABSTRACT_SOCKETS
	{
	    .scheme         = "abstract",
	    .dialer_alloc   = nni_ipc_dialer_alloc,
	    .listener_alloc = nni_ipc_listener_alloc,
	},
#endif
	{
	    .scheme         = "tcp",
	    .dialer_alloc   = nni_tcp_dialer_alloc,
	    .listener_alloc = nni_tcp_listener_alloc,
	},
	{
	    .scheme         = "tcp4",
	    .dialer_alloc   = nni_tcp_dialer_alloc,
	    .listener_alloc = nni_tcp_listener_alloc,
	},
#ifdef NNG_ENABLE_IPV6
	{
	    .scheme         = "tcp6",
	    .dialer_alloc   = nni_tcp_dialer_alloc,
	    .listener_alloc = nni_tcp_listener_alloc,
	},
#endif
	{
	    .scheme         = "tls+tcp",
	    .dialer_alloc   = nni_tls_dialer_alloc,
	    .listener_alloc = nni_tls_listener_alloc,
	},
	{
	    .scheme         = "tls+tcp4",
	    .dialer_alloc   = nni_tls_dialer_alloc,
	    .listener_alloc = nni_tls_listener_alloc,
	},
#ifdef NNG_ENABLE_IPV6
	{
	    .scheme         = "tls+tcp6",
	    .dialer_alloc   = nni_tls_dialer_alloc,
	    .listener_alloc = nni_tls_listener_alloc,
	},
#endif
	{
	    .scheme         = "ws",
	    .dialer_alloc   = nni_ws_dialer_alloc,
	    .listener_alloc = nni_ws_listener_alloc,
	},
	{
	    .scheme         = "ws4",
	    .dialer_alloc   = nni_ws_dialer_alloc,
	    .listener_alloc = nni_ws_listener_alloc,
	},
#ifdef NNG_ENABLE_IPV6
	{
	    .scheme         = "ws6",
	    .dialer_alloc   = nni_ws_dialer_alloc,
	    .listener_alloc = nni_ws_listener_alloc,
	},
#endif
	{
	    .scheme         = "wss",
	    .dialer_alloc   = nni_ws_dialer_alloc,
	    .listener_alloc = nni_ws_listener_alloc,
	},
#ifdef NNG_TRANSPORT_FDC
	{
	    .scheme         = "socket",
	    .dialer_alloc   = nni_sfd_dialer_alloc,
	    .listener_alloc = nni_sfd_listener_alloc,
	},
#endif
	{
	    .scheme = NULL,
	},
};

void
nng_stream_close(nng_stream *s)
{
	s->s_close(s);
}

void
nng_stream_free(nng_stream *s)
{
	if (s != NULL) {
		s->s_free(s);
	}
}

void
nng_stream_send(nng_stream *s, nng_aio *aio)
{
	s->s_send(s, aio);
}

void
nng_stream_recv(nng_stream *s, nng_aio *aio)
{
	s->s_recv(s, aio);
}

int
nni_stream_get(
    nng_stream *s, const char *nm, void *data, size_t *szp, nni_type t)
{
	return (s->s_get(s, nm, data, szp, t));
}

int
nni_stream_set(
    nng_stream *s, const char *nm, const void *data, size_t sz, nni_type t)
{
	return (s->s_set(s, nm, data, sz, t));
}

void
nng_stream_dialer_close(nng_stream_dialer *d)
{
	d->sd_close(d);
}

void
nng_stream_dialer_free(nng_stream_dialer *d)
{
	if (d != NULL) {
		d->sd_free(d);
	}
}

void
nng_stream_dialer_dial(nng_stream_dialer *d, nng_aio *aio)
{
	d->sd_dial(d, aio);
}

int
nng_stream_dialer_alloc_url(nng_stream_dialer **dp, const nng_url *url)
{
	int rv;

	if ((rv = nni_init()) != 0) {
		return (rv);
	}

	for (int i = 0; stream_drivers[i].scheme != NULL; i++) {
		if (strcmp(stream_drivers[i].scheme, url->u_scheme) == 0) {
			return (stream_drivers[i].dialer_alloc(dp, url));
		}
	}
	return (NNG_ENOTSUP);
}

int
nng_stream_dialer_alloc(nng_stream_dialer **dp, const char *uri)
{
	nng_url *url;
	int      rv;

	if ((rv = nni_init()) != 0) {
		return (rv);
	}
	if ((rv = nng_url_parse(&url, uri)) != 0) {
		return (rv);
	}
	rv = nng_stream_dialer_alloc_url(dp, url);
	nng_url_free(url);
	return (rv);
}

int
nni_stream_dialer_get(
    nng_stream_dialer *d, const char *nm, void *data, size_t *szp, nni_type t)
{
	return (d->sd_get(d, nm, data, szp, t));
}

int
nni_stream_dialer_set(nng_stream_dialer *d, const char *nm, const void *data,
    size_t sz, nni_type t)
{
	return (d->sd_set(d, nm, data, sz, t));
}

void
nng_stream_listener_close(nng_stream_listener *l)
{
	l->sl_close(l);
}
void
nng_stream_listener_free(nng_stream_listener *l)
{
	if (l != NULL) {
		l->sl_free(l);
	}
}
int
nng_stream_listener_listen(nng_stream_listener *l)
{
	return (l->sl_listen(l));
}

void
nng_stream_listener_accept(nng_stream_listener *l, nng_aio *aio)
{
	l->sl_accept(l, aio);
}

int
nni_stream_listener_get(nng_stream_listener *l, const char *nm, void *data,
    size_t *szp, nni_type t)
{
	return (l->sl_get(l, nm, data, szp, t));
}

int
nni_stream_listener_set(nng_stream_listener *l, const char *nm,
    const void *data, size_t sz, nni_type t)
{
	return (l->sl_set(l, nm, data, sz, t));
}

int
nng_stream_listener_alloc_url(nng_stream_listener **lp, const nng_url *url)
{
	int rv;

	if ((rv = nni_init()) != 0) {
		return (rv);
	}

	for (int i = 0; stream_drivers[i].scheme != NULL; i++) {
		if (strcmp(stream_drivers[i].scheme, url->u_scheme) == 0) {
			return (stream_drivers[i].listener_alloc(lp, url));
		}
	}
	return (NNG_ENOTSUP);
}

int
nng_stream_listener_alloc(nng_stream_listener **lp, const char *uri)
{
	nng_url *url;
	int      rv;

	if ((rv = nni_init()) != 0) {
		return (rv);
	}

	if ((rv = nng_url_parse(&url, uri)) != 0) {
		return (rv);
	}
	rv = nng_stream_listener_alloc_url(lp, url);
	nng_url_free(url);
	return (rv);
}

// Public stream options.

int
nng_stream_get(nng_stream *s, const char *n, void *v, size_t *szp)
{
	return (nni_stream_get(s, n, v, szp, NNI_TYPE_OPAQUE));
}

int
nng_stream_get_int(nng_stream *s, const char *n, int *v)
{
	return (nni_stream_get(s, n, v, NULL, NNI_TYPE_INT32));
}

int
nng_stream_get_bool(nng_stream *s, const char *n, bool *v)
{
	return (nni_stream_get(s, n, v, NULL, NNI_TYPE_BOOL));
}

int
nng_stream_get_size(nng_stream *s, const char *n, size_t *v)
{
	return (nni_stream_get(s, n, v, NULL, NNI_TYPE_SIZE));
}

int
nng_stream_get_uint64(nng_stream *s, const char *n, uint64_t *v)
{
	return (nni_stream_get(s, n, v, NULL, NNI_TYPE_UINT64));
}

int
nng_stream_get_string(nng_stream *s, const char *n, char **v)
{
	return (nni_stream_get(s, n, v, NULL, NNI_TYPE_STRING));
}

int
nng_stream_get_ptr(nng_stream *s, const char *n, void **v)
{
	return (nni_stream_get(s, n, v, NULL, NNI_TYPE_POINTER));
}

int
nng_stream_get_ms(nng_stream *s, const char *n, nng_duration *v)
{
	return (nni_stream_get(s, n, v, NULL, NNI_TYPE_DURATION));
}

int
nng_stream_get_addr(nng_stream *s, const char *n, nng_sockaddr *v)
{
	return (nni_stream_get(s, n, v, NULL, NNI_TYPE_SOCKADDR));
}

int
nng_stream_dialer_get(
    nng_stream_dialer *d, const char *n, void *v, size_t *szp)
{
	return (nni_stream_dialer_get(d, n, v, szp, NNI_TYPE_OPAQUE));
}

int
nng_stream_dialer_get_int(nng_stream_dialer *d, const char *n, int *v)
{
	return (nni_stream_dialer_get(d, n, v, NULL, NNI_TYPE_INT32));
}

int
nng_stream_dialer_get_bool(nng_stream_dialer *d, const char *n, bool *v)
{
	return (nni_stream_dialer_get(d, n, v, NULL, NNI_TYPE_BOOL));
}

int
nng_stream_dialer_get_size(nng_stream_dialer *d, const char *n, size_t *v)
{
	return (nni_stream_dialer_get(d, n, v, NULL, NNI_TYPE_SIZE));
}

int
nng_stream_dialer_get_uint64(nng_stream_dialer *d, const char *n, uint64_t *v)
{
	return (nni_stream_dialer_get(d, n, v, NULL, NNI_TYPE_UINT64));
}

int
nng_stream_dialer_get_string(nng_stream_dialer *d, const char *n, char **v)
{
	return (nni_stream_dialer_get(d, n, v, NULL, NNI_TYPE_STRING));
}

int
nng_stream_dialer_get_ptr(nng_stream_dialer *d, const char *n, void **v)
{
	return (nni_stream_dialer_get(d, n, v, NULL, NNI_TYPE_POINTER));
}

int
nng_stream_dialer_get_ms(nng_stream_dialer *d, const char *n, nng_duration *v)
{
	return (nni_stream_dialer_get(d, n, v, NULL, NNI_TYPE_DURATION));
}

int
nng_stream_dialer_get_addr(
    nng_stream_dialer *d, const char *n, nng_sockaddr *v)
{
	return (nni_stream_dialer_get(d, n, v, NULL, NNI_TYPE_SOCKADDR));
}

int
nng_stream_listener_get(
    nng_stream_listener *l, const char *n, void *v, size_t *szp)
{
	return (nni_stream_listener_get(l, n, v, szp, NNI_TYPE_OPAQUE));
}

int
nng_stream_listener_get_int(nng_stream_listener *l, const char *n, int *v)
{
	return (nni_stream_listener_get(l, n, v, NULL, NNI_TYPE_INT32));
}

int
nng_stream_listener_get_bool(nng_stream_listener *l, const char *n, bool *v)
{
	return (nni_stream_listener_get(l, n, v, NULL, NNI_TYPE_BOOL));
}

int
nng_stream_listener_get_size(nng_stream_listener *l, const char *n, size_t *v)
{
	return (nni_stream_listener_get(l, n, v, NULL, NNI_TYPE_SIZE));
}

int
nng_stream_listener_get_uint64(
    nng_stream_listener *l, const char *n, uint64_t *v)
{
	return (nni_stream_listener_get(l, n, v, NULL, NNI_TYPE_UINT64));
}

int
nng_stream_listener_get_string(nng_stream_listener *l, const char *n, char **v)
{
	return (nni_stream_listener_get(l, n, v, NULL, NNI_TYPE_STRING));
}

int
nng_stream_listener_get_ptr(nng_stream_listener *l, const char *n, void **v)
{
	return (nni_stream_listener_get(l, n, v, NULL, NNI_TYPE_POINTER));
}

int
nng_stream_listener_get_ms(
    nng_stream_listener *l, const char *n, nng_duration *v)
{
	return (nni_stream_listener_get(l, n, v, NULL, NNI_TYPE_DURATION));
}

int
nng_stream_listener_get_addr(
    nng_stream_listener *l, const char *n, nng_sockaddr *v)
{
	return (nni_stream_listener_get(l, n, v, NULL, NNI_TYPE_SOCKADDR));
}

int
nng_stream_set(nng_stream *s, const char *n, const void *v, size_t sz)
{
	return (nni_stream_set(s, n, v, sz, NNI_TYPE_OPAQUE));
}

int
nng_stream_set_int(nng_stream *s, const char *n, int v)
{
	return (nni_stream_set(s, n, &v, sizeof(v), NNI_TYPE_INT32));
}

int
nng_stream_set_bool(nng_stream *s, const char *n, bool v)
{
	return (nni_stream_set(s, n, &v, sizeof(v), NNI_TYPE_BOOL));
}

int
nng_stream_set_size(nng_stream *s, const char *n, size_t v)
{
	return (nni_stream_set(s, n, &v, sizeof(v), NNI_TYPE_SIZE));
}

int
nng_stream_set_uint64(nng_stream *s, const char *n, uint64_t v)
{
	return (nni_stream_set(s, n, &v, sizeof(v), NNI_TYPE_UINT64));
}

int
nng_stream_set_ms(nng_stream *s, const char *n, nng_duration v)
{
	return (nni_stream_set(s, n, &v, sizeof(v), NNI_TYPE_DURATION));
}

int
nng_stream_set_ptr(nng_stream *s, const char *n, void *v)
{
	return (nni_stream_set(s, n, &v, sizeof(v), NNI_TYPE_POINTER));
}

int
nng_stream_set_string(nng_stream *s, const char *n, const char *v)
{
	return (nni_stream_set(
	    s, n, v, v == NULL ? 0 : strlen(v) + 1, NNI_TYPE_STRING));
}

#ifndef NNG_ELIDE_DEPRECATED
int
nng_stream_set_addr(nng_stream *s, const char *n, const nng_sockaddr *v)
{
	return (nni_stream_set(s, n, v, sizeof(*v), NNI_TYPE_SOCKADDR));
}
#endif

int
nng_stream_dialer_set(
    nng_stream_dialer *d, const char *n, const void *v, size_t sz)
{
	return (nni_stream_dialer_set(d, n, v, sz, NNI_TYPE_OPAQUE));
}

int
nng_stream_dialer_set_int(nng_stream_dialer *d, const char *n, int v)
{
	return (nni_stream_dialer_set(d, n, &v, sizeof(v), NNI_TYPE_INT32));
}

int
nng_stream_dialer_set_bool(nng_stream_dialer *d, const char *n, bool v)
{
	return (nni_stream_dialer_set(d, n, &v, sizeof(v), NNI_TYPE_BOOL));
}

int
nng_stream_dialer_set_size(nng_stream_dialer *d, const char *n, size_t v)
{
	return (nni_stream_dialer_set(d, n, &v, sizeof(v), NNI_TYPE_SIZE));
}

int
nng_stream_dialer_set_uint64(nng_stream_dialer *d, const char *n, uint64_t v)
{
	return (nni_stream_dialer_set(d, n, &v, sizeof(v), NNI_TYPE_UINT64));
}

int
nng_stream_dialer_set_ms(nng_stream_dialer *d, const char *n, nng_duration v)
{
	return (nni_stream_dialer_set(d, n, &v, sizeof(v), NNI_TYPE_DURATION));
}

int
nng_stream_dialer_set_ptr(nng_stream_dialer *d, const char *n, void *v)
{
	return (nni_stream_dialer_set(d, n, &v, sizeof(v), NNI_TYPE_POINTER));
}

int
nng_stream_dialer_set_string(
    nng_stream_dialer *d, const char *n, const char *v)
{
	return (nni_stream_dialer_set(
	    d, n, v, v == NULL ? 0 : strlen(v) + 1, NNI_TYPE_STRING));
}

int
nng_stream_dialer_set_addr(
    nng_stream_dialer *d, const char *n, const nng_sockaddr *v)
{
	return (nni_stream_dialer_set(d, n, v, sizeof(*v), NNI_TYPE_SOCKADDR));
}

int
nng_stream_listener_set(
    nng_stream_listener *l, const char *n, const void *v, size_t sz)
{
	return (nni_stream_listener_set(l, n, v, sz, NNI_TYPE_OPAQUE));
}

int
nng_stream_listener_set_int(nng_stream_listener *l, const char *n, int v)
{
	return (nni_stream_listener_set(l, n, &v, sizeof(v), NNI_TYPE_INT32));
}

int
nng_stream_listener_set_bool(nng_stream_listener *l, const char *n, bool v)
{
	return (nni_stream_listener_set(l, n, &v, sizeof(v), NNI_TYPE_BOOL));
}

int
nng_stream_listener_set_size(nng_stream_listener *l, const char *n, size_t v)
{
	return (nni_stream_listener_set(l, n, &v, sizeof(v), NNI_TYPE_SIZE));
}

int
nng_stream_listener_set_uint64(
    nng_stream_listener *l, const char *n, uint64_t v)
{
	return (nni_stream_listener_set(l, n, &v, sizeof(v), NNI_TYPE_UINT64));
}

int
nng_stream_listener_set_ms(
    nng_stream_listener *l, const char *n, nng_duration v)
{
	return (
	    nni_stream_listener_set(l, n, &v, sizeof(v), NNI_TYPE_DURATION));
}

int
nng_stream_listener_set_ptr(nng_stream_listener *l, const char *n, void *v)
{
	return (
	    nni_stream_listener_set(l, n, &v, sizeof(v), NNI_TYPE_POINTER));
}

int
nng_stream_listener_set_string(
    nng_stream_listener *l, const char *n, const char *v)
{
	return (nni_stream_listener_set(
	    l, n, v, v == NULL ? 0 : strlen(v) + 1, NNI_TYPE_STRING));
}

int
nng_stream_listener_set_addr(
    nng_stream_listener *l, const char *n, const nng_sockaddr *v)
{
	return (
	    nni_stream_listener_set(l, n, v, sizeof(*v), NNI_TYPE_SOCKADDR));
}
