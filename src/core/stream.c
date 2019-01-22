//
// Copyright 2019 Staysail Systems, Inc. <info@staysail.tech>
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

#include "core/tcp.h"
#include "supplemental/tls/tls_api.h"
#include "supplemental/websocket/websocket.h"

static struct {
	const char *scheme;
	int (*dialer_alloc)(nng_stream_dialer **, const nng_url *);
	int (*listener_alloc)(nng_stream_listener **, const nng_url *);
	int (*checkopt)(const char *, const void *, size_t, nni_type);

} stream_drivers[] = {
	{
	    .scheme         = "ipc",
	    .dialer_alloc   = nni_ipc_dialer_alloc,
	    .listener_alloc = nni_ipc_listener_alloc,
	    .checkopt       = nni_ipc_checkopt,
	},
	{
	    .scheme         = "tcp",
	    .dialer_alloc   = nni_tcp_dialer_alloc,
	    .listener_alloc = nni_tcp_listener_alloc,
	    .checkopt       = nni_tcp_checkopt,
	},
	{
	    .scheme         = "tcp4",
	    .dialer_alloc   = nni_tcp_dialer_alloc,
	    .listener_alloc = nni_tcp_listener_alloc,
	    .checkopt       = nni_tcp_checkopt,
	},
	{
	    .scheme         = "tcp6",
	    .dialer_alloc   = nni_tcp_dialer_alloc,
	    .listener_alloc = nni_tcp_listener_alloc,
	    .checkopt       = nni_tcp_checkopt,
	},
	{
	    .scheme         = "tls+tcp",
	    .dialer_alloc   = nni_tls_dialer_alloc,
	    .listener_alloc = nni_tls_listener_alloc,
	    .checkopt       = nni_tls_checkopt,
	},
	{
	    .scheme         = "tls+tcp4",
	    .dialer_alloc   = nni_tls_dialer_alloc,
	    .listener_alloc = nni_tls_listener_alloc,
	    .checkopt       = nni_tls_checkopt,
	},
	{
	    .scheme         = "tls+tcp6",
	    .dialer_alloc   = nni_tls_dialer_alloc,
	    .listener_alloc = nni_tls_listener_alloc,
	    .checkopt       = nni_tls_checkopt,
	},
	{
	    .scheme         = "ws",
	    .dialer_alloc   = nni_ws_dialer_alloc,
	    .listener_alloc = nni_ws_listener_alloc,
	    .checkopt       = nni_ws_checkopt,
	},
	{
	    .scheme         = "wss",
	    .dialer_alloc   = nni_ws_dialer_alloc,
	    .listener_alloc = nni_ws_listener_alloc,
	    .checkopt       = nni_ws_checkopt,
	},
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
nni_stream_getx(
    nng_stream *s, const char *nm, void *data, size_t *szp, nni_type t)
{
	return (s->s_getx(s, nm, data, szp, t));
}

int
nni_stream_setx(
    nng_stream *s, const char *nm, const void *data, size_t sz, nni_type t)
{
	return (s->s_setx(s, nm, data, sz, t));
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
nni_stream_dialer_getx(
    nng_stream_dialer *d, const char *nm, void *data, size_t *szp, nni_type t)
{
	return (d->sd_getx(d, nm, data, szp, t));
}

int
nni_stream_dialer_setx(nng_stream_dialer *d, const char *nm, const void *data,
    size_t sz, nni_type t)
{
	return (d->sd_setx(d, nm, data, sz, t));
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
nni_stream_listener_getx(nng_stream_listener *l, const char *nm, void *data,
    size_t *szp, nni_type t)
{
	return (l->sl_getx(l, nm, data, szp, t));
}

int
nni_stream_listener_setx(nng_stream_listener *l, const char *nm,
    const void *data, size_t sz, nni_type t)
{
	return (l->sl_setx(l, nm, data, sz, t));
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

int
nni_stream_checkopt(const char *scheme, const char *name, const void *data,
    size_t sz, nni_type t)
{
	for (int i = 0; stream_drivers[i].scheme != NULL; i++) {
		if (strcmp(stream_drivers[i].scheme, scheme) != 0) {
			continue;
		}
		if (stream_drivers[i].checkopt == NULL) {
			return (NNG_ENOTSUP);
		}
		return (stream_drivers[i].checkopt(name, data, sz, t));
	}
	return (NNG_ENOTSUP);
}

//
// This next block sets up to define the various typed option functions.
// To make it easier to cover them all at once, we use macros.
//

#define DEFGET(base)                                                         \
	int nng_##base##_get(                                                \
	    nng_##base *s, const char *nm, void *vp, size_t *szp)            \
	{                                                                    \
		return (nni_##base##_getx(s, nm, vp, szp, NNI_TYPE_OPAQUE)); \
	}

#define DEFTYPEDGET(base, suffix, type, nnitype)                     \
	int nng_##base##_get_##suffix(                               \
	    nng_##base *s, const char *nm, type *vp)                 \
	{                                                            \
		size_t sz = sizeof(*vp);                             \
		return (nni_##base##_getx(s, nm, vp, &sz, nnitype)); \
	}

#define DEFGETALL(base)                                        \
	DEFGET(base)                                           \
	DEFTYPEDGET(base, int, int, NNI_TYPE_INT32)            \
	DEFTYPEDGET(base, bool, bool, NNI_TYPE_BOOL)           \
	DEFTYPEDGET(base, size, size_t, NNI_TYPE_SIZE)         \
	DEFTYPEDGET(base, uint64, uint64_t, NNI_TYPE_UINT64)   \
	DEFTYPEDGET(base, ptr, void *, NNI_TYPE_POINTER)       \
	DEFTYPEDGET(base, ms, nng_duration, NNI_TYPE_DURATION) \
	DEFTYPEDGET(base, addr, nng_sockaddr, NNI_TYPE_SOCKADDR)

DEFGETALL(stream)
DEFGETALL(stream_dialer)
DEFGETALL(stream_listener)

#define DEFSET(base)                                                        \
	int nng_##base##_set(                                               \
	    nng_##base *s, const char *nm, const void *vp, size_t sz)       \
	{                                                                   \
		return (nni_##base##_setx(s, nm, vp, sz, NNI_TYPE_OPAQUE)); \
	}

#define DEFTYPEDSETEX(base, suffix, type, len, nnitype)                      \
	int nng_##base##_set_##suffix(nng_##base *s, const char *nm, type v) \
	{                                                                    \
		return (nni_##base##_setx(s, nm, &v, len, nnitype));         \
	}

#define DEFTYPEDSET(base, suffix, type, nnitype)                             \
	int nng_##base##_set_##suffix(nng_##base *s, const char *nm, type v) \
	{                                                                    \
		return (nni_##base##_setx(s, nm, &v, sizeof(v), nnitype));   \
	}

#define DEFSTRINGSET(base)                                            \
	int nng_##base##_set_string(                                  \
	    nng_##base *s, const char *nm, const char *v)             \
	{                                                             \
		return (nni_##base##_setx(s, nm, v,                   \
		    v != NULL ? strlen(v) + 1 : 0, NNI_TYPE_STRING)); \
	}

#define DEFSOCKADDRSET(base)                                      \
	int nng_##base##_set_adddr(                               \
	    nng_##base *s, const char *nm, const nng_sockaddr *v) \
	{                                                         \
		return (nni_##base##_setx(                        \
		    s, nm, v, sizeof(*v), NNI_TYPE_SOCKADDR));    \
	}

#define DEFSETALL(base)                                        \
	DEFSET(base)                                           \
	DEFTYPEDSET(base, int, int, NNI_TYPE_INT32)            \
	DEFTYPEDSET(base, bool, bool, NNI_TYPE_BOOL)           \
	DEFTYPEDSET(base, size, size_t, NNI_TYPE_SIZE)         \
	DEFTYPEDSET(base, ms, nng_duration, NNI_TYPE_DURATION) \
	DEFTYPEDSET(base, ptr, void *, NNI_TYPE_POINTER)       \
	DEFSTRINGSET(base)                                     \
	DEFSOCKADDRSET(base)

DEFSETALL(stream)
DEFSETALL(stream_dialer)
DEFSETALL(stream_listener)