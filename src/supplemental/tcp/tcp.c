//
// Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <stddef.h>
#include <stdint.h>

#include <nng/nng.h>
#include <nng/supplemental/tcp/tcp.h>

#include "core/nng_impl.h"

// This is our "public" TCP API.  This allows applications to access
// basic TCP functions, using our AIO framework.  Most applications will
// not need this.

// We treat nng_tcp as nni_tcp_conn, nng_tcp_dialer as nni_tcp_dialer,
// and nng_tcp_listener as nni_tcp_listener.  We cast through void to
// provide isolation of the names in a way that makes the compiler happy.
// It turns out we can pretty much just wrap the platform API for TCP that
// we have already created.

void
nng_tcp_close(nng_tcp *tcp)
{
	nni_tcp_conn_close((void *) tcp);
}

void
nng_tcp_free(nng_tcp *tcp)
{
	nni_tcp_conn_fini((void *) tcp);
}

void
nng_tcp_send(nng_tcp *tcp, nng_aio *aio)
{
	nni_tcp_conn_send((void *) tcp, aio);
}

void
nng_tcp_recv(nng_tcp *tcp, nng_aio *aio)
{
	nni_tcp_conn_recv((void *) tcp, aio);
}

int
nng_tcp_sockname(nng_tcp *tcp, nng_sockaddr *sa)
{
	return (nni_tcp_conn_sockname((void *) tcp, sa));
}

int
nng_tcp_peername(nng_tcp *tcp, nng_sockaddr *sa)
{
	return (nni_tcp_conn_peername((void *) tcp, sa));
}

int
nng_tcp_set_nodelay(nng_tcp *tcp, bool nodelay)
{
	return (nni_tcp_conn_set_nodelay((void *) tcp, nodelay));
}

int
nng_tcp_set_keepalive(nng_tcp *tcp, bool ka)
{
	return (nni_tcp_conn_set_keepalive((void *) tcp, ka));
}

int
nng_tcp_dialer_alloc(nng_tcp_dialer **dp)
{
	nni_tcp_dialer *d;
	int             rv;

	if ((rv = nni_init()) != 0) {
		return (rv);
	}
	if ((rv = nni_tcp_dialer_init(&d)) == 0) {
		*dp = (void *) d;
	}
	return (rv);
}

void
nng_tcp_dialer_close(nng_tcp_dialer *d)
{
	nni_tcp_dialer_close((void *) d);
}

void
nng_tcp_dialer_free(nng_tcp_dialer *d)
{
	nni_tcp_dialer_fini((void *) d);
}

int
nng_tcp_dialer_set_source(nng_tcp_dialer *d, const nng_sockaddr *sa)
{
	return (nni_tcp_dialer_set_src_addr((void *) d, sa));
}

void
nng_tcp_dialer_dial(nng_tcp_dialer *d, const nng_sockaddr *sa, nng_aio *aio)
{
	nni_tcp_dialer_dial((void *) d, sa, aio);
}

int
nng_tcp_listener_alloc(nng_tcp_listener **lp)
{
	nni_tcp_listener *l;
	int               rv;

	if ((rv = nni_init()) != 0) {
		return (rv);
	}
	if ((rv = nni_tcp_listener_init(&l)) == 0) {
		*lp = (void *) l;
	}
	return (rv);
}

void
nng_tcp_listener_close(nng_tcp_listener *l)
{
	nni_tcp_listener_close((void *) l);
}

void
nng_tcp_listener_free(nng_tcp_listener *l)
{
	nni_tcp_listener_fini((void *) l);
}

int
nng_tcp_listener_listen(nng_tcp_listener *l, nng_sockaddr *sa)
{
	return (nni_tcp_listener_listen((void *) l, sa));
}

void
nng_tcp_listener_accept(nng_tcp_listener *l, nng_aio *aio)
{
	nni_tcp_listener_accept((void *) l, aio);
}
