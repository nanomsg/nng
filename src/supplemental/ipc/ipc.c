//
// Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
// Copyright 2018 Devolutions <info@devolutions.net>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <stddef.h>
#include <stdint.h>

#include <nng/nng.h>
#include <nng/supplemental/ipc/ipc.h>

#include "core/nng_impl.h"

// This is our "public" IPC API.  This allows applications to access
// basic IPC functions, using our AIO framework.  Most applications will
// not need this.

// We treat nng_ipc as nni_ipc_conn, nng_ipc_dialer as nni_ipc_dialer,
// and nng_ipc_listener as nni_ipc_listener.  We cast through void to
// provide isolation of the names in a way that makes the compiler happy.
// It turns out we can pretty much just wrap the platform API for IPC that
// we have already created.

void
nng_ipc_close(nng_ipc *ipc)
{
	nni_ipc_conn_close((void *) ipc);
}

void
nng_ipc_free(nng_ipc *ipc)
{
	nni_ipc_conn_fini((void *) ipc);
}

void
nng_ipc_send(nng_ipc *ipc, nng_aio *aio)
{
	nni_ipc_conn_send((void *) ipc, aio);
}

void
nng_ipc_recv(nng_ipc *ipc, nng_aio *aio)
{
	nni_ipc_conn_recv((void *) ipc, aio);
}

int
nng_ipc_setopt(nng_ipc *ipc, const char *name, const void *val, size_t sz)
{
	return (
	    nni_ipc_conn_setopt((void *) ipc, name, val, sz, NNI_TYPE_OPAQUE));
}

int
nng_ipc_getopt(nng_ipc *ipc, const char *name, void *val, size_t *szp)
{
	return (nni_ipc_conn_getopt(
	    (void *) ipc, name, val, szp, NNI_TYPE_OPAQUE));
}

int
nng_ipc_dialer_alloc(nng_ipc_dialer **dp)
{
	nni_ipc_dialer *d;
	int             rv;

	if ((rv = nni_init()) != 0) {
		return (rv);
	}
	if ((rv = nni_ipc_dialer_init(&d)) == 0) {
		*dp = (void *) d;
	}
	return (rv);
}

void
nng_ipc_dialer_close(nng_ipc_dialer *d)
{
	nni_ipc_dialer_close((void *) d);
}

void
nng_ipc_dialer_free(nng_ipc_dialer *d)
{
	nni_ipc_dialer_fini((void *) d);
}

void
nng_ipc_dialer_dial(nng_ipc_dialer *d, const nng_sockaddr *sa, nng_aio *aio)
{
	nni_ipc_dialer_dial((void *) d, sa, aio);
}

int
nng_ipc_listener_alloc(nng_ipc_listener **lp)
{
	nni_ipc_listener *l;
	int               rv;

	if ((rv = nni_init()) != 0) {
		return (rv);
	}
	if ((rv = nni_ipc_listener_init(&l)) == 0) {
		*lp = (void *) l;
	}
	return (rv);
}

void
nng_ipc_listener_close(nng_ipc_listener *l)
{
	nni_ipc_listener_close((void *) l);
}

void
nng_ipc_listener_free(nng_ipc_listener *l)
{
	nni_ipc_listener_fini((void *) l);
}

int
nng_ipc_listener_listen(nng_ipc_listener *l, const nng_sockaddr *sa)
{
	return (nni_ipc_listener_listen((void *) l, sa));
}

void
nng_ipc_listener_accept(nng_ipc_listener *l, nng_aio *aio)
{
	nni_ipc_listener_accept((void *) l, aio);
}
