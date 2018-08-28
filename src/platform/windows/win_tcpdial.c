//
// Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "core/nng_impl.h"

#ifdef NNG_PLATFORM_WINDOWS

#include "win_tcp.h"

#include <malloc.h>
#include <stdio.h>

int
nni_tcp_dialer_init(nni_tcp_dialer **dp)
{
	nni_tcp_dialer *d;
	int             rv;
	SOCKET          s;
	DWORD           nbytes;
	GUID            guid = WSAID_CONNECTEX;

	if ((d = NNI_ALLOC_STRUCT(d)) == NULL) {
		return (NNG_ENOMEM);
	}
	ZeroMemory(d, sizeof(*d));
	nni_mtx_init(&d->mtx);
	nni_aio_list_init(&d->aios);

	// Create a scratch socket for use with ioctl.
	s = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
	if (s == INVALID_SOCKET) {
		rv = nni_win_error(GetLastError());
		nni_tcp_dialer_fini(d);
		return (rv);
	}

	// Look up the function pointer.
	if (WSAIoctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER, &guid,
	        sizeof(guid), &d->connectex, sizeof(d->connectex), &nbytes,
	        NULL, NULL) == SOCKET_ERROR) {
		rv = nni_win_error(GetLastError());
		closesocket(s);
		nni_tcp_dialer_fini(d);
		return (rv);
	}

	closesocket(s);

	*dp = d;
	return (0);
}

void
nni_tcp_dialer_close(nni_tcp_dialer *d)
{
	nni_mtx_lock(&d->mtx);
	if (!d->closed) {
		nni_aio *aio;
		d->closed = true;

		NNI_LIST_FOREACH (&d->aios, aio) {
			nni_tcp_conn *c;

			if ((c = nni_aio_get_prov_extra(aio, 0)) != NULL) {
				c->conn_rv = NNG_ECLOSED;
				CancelIoEx((HANDLE) c->s, &c->conn_io.olpd);
			}
		}
	}
	nni_mtx_unlock(&d->mtx);
}

void
nni_tcp_dialer_fini(nni_tcp_dialer *d)
{
	nni_tcp_dialer_close(d);
	nni_mtx_lock(&d->mtx);
	if (!nni_list_empty(&d->aios)) {
		nni_mtx_unlock(&d->mtx);
		nni_reap(&d->reap, (nni_cb) nni_tcp_dialer_fini, d);
		return;
	}
	nni_mtx_unlock(&d->mtx);

	nni_mtx_fini(&d->mtx);
	NNI_FREE_STRUCT(d);
}

static void
tcp_dial_cancel(nni_aio *aio, void *arg, int rv)
{
	nni_tcp_dialer *d = arg;
	nni_tcp_conn *  c;

	nni_mtx_lock(&d->mtx);
	if ((c = nni_aio_get_prov_extra(aio, 0)) != NULL) {
		if (c->conn_rv == 0) {
			c->conn_rv = rv;
		}
		CancelIoEx((HANDLE) c->s, &c->conn_io.olpd);
	}
	nni_mtx_unlock(&d->mtx);
}

static void
tcp_dial_cb(nni_win_io *io, int rv, size_t cnt)
{
	nni_tcp_conn *  c   = io->ptr;
	nni_tcp_dialer *d   = c->dialer;
	nni_aio *       aio = c->conn_aio;

	NNI_ARG_UNUSED(cnt);

	nni_mtx_lock(&d->mtx);
	if ((aio = c->conn_aio) == NULL) {
		// This should never occur.
		nni_mtx_unlock(&d->mtx);
		return;
	}

	c->conn_aio = NULL;
	nni_aio_set_prov_extra(aio, 0, NULL);
	nni_aio_list_remove(aio);
	if (c->conn_rv != 0) {
		rv = c->conn_rv;
	}
	nni_mtx_unlock(&d->mtx);

	if (rv != 0) {
		nni_tcp_conn_fini(c);
		nni_aio_finish_error(aio, rv);
	} else {
		DWORD yes = 1;
		(void) setsockopt(c->s, SOL_SOCKET, SO_UPDATE_CONNECT_CONTEXT,
		    (char *) &yes, sizeof(yes));
		nni_aio_set_output(aio, 0, c);
		nni_aio_finish(aio, 0, 0);
	}
}

int
nni_tcp_dialer_set_src_addr(nni_tcp_dialer *d, const nni_sockaddr *sa)
{
	SOCKADDR_STORAGE     ss;
	struct sockaddr_in * sin;
	struct sockaddr_in6 *sin6;
	size_t               sslen;

	if ((sslen = nni_win_nn2sockaddr(&ss, sa)) == 0) {
		return (NNG_EADDRINVAL);
	}
	// Ensure we are either IPv4 or IPv6, and port is not set.  (We
	// do not allow binding to a specific port.)
	switch (ss.ss_family) {
	case AF_INET:
		sin = (void *) &ss;
		if (sin->sin_port != 0) {
			return (NNG_EADDRINVAL);
		}
		break;
	case AF_INET6:
		sin6 = (void *) &ss;
		if (sin6->sin6_port != 0) {
			return (NNG_EADDRINVAL);
		}
		break;
	default:
		return (NNG_EADDRINVAL);
	}
	nni_mtx_lock(&d->mtx);
	if (d->closed) {
		nni_mtx_unlock(&d->mtx);
		return (NNG_ECLOSED);
	}
	d->src    = ss;
	d->srclen = sslen;
	nni_mtx_unlock(&d->mtx);
	return (0);
}

void
nni_tcp_dialer_dial(nni_tcp_dialer *d, const nni_sockaddr *sa, nni_aio *aio)
{
	SOCKET           s;
	SOCKADDR_STORAGE ss;
	int              len;
	nni_tcp_conn *   c;
	int              rv;

	if (nni_aio_begin(aio) != 0) {
		return;
	}

	if ((len = nni_win_nn2sockaddr(&ss, sa)) <= 0) {
		nni_aio_finish_error(aio, NNG_EADDRINVAL);
		return;
	}

	if ((s = socket(ss.ss_family, SOCK_STREAM, 0)) == INVALID_SOCKET) {
		nni_aio_finish_error(aio, nni_win_error(GetLastError()));
		return;
	}

	if ((rv = nni_win_tcp_conn_init(&c, s)) != 0) {
		nni_tcp_conn_fini(c);
		nni_aio_finish_error(aio, rv);
		return;
	}

	c->peername = ss;

	if ((rv = nni_win_io_init(&c->conn_io, tcp_dial_cb, c)) != 0) {
		nni_aio_finish_error(aio, rv);
		return;
	}

	nni_mtx_lock(&d->mtx);
	if (d->closed) {
		nni_mtx_unlock(&d->mtx);
		nni_tcp_conn_fini(c);
		nni_aio_finish_error(aio, NNG_ECLOSED);
		return;
	}

	// Windows ConnectEx requires the socket to be bound
	// first. We just bind to an ephemeral address in the
	// same family, unless a different default was requested.
	if (d->srclen != 0) {
		len = (int) d->srclen;
		memcpy(&c->sockname, &d->src, len);
	} else {
		ZeroMemory(&c->sockname, sizeof(c->sockname));
		c->sockname.ss_family = ss.ss_family;
	}
	if (bind(s, (SOCKADDR *) &c->sockname, len) != 0) {
		rv = nni_win_error(GetLastError());
		nni_mtx_unlock(&d->mtx);
		nni_tcp_conn_fini(c);
		nni_aio_finish_error(aio, rv);
		return;
	}

	c->dialer = d;
	nni_aio_set_prov_extra(aio, 0, c);
	if ((rv = nni_aio_schedule(aio, tcp_dial_cancel, d)) != 0) {
		nni_mtx_unlock(&d->mtx);
		nni_tcp_conn_fini(c);
		nni_aio_finish_error(aio, rv);
		return;
	}
	c->conn_aio = aio;
	nni_aio_list_append(&d->aios, aio);

	// dialing is concurrent.
	if (!d->connectex(s, (struct sockaddr *) &c->peername, len, NULL, 0,
	        NULL, &c->conn_io.olpd)) {
		if ((rv = GetLastError()) != ERROR_IO_PENDING) {
			nni_aio_list_remove(aio);
			nni_mtx_unlock(&d->mtx);

			nni_tcp_conn_fini(c);
			nni_aio_finish_error(aio, rv);
			return;
		}
	}
	nni_mtx_unlock(&d->mtx);
}

#endif // NNG_PLATFORM_WINDOWS
