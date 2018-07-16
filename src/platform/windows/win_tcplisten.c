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

#include <malloc.h>
#include <stdbool.h>
#include <stdio.h>

#include "win_tcp.h"

// tcp_listener_funcs looks up function pointers we need for advanced accept
// functionality on Windows.  Windows is weird.
static int
tcp_listener_funcs(nni_tcp_listener *l)
{
	static SRWLOCK                   lock = SRWLOCK_INIT;
	static LPFN_ACCEPTEX             acceptex;
	static LPFN_GETACCEPTEXSOCKADDRS getacceptexsockaddrs;

	AcquireSRWLockExclusive(&lock);
	if (acceptex == NULL) {
		int    rv;
		DWORD  nbytes;
		GUID   guid1 = WSAID_ACCEPTEX;
		GUID   guid2 = WSAID_GETACCEPTEXSOCKADDRS;
		SOCKET s     = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);

		if (s == INVALID_SOCKET) {
			rv = nni_win_error(GetLastError());
			ReleaseSRWLockExclusive(&lock);
			return (rv);
		}

		// Look up the function pointer.
		if ((WSAIoctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER, &guid1,
		         sizeof(guid1), &acceptex, sizeof(acceptex), &nbytes,
		         NULL, NULL) == SOCKET_ERROR) ||
		    (WSAIoctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER, &guid2,
		         sizeof(guid2), &getacceptexsockaddrs,
		         sizeof(getacceptexsockaddrs), &nbytes, NULL,
		         NULL) == SOCKET_ERROR)) {
			rv                   = nni_win_error(GetLastError());
			acceptex             = NULL;
			getacceptexsockaddrs = NULL;
			ReleaseSRWLockExclusive(&lock);
			closesocket(s);
			return (rv);
		}
		closesocket(s);
	}
	ReleaseSRWLockExclusive(&lock);

	l->acceptex             = acceptex;
	l->getacceptexsockaddrs = getacceptexsockaddrs;
	return (0);
}

static void
tcp_accept_cb(nni_win_io *io, int rv, size_t cnt)
{
	nni_tcp_conn *    c = io->ptr;
	nni_tcp_listener *l = c->listener;
	nni_aio *         aio;
	int               len1;
	int               len2;
	SOCKADDR *        sa1;
	SOCKADDR *        sa2;
	DWORD             yes;

	NNI_ARG_UNUSED(cnt);

	nni_mtx_lock(&l->mtx);
	if ((aio = c->conn_aio) == NULL) {
		// This case should not occur. The situation would indicate
		// a case where the connection was accepted already.
		nni_mtx_unlock(&l->mtx);
		return;
	}
	c->conn_aio = NULL;
	nni_aio_set_prov_extra(aio, 0, NULL);
	nni_aio_list_remove(aio);
	if (c->conn_rv != 0) {
		rv = c->conn_rv;
	}
	nni_mtx_unlock(&l->mtx);

	if (rv != 0) {
		nni_tcp_conn_fini(c);
		nni_aio_finish_error(aio, rv);
		return;
	}

	len1 = (int) sizeof(c->sockname);
	len2 = (int) sizeof(c->peername);
	l->getacceptexsockaddrs(c->buf, 0, 256, 256, &sa1, &len1, &sa2, &len2);
	memcpy(&c->sockname, sa1, len1);
	memcpy(&c->peername, sa2, len2);

	yes = 1;
	(void) setsockopt(c->s, SOL_SOCKET, SO_UPDATE_ACCEPT_CONTEXT,
	    (char *) &yes, sizeof(yes));
	nni_aio_set_output(aio, 0, c);
	nni_aio_finish(aio, 0, 0);
}

int
nni_tcp_listener_init(nni_tcp_listener **lp)
{
	nni_tcp_listener *l;
	int               rv;

	if ((l = NNI_ALLOC_STRUCT(l)) == NULL) {
		return (NNG_ENOMEM);
	}
	ZeroMemory(l, sizeof(*l));
	nni_mtx_init(&l->mtx);
	nni_aio_list_init(&l->aios);
	if ((rv = tcp_listener_funcs(l)) != 0) {
		nni_tcp_listener_fini(l);
		return (rv);
	}

	*lp = l;
	return (0);
}

void
nni_tcp_listener_close(nni_tcp_listener *l)
{
	nni_mtx_lock(&l->mtx);
	if (!l->closed) {
		nni_aio *aio;
		l->closed = true;

		NNI_LIST_FOREACH (&l->aios, aio) {
			nni_tcp_conn *c;

			if ((c = nni_aio_get_prov_extra(aio, 0)) != NULL) {
				c->conn_rv = NNG_ECLOSED;
				nni_win_io_cancel(&c->conn_io);
			}
		}
		closesocket(l->s);
	}
	nni_mtx_unlock(&l->mtx);
}

void
nni_tcp_listener_fini(nni_tcp_listener *l)
{
	nni_tcp_listener_close(l);
	nni_mtx_lock(&l->mtx);
	if (!nni_list_empty(&l->aios)) {
		nni_mtx_unlock(&l->mtx);
		nni_reap(&l->reap, (nni_cb) nni_tcp_listener_fini, l);
		return;
	}
	nni_mtx_unlock(&l->mtx);
	nni_mtx_fini(&l->mtx);
	NNI_FREE_STRUCT(l);
}

int
nni_tcp_listener_listen(nni_tcp_listener *l, nni_sockaddr *sa)
{
	int   rv;
	BOOL  yes;
	DWORD no;
	int   len;

	nni_mtx_lock(&l->mtx);
	if (l->closed) {
		nni_mtx_unlock(&l->mtx);
		return (NNG_ECLOSED);
	}
	if (l->started) {
		nni_mtx_unlock(&l->mtx);
		return (NNG_EBUSY);
	}
	if ((len = nni_win_nn2sockaddr(&l->ss, sa)) <= 0) {
		nni_mtx_unlock(&l->mtx);
		return (NNG_EADDRINVAL);
	}
	l->s = socket(l->ss.ss_family, SOCK_STREAM, 0);
	if (l->s == INVALID_SOCKET) {
		rv = nni_win_error(GetLastError());
		nni_mtx_unlock(&l->mtx);
		return (rv);
	}

	// Don't inherit the handle (CLOEXEC really).
	SetHandleInformation((HANDLE) l->s, HANDLE_FLAG_INHERIT, 0);

	no = 0;
	(void) setsockopt(
	    l->s, IPPROTO_IPV6, IPV6_V6ONLY, (char *) &no, sizeof(no));
	yes = 1;
	(void) setsockopt(
	    l->s, IPPROTO_TCP, TCP_NODELAY, (char *) &yes, sizeof(yes));

	if ((rv = nni_win_io_register((HANDLE) l->s)) != 0) {
		closesocket(l->s);
		l->s = INVALID_SOCKET;
		nni_mtx_unlock(&l->mtx);
		return (rv);
	}

	// Make sure that we use the address exclusively.  Windows lets
	// others hijack us by default.
	yes = 1;
	if ((setsockopt(l->s, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (char *) &yes,
	         sizeof(yes)) != 0) ||
	    (bind(l->s, (SOCKADDR *) &l->ss, len) != 0) ||
	    (getsockname(l->s, (SOCKADDR *) &l->ss, &len) != 0) ||
	    (listen(l->s, SOMAXCONN) != 0)) {
		rv = nni_win_error(GetLastError());
		closesocket(l->s);
		l->s = INVALID_SOCKET;
		nni_mtx_unlock(&l->mtx);
		return (rv);
	}
	nni_win_sockaddr2nn(sa, &l->ss);
	l->started = true;
	nni_mtx_unlock(&l->mtx);
	return (0);
}

static void
tcp_accept_cancel(nni_aio *aio, int rv)
{
	nni_tcp_listener *l = nni_aio_get_prov_data(aio);
	nni_tcp_conn *    c;

	nni_mtx_lock(&l->mtx);
	if ((c = nni_aio_get_prov_extra(aio, 0)) != NULL) {
		if (c->conn_rv == 0) {
			c->conn_rv = rv;
		}
		nni_win_io_cancel(&c->conn_io);
	}
	nni_mtx_unlock(&l->mtx);
}

void
nni_tcp_listener_accept(nni_tcp_listener *l, nni_aio *aio)
{
	SOCKET        s;
	int           rv;
	DWORD         cnt;
	nni_tcp_conn *c;

	if (nni_aio_begin(aio) != 0) {
		return;
	}
	nni_mtx_lock(&l->mtx);
	if (l->closed) {
		nni_mtx_unlock(&l->mtx);
		nni_aio_finish_error(aio, NNG_ECLOSED);
		return;
	}

	// Windows requires us to explicity create the socket before
	// calling accept on it.
	if ((s = socket(l->ss.ss_family, SOCK_STREAM, 0)) == INVALID_SOCKET) {
		rv = nni_win_error(GetLastError());
		nni_mtx_unlock(&l->mtx);
		nni_aio_finish_error(aio, rv);
		return;
	}
	if ((rv = nni_win_tcp_conn_init(&c, s)) != 0) {
		nni_mtx_unlock(&l->mtx);
		closesocket(s);
		nni_aio_finish_error(aio, rv);
		return;
	}
	c->listener = l;
	c->conn_aio = aio;
	nni_aio_set_prov_extra(aio, 0, c);
	if (((rv = nni_win_io_init(
	          &c->conn_io, (HANDLE) l->s, tcp_accept_cb, c)) != 0) ||
	    ((rv = nni_aio_schedule(aio, tcp_accept_cancel, l)) != 0)) {
		nni_aio_set_prov_extra(aio, 0, NULL);
		nni_mtx_unlock(&l->mtx);
		nni_tcp_conn_fini(c);
		nni_aio_finish_error(aio, rv);
		return;
	}
	nni_list_append(&l->aios, aio);
	if ((!l->acceptex(
	        l->s, s, c->buf, 0, 256, 256, &cnt, &c->conn_io.olpd)) &&
	    ((rv = GetLastError()) != ERROR_IO_PENDING)) {
		// Fast failure (synchronous.)
		nni_aio_list_remove(aio);
		nni_mtx_unlock(&l->mtx);
		nni_tcp_conn_fini(c);
		nni_aio_finish_error(aio, rv);
		return;
	}
	nni_mtx_unlock(&l->mtx);
}

#endif // NNG_PLATFORM_WINDOWS
