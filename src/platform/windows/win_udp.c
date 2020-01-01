//
// Copyright 2020 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

// Silence complaints about inet_addr()
#define _WINSOCK_DEPRECATED_NO_WARNINGS 1

#include "core/nng_impl.h"

#ifdef NNG_PLATFORM_WINDOWS

#include <malloc.h>
#include <stdio.h>

struct nni_plat_udp {
	SOCKET           s;
	nni_mtx          lk;
	nni_cv           cv;
	nni_list         rxq;
	nni_win_io       rxio;
	int              cancel_rv;
	bool             closed;
	SOCKADDR_STORAGE rxsa;
	int              rxsalen;
};

static void udp_recv_cb(nni_win_io *, int, size_t);
static void udp_recv_start(nni_plat_udp *);

// nni_plat_udp_open initializes a UDP socket, binding to the local
// address specified specified.
int
nni_plat_udp_open(nni_plat_udp **udpp, nni_sockaddr *sa)
{
	nni_plat_udp *   u;
	SOCKADDR_STORAGE ss;
	int              sslen;
	DWORD            no;
	int              rv;

	if ((sslen = nni_win_nn2sockaddr(&ss, sa)) < 0) {
		return (NNG_EADDRINVAL);
	}

	if ((u = NNI_ALLOC_STRUCT(u)) == NULL) {
		return (NNG_ENOMEM);
	}
	nni_aio_list_init(&u->rxq);
	nni_mtx_init(&u->lk);
	nni_cv_init(&u->cv, &u->lk);

	u->s = socket(ss.ss_family, SOCK_DGRAM, IPPROTO_UDP);
	if (u->s == INVALID_SOCKET) {
		rv = nni_win_error(GetLastError());
		nni_plat_udp_close(u);
		return (rv);
	}
	// Don't inherit the handle (CLOEXEC really).
	SetHandleInformation((HANDLE) u->s, HANDLE_FLAG_INHERIT, 0);
	no = 0;
	(void) setsockopt(
	    u->s, IPPROTO_IPV6, IPV6_V6ONLY, (char *) &no, sizeof(no));

	if (((rv = nni_win_io_init(&u->rxio, udp_recv_cb, u)) != 0) ||
	    ((rv = nni_win_io_register((HANDLE) u->s)) != 0)) {
		nni_plat_udp_close(u);
		return (rv);
	}

	// Bind the local address
	if (bind(u->s, (struct sockaddr *) &ss, sslen) == SOCKET_ERROR) {
		rv = nni_win_error(GetLastError());
		nni_plat_udp_close(u);
		return (rv);
	}

	*udpp = u;
	return (rv);
}

// nni_plat_udp_close closes the underlying UDP socket.
void
nni_plat_udp_close(nni_plat_udp *u)
{
	nni_mtx_lock(&u->lk);
	u->closed = true;
	if (!nni_list_empty(&u->rxq)) {
		CancelIoEx((HANDLE) u->s, &u->rxio.olpd);
	}
	while (!nni_list_empty(&u->rxq)) {
		nni_cv_wait(&u->cv);
	}
	nni_mtx_unlock(&u->lk);

	if (u->s != INVALID_SOCKET) {
		closesocket(u->s);
	}

	nni_win_io_fini(&u->rxio);
	nni_mtx_fini(&u->lk);
	nni_cv_fini(&u->cv);
	NNI_FREE_STRUCT(u);
}

// nni_plat_udp_send sends the data in the aio to the the
// destination specified in the nni_aio.  The iovs are the UDP payload.
void
nni_plat_udp_send(nni_plat_udp *u, nni_aio *aio)
{
	SOCKADDR_STORAGE to;
	int              tolen;
	nng_sockaddr *   sa;
	unsigned         naiov;
	nni_iov *        aiov;
	WSABUF *         iov;
	int              rv;
	DWORD            nsent;

	if (nni_aio_begin(aio) != 0) {
		return;
	}
	sa = nni_aio_get_input(aio, 0);
	if ((tolen = nni_win_nn2sockaddr(&to, sa)) < 0) {
		nni_aio_finish_error(aio, NNG_EADDRINVAL);
		return;
	}

	nni_aio_get_iov(aio, &naiov, &aiov);
	iov = _malloca(sizeof(*iov) * naiov);

	// NB: UDP send runs "quickly" on Windows, without any need for
	// a blocking or asynchronous operation. If the message can't be
	// sent immediately (or queued for it), then it is dropped.

	nni_mtx_lock(&u->lk);
	if ((u->s == INVALID_SOCKET) || u->closed) {
		nni_mtx_unlock(&u->lk);
		nni_aio_finish_error(aio, NNG_ECLOSED);
		_freea(iov);
		return;
	}

	// Put the AIOs in Windows form.
	for (unsigned i = 0; i < naiov; i++) {
		iov[i].buf = aiov[i].iov_buf;
		iov[i].len = (ULONG) aiov[i].iov_len;
	}

	// We can use a "non-overlapping" send; there is little point in
	// handling UDP send completions asynchronously.
	rv = WSASendTo(u->s, iov, (DWORD) naiov, &nsent, 0,
	    (struct sockaddr *) &to, tolen, NULL, NULL);

	if (rv == SOCKET_ERROR) {
		rv    = nni_win_error(GetLastError());
		nsent = 0;
	}
	nni_mtx_unlock(&u->lk);

	_freea(iov);

	nni_aio_finish(aio, rv, nsent);

	return;
}

static void
udp_recv_cancel(nni_aio *aio, void *arg, int rv)
{
	nni_plat_udp *u = arg;
	nni_mtx_lock(&u->lk);
	if (aio == nni_list_first(&u->rxq)) {
		u->cancel_rv = rv;
		CancelIoEx((HANDLE) u->s, &u->rxio.olpd);
	} else if (nni_aio_list_active(aio)) {
		nni_aio_list_remove(aio);
		nni_aio_finish_error(aio, rv);
		nni_cv_wake(&u->cv);
	}
	nni_mtx_unlock(&u->lk);
}

static void
udp_recv_cb(nni_win_io *io, int rv, size_t num)
{
	nni_plat_udp *u = io->ptr;
	nni_sockaddr *sa;
	nni_aio *     aio;

	nni_mtx_lock(&u->lk);
	if ((aio = nni_list_first(&u->rxq)) == NULL) {
		// Should indicate that it was closed.
		nni_mtx_unlock(&u->lk);
		return;
	}
	if (u->cancel_rv != 0) {
		rv           = u->cancel_rv;
		u->cancel_rv = 0;
	}

	// convert address from Windows form...
	if ((sa = nni_aio_get_input(aio, 0)) != NULL) {
		if (nni_win_sockaddr2nn(sa, &u->rxsa) != 0) {
			rv  = NNG_EADDRINVAL;
			num = 0;
		}
	}

	nni_aio_list_remove(aio);
	udp_recv_start(u);
	nni_mtx_unlock(&u->lk);

	nni_aio_finish_synch(aio, rv, num);
}

static void
udp_recv_start(nni_plat_udp *u)
{
	int      rv;
	DWORD    flags;
	nni_iov *aiov;
	unsigned naiov;
	WSABUF * iov;
	nni_aio *aio;

	if ((u->s == INVALID_SOCKET) || (u->closed)) {
		while ((aio = nni_list_first(&u->rxq)) != NULL) {
			nni_list_remove(&u->rxq, aio);
			nni_aio_finish_error(aio, NNG_ECLOSED);
		}
		nni_cv_wake(&u->cv);
		return;
	}

again:
	if ((aio = nni_list_first(&u->rxq)) == NULL) {
		return;
	}

	u->rxsalen = sizeof(SOCKADDR_STORAGE);
	nni_aio_get_iov(aio, &naiov, &aiov);

	// This is a stack allocation- it should always succeed - or
	// throw an exception if there is not sufficient stack space.
	// (Turns out it can allocate from the heap, but same semantics.)
	iov = _malloca(sizeof(*iov) * naiov);

	// Put the AIOs in Windows form.
	for (unsigned i = 0; i < naiov; i++) {
		iov[i].buf = aiov[i].iov_buf;
		iov[i].len = (ULONG) aiov[i].iov_len;
	}

	// Note that the IOVs for the event were prepared on entry
	// already. The actual aio's iov array we don't touch.
	flags = 0;

	rv = WSARecvFrom(u->s, iov, (DWORD) naiov, NULL, &flags,
	    (struct sockaddr *) &u->rxsa, &u->rxsalen, &u->rxio.olpd, NULL);

	_freea(iov);

	if ((rv == SOCKET_ERROR) &&
	    ((rv = GetLastError()) != ERROR_IO_PENDING)) {
		// Synchronous failure.
		nni_aio_finish_error(aio, nni_win_error(rv));
		goto again;
	}
}

// nni_plat_udp_pipe_recv recvs a message, storing it in the iovs
// from the UDP payload.  If the UDP payload will not fit, then
// NNG_EMSGSIZE results.
void
nni_plat_udp_recv(nni_plat_udp *u, nni_aio *aio)
{
	int rv;
	if (nni_aio_begin(aio) != 0) {
		return;
	}
	nni_mtx_lock(&u->lk);
	if (u->closed) {
		nni_mtx_unlock(&u->lk);
		nni_aio_finish_error(aio, NNG_ECLOSED);
		return;
	}
	if ((rv = nni_aio_schedule(aio, udp_recv_cancel, u)) != 0) {
		nni_mtx_unlock(&u->lk);
		nni_aio_finish_error(aio, rv);
		return;
	}
	nni_list_append(&u->rxq, aio);
	if (nni_list_first(&u->rxq) == aio) {
		udp_recv_start(u);
	}
	nni_mtx_unlock(&u->lk);
}

int
nni_plat_udp_sockname(nni_plat_udp *udp, nni_sockaddr *sa)
{
	SOCKADDR_STORAGE ss;
	int              sz;

	sz = sizeof(ss);
	if (getsockname(udp->s, (SOCKADDR *) &ss, &sz) < 0) {
		return (nni_win_error(GetLastError()));
	}
	return (nni_win_sockaddr2nn(sa, &ss));
}

int
nni_win_udp_sysinit(void)
{
	WSADATA data;
	if (WSAStartup(MAKEWORD(2, 2), &data) != 0) {
		NNI_ASSERT(LOBYTE(data.wVersion) == 2);
		NNI_ASSERT(HIBYTE(data.wVersion) == 2);
		return (nni_win_error(GetLastError()));
	}
	return (0);
}

void
nni_win_udp_sysfini(void)
{
	WSACleanup();
}

#endif // NNG_PLATFORM_WINDOWS
