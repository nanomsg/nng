//
// Copyright 2017 Garrett D'Amore <garrett@damore.org>
// Copyright 2017 Capitar IT Group BV <info@capitar.com>
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

#include <stdio.h>

struct nni_plat_udp {
	SOCKET           s;
	nni_mtx          lk;
	nni_win_event    rxev;
	nni_win_event    txev;
	SOCKADDR_STORAGE rxsa;
	SOCKADDR_STORAGE txsa;
	int              rxsalen;
	int              txsalen;
};

static int  nni_win_udp_start_rx(nni_win_event *, nni_aio *);
static int  nni_win_udp_start_tx(nni_win_event *, nni_aio *);
static void nni_win_udp_finish_rx(nni_win_event *, nni_aio *);
static void nni_win_udp_finish_tx(nni_win_event *, nni_aio *);
static void nni_win_udp_cancel(nni_win_event *);

static nni_win_event_ops nni_win_udp_rxo = {
	.wev_start  = nni_win_udp_start_rx,
	.wev_finish = nni_win_udp_finish_rx,
	.wev_cancel = nni_win_udp_cancel,
};

static nni_win_event_ops nni_win_udp_txo = {
	.wev_start  = nni_win_udp_start_tx,
	.wev_finish = nni_win_udp_finish_tx,
	.wev_cancel = nni_win_udp_cancel,
};

// nni_plat_udp_open initializes a UDP socket, binding to the local
// address specified specified in the AIO.  The remote address is
// not used.  The resulting nni_plat_udp structure is returned in the
// the aio's a_pipe.
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
	nni_mtx_init(&u->lk);

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

	if (((rv = nni_win_event_init(&u->rxev, &nni_win_udp_rxo, u)) != 0) ||
	    ((rv = nni_win_event_init(&u->txev, &nni_win_udp_txo, u)) != 0) ||
	    ((rv = nni_win_iocp_register((HANDLE) u->s)) != 0)) {
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
	if (u->s != INVALID_SOCKET) {
		closesocket(u->s);
	}
	nni_win_event_fini(&u->rxev);
	nni_win_event_fini(&u->txev);
	nni_mtx_fini(&u->lk);
	NNI_FREE_STRUCT(u);
}

// nni_plat_udp_send sends the data in the aio to the the
// destination specified in the nni_aio.  The iovs are the
// UDP payload.
void
nni_plat_udp_send(nni_plat_udp *u, nni_aio *aio)
{
	nni_win_event_submit(&u->txev, aio);
}

// nni_plat_udp_pipe_recv recvs a message, storing it in the iovs
// from the UDP payload.  If the UDP payload will not fit, then
// NNG_EMSGSIZE results.
void
nni_plat_udp_recv(nni_plat_udp *u, nni_aio *aio)
{
	nni_win_event_submit(&u->rxev, aio);
}

static int
nni_win_udp_start_rx(nni_win_event *evt, nni_aio *aio)
{
	int           rv;
	SOCKET        s;
	WSABUF        iov[4];
	DWORD         niov;
	DWORD         flags;
	nni_plat_udp *u = evt->ptr;

	if ((s = u->s) == INVALID_SOCKET) {
		evt->status = NNG_ECLOSED;
		evt->count  = 0;
		return (1);
	}

	u->rxsalen = sizeof(SOCKADDR_STORAGE);
	NNI_ASSERT(aio->a_niov > 0);
	NNI_ASSERT(aio->a_niov <= 4);
	NNI_ASSERT(aio->a_iov[0].iov_len > 0);
	NNI_ASSERT(aio->a_iov[0].iov_buf != NULL);

	niov = aio->a_niov;

	// Put the AIOs in Windows form.
	for (int i = 0; i < aio->a_niov; i++) {
		iov[i].buf = aio->a_iov[i].iov_buf;
		iov[i].len = (ULONG) aio->a_iov[i].iov_len;
	}

	// Note that the IOVs for the event were prepared on entry
	// already. The actual aio's iov array we don't touch.

	evt->count = 0;
	flags      = 0;

	rv = WSARecvFrom(u->s, iov, niov, NULL, &flags,
	    (struct sockaddr *) &u->rxsa, &u->rxsalen, &evt->olpd, NULL);

	if ((rv == SOCKET_ERROR) &&
	    ((rv = GetLastError()) != ERROR_IO_PENDING)) {
		// Synchronous failure.
		evt->status = nni_win_error(rv);
		evt->count  = 0;
		return (1);
	}

	// Wait for the I/O completion event.  Note that when an I/O
	// completes immediately, the I/O completion packet is still
	// delivered.
	return (0);
}

static int
nni_win_udp_start_tx(nni_win_event *evt, nni_aio *aio)
{
	int           rv;
	SOCKET        s;
	WSABUF        iov[4];
	DWORD         niov;
	nni_plat_udp *u = evt->ptr;
	int           salen;

	if ((s = u->s) == INVALID_SOCKET) {
		evt->status = NNG_ECLOSED;
		evt->count  = 0;
		return (1);
	}

	if ((salen = nni_win_nn2sockaddr(&u->txsa, aio->a_addr)) < 0) {
		evt->status = NNG_EADDRINVAL;
		evt->count  = 0;
		return (1);
	}

	NNI_ASSERT(aio->a_addr != NULL);
	NNI_ASSERT(aio->a_niov > 0);
	NNI_ASSERT(aio->a_niov <= 4);
	NNI_ASSERT(aio->a_iov[0].iov_len > 0);
	NNI_ASSERT(aio->a_iov[0].iov_buf != NULL);

	niov = aio->a_niov;

	// Put the AIOs in Windows form.
	for (int i = 0; i < aio->a_niov; i++) {
		iov[i].buf = aio->a_iov[i].iov_buf;
		iov[i].len = (ULONG) aio->a_iov[i].iov_len;
	}

	// Note that the IOVs for the event were prepared on entry
	// already. The actual aio's iov array we don't touch.

	evt->count = 0;

	rv = WSASendTo(u->s, iov, niov, NULL, 0, (struct sockaddr *) &u->txsa,
	    salen, &evt->olpd, NULL);

	if ((rv == SOCKET_ERROR) &&
	    ((rv = GetLastError()) != ERROR_IO_PENDING)) {
		// Synchronous failure.
		evt->status = nni_win_error(rv);
		evt->count  = 0;
		return (1);
	}

	// Wait for the I/O completion event.  Note that when an I/O
	// completes immediately, the I/O completion packet is still
	// delivered.
	return (0);
}

static void
nni_win_udp_cancel(nni_win_event *evt)
{
	nni_plat_udp *u = evt->ptr;

	(void) CancelIoEx((HANDLE) u->s, &evt->olpd);
}

static void
nni_win_udp_finish_rx(nni_win_event *evt, nni_aio *aio)
{
	int           rv;
	size_t        cnt;
	nni_plat_udp *u = evt->ptr;

	cnt = evt->count;
	if ((rv = evt->status) == 0) {
		// convert address from Windows form...
		if (aio->a_addr != NULL) {
			if (nni_win_sockaddr2nn(aio->a_addr, &u->rxsa) != 0) {
				rv  = NNG_EADDRINVAL;
				cnt = 0;
			}
		}
	}

	// All done; hopefully successfully.
	nni_aio_finish(aio, rv, cnt);
}

static void
nni_win_udp_finish_tx(nni_win_event *evt, nni_aio *aio)
{
	int    rv;
	size_t cnt;

	cnt = evt->count;
	rv  = evt->status;

	nni_aio_finish(aio, rv, cnt);
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
