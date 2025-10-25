//
// Copyright 2024 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "core/nng_impl.h"

#ifdef NNG_PLATFORM_WINDOWS

#include <stdio.h>

static LPFN_ACCEPTEX             acceptex;
static LPFN_GETACCEPTEXSOCKADDRS getacceptexsockaddrs;
static LPFN_CONNECTEX            connectex;

int
nni_win_tcp_sysinit(void)
{
	int rv;

	WSADATA data;

	if (WSAStartup(MAKEWORD(2, 2), &data) != 0) {
		NNI_ASSERT(LOBYTE(data.wVersion) == 2);
		NNI_ASSERT(HIBYTE(data.wVersion) == 2);
		return (nni_win_error(GetLastError()));
	}

	DWORD nbytes;
	GUID  guid1 = WSAID_ACCEPTEX;
	GUID  guid2 = WSAID_GETACCEPTEXSOCKADDRS;
	GUID  guid3 = WSAID_CONNECTEX;

	SOCKET s = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
	if (s == INVALID_SOCKET) {
		rv = nni_win_error(GetLastError());
		WSACleanup();
		return (rv);
	}
	if ((WSAIoctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER, &guid1,
	         sizeof(guid1), &acceptex, sizeof(acceptex), &nbytes, NULL,
	         NULL) == SOCKET_ERROR) ||
	    (WSAIoctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER, &guid2,
	         sizeof(guid2), &getacceptexsockaddrs,
	         sizeof(getacceptexsockaddrs), &nbytes, NULL,
	         NULL) == SOCKET_ERROR) ||
	    (WSAIoctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER, &guid3,
	         sizeof(guid3), &connectex, sizeof(connectex), &nbytes, NULL,
	         NULL) == SOCKET_ERROR)) {
		rv = nni_win_error(GetLastError());
		closesocket(s);
		WSACleanup();
		return (rv);
	}

	closesocket(s);
	return (0);
}

int
nni_win_acceptex(SOCKET listen, SOCKET child, void *buf, LPOVERLAPPED olpd)
{
	DWORD cnt = 0;
	return (acceptex(listen, child, buf, 0, 256, 256, &cnt, olpd));
}

// This is called after a socket is accepted for the connection, and the buffer
// contains the peers socket addresses.  It is is kind of weird, windows
// specific, and must be called only after acceptex.  The caller should call
// setsockopt(s, SOL_SOCKET, SO_UPDATE_ACCEPT_CONTEXT) after calling this.
void
nni_win_get_acceptex_sockaddrs(
    void *buf, SOCKADDR_STORAGE *self, SOCKADDR_STORAGE *peer)
{
	SOCKADDR *self_p;
	SOCKADDR *peer_p;
	int       self_len;
	int       peer_len;

	getacceptexsockaddrs(
	    buf, 0, 256, 256, &self_p, &self_len, &peer_p, &peer_len);

	(void) memcpy(self, self_p, self_len);
	(void) memcpy(peer, peer_p, peer_len);
}

int
nni_win_connectex(SOCKET s, SOCKADDR *peer, int peer_len, LPOVERLAPPED olpd)
{
	return (connectex(s, peer, peer_len, NULL, 0, NULL, olpd));
}

void
nni_win_tcp_sysfini(void)
{
	WSACleanup();
}

#endif // NNG_PLATFORM_WINDOWS
