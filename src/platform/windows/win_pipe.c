//
// Copyright 2017 Garrett D'Amore <garrett@damore.org>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "core/nng_impl.h"

#include <stdio.h>

// Windows named pipes won't work for us; we *MUST* use sockets.  This is
// a real sadness, but what can you do.  We use an anonymous socket bound
// to localhost and a connected peer.  This is because folks that want to
// use notification pipes (ugh) are expecting this to work with select(),
// which only supports real winsock sockets.  We use an ephemeral port,
// bound to localhost; some care is taken to prevent other applications on
// the same host from messing us up by accessing the same port.

#ifdef NNG_PLATFORM_WINDOWS

int
nni_plat_pipe_open(int *wfdp, int *rfdp)
{
	SOCKET rfd = INVALID_SOCKET;
	SOCKET wfd = INVALID_SOCKET;
	SOCKET afd;

	struct sockaddr_in addr;
	socklen_t          alen;
	int                one;
	ULONG              yes;
	int                rv;

	ZeroMemory(&addr, sizeof(addr));

	// Restrict our bind to the loopback address.  We bind to an
	// ephemeral port.
	addr.sin_family      = AF_INET;
	addr.sin_port        = 0;
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

	afd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (afd == INVALID_SOCKET) {
		goto fail;
	}

	// Make sure we have exclusive address use...
	one = 1;
	if (setsockopt(afd, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (char *) (&one),
	        sizeof(one)) != 0) {
		goto fail;
	}

	alen = sizeof(addr);
	if (bind(afd, (struct sockaddr *) &addr, alen) != 0) {
		goto fail;
	}
	// What port did we bind to?
	if (getsockname(afd, (struct sockaddr *) &addr, &alen) != 0) {
		goto fail;
	}

	// Minimum backlog -- we only expect one connection ever.
	if (listen(afd, 1) != 0) {
		goto fail;
	}

	rfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (afd == INVALID_SOCKET) {
		goto fail;
	}
	if (connect(rfd, (struct sockaddr *) &addr, alen) != 0) {
		goto fail;
	}

	// Now we have to do the accept dance.  We don't care about the
	// peer address, since know it.
	wfd = accept(afd, NULL, 0);
	if (wfd == INVALID_SOCKET) {
		goto fail;
	}

	// Now that we are connected, mark everything non-blocking.
	yes = 1;
	if (ioctlsocket(rfd, FIONBIO, &yes) != 0) {
		goto fail;
	}
	yes = 1;
	if (ioctlsocket(wfd, FIONBIO, &yes) != 0) {
		goto fail;
	}

	// Close the listener now that we have the connection.
	closesocket((SOCKET) afd);
	*rfdp = (int) rfd;
	*wfdp = (int) wfd;
	return (0);

fail:
	rv = nni_win_error(GetLastError());
	if (afd != INVALID_SOCKET) {
		closesocket(afd);
	}
	if (rfd != INVALID_SOCKET) {
		closesocket(rfd);
	}
	if (wfd != INVALID_SOCKET) {
		closesocket(wfd);
	}

	return (rv);
}

void
nni_plat_pipe_raise(int wfd)
{
	char c = 1;

	send((SOCKET) wfd, &c, 1, 0);
}

void
nni_plat_pipe_clear(int rfd)
{
	char buf[32];

	for (;;) {
		// Completely drain the pipe, but don't wait.  This coalesces
		// events somewhat.
		if (recv((SOCKET) rfd, buf, sizeof(buf), 0) <= 0) {
			return;
		}
	}
}

void
nni_plat_pipe_close(int wfd, int rfd)
{
	closesocket((SOCKET) wfd);
	closesocket((SOCKET) rfd);
}

#endif // NNG_PLATFORM_WINDOWS
