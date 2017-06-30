//
// Copyright 2017 Garrett D'Amore <garrett@damore.org>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "core/nng_impl.h"

#ifdef PLATFORM_POSIX_NET
#include "platform/posix/posix_aio.h"
#include "platform/posix/posix_socket.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>
#include <netdb.h>

// We alias nni_plat_tcpsock to an nni_posix_sock.

int
nni_plat_lookup_host(const char *host, nni_sockaddr *addr, int flags)
{
	struct addrinfo hint;
	struct addrinfo *ai;

	memset(&hint, 0, sizeof (hint));
	hint.ai_flags = AI_PASSIVE | AI_ADDRCONFIG | AI_NUMERICSERV;
	hint.ai_family = PF_UNSPEC;
	hint.ai_socktype = SOCK_STREAM;
	hint.ai_protocol = IPPROTO_TCP;
	if (flags & NNI_FLAG_IPV4ONLY) {
		hint.ai_family = PF_INET;
	}

	if (getaddrinfo(host, "1", &hint, &ai) != 0) {
		return (NNG_EADDRINVAL);
	}

	if (nni_posix_from_sockaddr(addr, ai->ai_addr) < 0) {
		freeaddrinfo(ai);
		return (NNG_EADDRINVAL);
	}
	freeaddrinfo(ai);
	return (0);
}


int
nni_plat_tcp_send(nni_plat_tcpsock *s, nni_iov *iovs, int cnt)
{
	return (nni_posix_sock_send_sync((void *) s, iovs, cnt));
}


int
nni_plat_tcp_recv(nni_plat_tcpsock *s, nni_iov *iovs, int cnt)
{
	return (nni_posix_sock_recv_sync((void *) s, iovs, cnt));
}


void
nni_plat_tcp_aio_send(nni_plat_tcpsock *s, nni_aio *aio)
{
	nni_posix_sock_aio_send((void *) s, aio);
}


void
nni_plat_tcp_aio_recv(nni_plat_tcpsock *s, nni_aio *aio)
{
	nni_posix_sock_aio_recv((void *) s, aio);
}


int
nni_plat_tcp_init(nni_plat_tcpsock **sp)
{
	nni_posix_sock *s;
	int rv;

	if ((rv = nni_posix_sock_init(&s)) == 0) {
		*sp = (void *) s;
	}
	return (rv);
}


void
nni_plat_tcp_fini(nni_plat_tcpsock *s)
{
	nni_posix_sock_fini((void *) s);
}


void
nni_plat_tcp_shutdown(nni_plat_tcpsock *s)
{
	nni_posix_sock_shutdown((void *) s);
}


int
nni_plat_tcp_listen(nni_plat_tcpsock *s, const nni_sockaddr *addr)
{
	return (nni_posix_sock_listen((void *) s, addr));
}


// nni_plat_tcp_connect establishes an outbound connection.  It the
// bind address is not null, then it will attempt to bind to the local
// address specified first.
int
nni_plat_tcp_connect(nni_plat_tcpsock *s, const nni_sockaddr *addr,
    const nni_sockaddr *bindaddr)
{
	return (nni_posix_sock_connect_sync((void *) s, addr, bindaddr));
}


int
nni_plat_tcp_accept(nni_plat_tcpsock *s, nni_plat_tcpsock *server)
{
	return (nni_posix_sock_accept_sync((void *) s, (void *) server));
}


#else

// Suppress empty symbols warnings in ranlib.
int nni_posix_net_not_used = 0;

#endif // PLATFORM_POSIX_NET
