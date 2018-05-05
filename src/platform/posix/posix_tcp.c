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

#ifdef NNG_PLATFORM_POSIX
#include "platform/posix/posix_aio.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

int
nni_plat_tcp_ep_init(nni_plat_tcp_ep **epp, const nni_sockaddr *lsa,
    const nni_sockaddr *rsa, int mode)
{
	nni_posix_epdesc *      ed;
	int                     rv;
	struct sockaddr_storage ss;
	int                     len;

	NNI_ARG_UNUSED(mode);

	if ((rv = nni_posix_epdesc_init(&ed, mode)) != 0) {
		return (rv);
	}

	if ((rsa != NULL) && (rsa->s_family != NNG_AF_UNSPEC)) {
		len = nni_posix_nn2sockaddr((void *) &ss, rsa);
		nni_posix_epdesc_set_remote(ed, &ss, len);
	}
	if ((lsa != NULL) && (lsa->s_family != NNG_AF_UNSPEC)) {
		len = nni_posix_nn2sockaddr((void *) &ss, lsa);
		nni_posix_epdesc_set_local(ed, &ss, len);
	}

	*epp = (void *) ed;
	return (0);
}

void
nni_plat_tcp_ep_fini(nni_plat_tcp_ep *ep)
{
	nni_posix_epdesc_fini((void *) ep);
}

void
nni_plat_tcp_ep_close(nni_plat_tcp_ep *ep)
{
	nni_posix_epdesc_close((void *) ep);
}

int
nni_plat_tcp_ep_listen(nni_plat_tcp_ep *ep, nng_sockaddr *bsa)
{
	int rv;
	rv = nni_posix_epdesc_listen((void *) ep);
	if ((rv == 0) && (bsa != NULL)) {
		rv = nni_posix_epdesc_sockname((void *) ep, bsa);
	}
	return (rv);
}

void
nni_plat_tcp_ep_connect(nni_plat_tcp_ep *ep, nni_aio *aio)
{
	nni_posix_epdesc_connect((void *) ep, aio);
}

void
nni_plat_tcp_ep_accept(nni_plat_tcp_ep *ep, nni_aio *aio)
{
	nni_posix_epdesc_accept((void *) ep, aio);
}

void
nni_plat_tcp_pipe_fini(nni_plat_tcp_pipe *p)
{
	nni_posix_pipedesc_fini((void *) p);
}

void
nni_plat_tcp_pipe_close(nni_plat_tcp_pipe *p)
{
	nni_posix_pipedesc_close((void *) p);
}

void
nni_plat_tcp_pipe_send(nni_plat_tcp_pipe *p, nni_aio *aio)
{
	nni_posix_pipedesc_send((void *) p, aio);
}

void
nni_plat_tcp_pipe_recv(nni_plat_tcp_pipe *p, nni_aio *aio)
{
	nni_posix_pipedesc_recv((void *) p, aio);
}

int
nni_plat_tcp_pipe_peername(nni_plat_tcp_pipe *p, nni_sockaddr *sa)
{
	return (nni_posix_pipedesc_peername((void *) p, sa));
}

int
nni_plat_tcp_pipe_sockname(nni_plat_tcp_pipe *p, nni_sockaddr *sa)
{
	return (nni_posix_pipedesc_sockname((void *) p, sa));
}

int
nni_plat_tcp_pipe_set_keepalive(nni_plat_tcp_pipe *p, bool v)
{
	return (nni_posix_pipedesc_set_keepalive((void *) p, v));
}

int
nni_plat_tcp_pipe_set_nodelay(nni_plat_tcp_pipe *p, bool v)
{
	return (nni_posix_pipedesc_set_nodelay((void *) p, v));
}

int
nni_plat_tcp_ntop(const nni_sockaddr *sa, char *ipstr, char *portstr)
{
	const void *ap;
	uint16_t    port;
	int         af;
	switch (sa->s_family) {
	case NNG_AF_INET:
		ap   = &sa->s_in.sa_addr;
		port = sa->s_in.sa_port;
		af   = AF_INET;
		break;
	case NNG_AF_INET6:
		ap   = &sa->s_in6.sa_addr;
		port = sa->s_in6.sa_port;
		af   = AF_INET6;
		break;
	default:
		return (NNG_EINVAL);
	}
	if (ipstr != NULL) {
		if (af == AF_INET6) {
			size_t l;
			ipstr[0] = '[';
			inet_ntop(af, ap, ipstr + 1, INET6_ADDRSTRLEN);
			l          = strlen(ipstr);
			ipstr[l++] = ']';
			ipstr[l++] = '\0';
		} else {
			inet_ntop(af, ap, ipstr, INET6_ADDRSTRLEN);
		}
	}
	if (portstr != NULL) {
#ifdef NNG_LITTLE_ENDIAN
		port = ((port >> 8) & 0xff) | ((port & 0xff) << 8);
#endif
		snprintf(portstr, 6, "%u", port);
	}
	return (0);
}

#endif // NNG_PLATFORM_POSIX
