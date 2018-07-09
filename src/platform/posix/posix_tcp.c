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
