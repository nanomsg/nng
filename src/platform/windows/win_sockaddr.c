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
#include "win_impl.h"

#include <string.h>

int
nni_win_nn2sockaddr(SOCKADDR_STORAGE *ss, const nni_sockaddr *sa)
{
	SOCKADDR_IN * sin;
	SOCKADDR_IN6 *sin6;

	if ((ss == NULL) || (sa == NULL)) {
		return (-1);
	}
	switch (sa->s_family) {
	case NNG_AF_INET:
		sin = (void *) ss;
		memset(sin, 0, sizeof(*sin));
		sin->sin_family      = PF_INET;
		sin->sin_port        = sa->s_in.sa_port;
		sin->sin_addr.s_addr = sa->s_in.sa_addr;
		return (sizeof(*sin));

	case NNG_AF_INET6:
		sin6 = (void *) ss;
		memset(sin6, 0, sizeof(*sin6));
		sin6->sin6_family = PF_INET6;
		sin6->sin6_port   = sa->s_in6.sa_port;
		memcpy(sin6->sin6_addr.s6_addr, sa->s_in6.sa_addr, 16);
		return (sizeof(*sin6));
	}
	return (-1);
}

int
nni_win_sockaddr2nn(nni_sockaddr *sa, const SOCKADDR_STORAGE *ss)
{
	SOCKADDR_IN * sin;
	SOCKADDR_IN6 *sin6;

	if ((ss == NULL) || (sa == NULL)) {
		return (-1);
	}
	switch (ss->ss_family) {
	case PF_INET:
		sin                = (void *) ss;
		sa->s_in.sa_family = NNG_AF_INET;
		sa->s_in.sa_port   = sin->sin_port;
		sa->s_in.sa_addr   = sin->sin_addr.s_addr;
		return (0);

	case PF_INET6:
		sin6                = (void *) ss;
		sa->s_in6.sa_family = NNG_AF_INET6;
		sa->s_in6.sa_port   = sin6->sin6_port;
		memcpy(sa->s_in6.sa_addr, sin6->sin6_addr.s6_addr, 16);
		return (0);
	}
	return (-1);
}
