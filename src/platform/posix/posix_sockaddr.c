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

#ifdef NNG_PLATFORM_POSIX

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>

#ifndef NNG_HAVE_INET6
#undef NNG_ENABLE_IPV6
#endif

size_t
nni_posix_nn2sockaddr(void *sa, const nni_sockaddr *na)
{
	struct sockaddr_in          *sin;
	struct sockaddr_un          *spath;
	const nng_sockaddr_in       *nsin;
	const nng_sockaddr_path     *nspath;
	const nng_sockaddr_abstract *nsabs;
	size_t                       sz;
#ifdef NNG_ENABLE_IPV6
	struct sockaddr_in6    *sin6;
	const nng_sockaddr_in6 *nsin6;
#endif

	if ((sa == NULL) || (na == NULL)) {
		return (0);
	}
	switch (na->s_family) {
	case NNG_AF_INET:
		sin  = (void *) sa;
		nsin = &na->s_in;
		memset(sin, 0, sizeof(*sin));
		sin->sin_family      = PF_INET;
		sin->sin_port        = nsin->sa_port;
		sin->sin_addr.s_addr = nsin->sa_addr;
		return (sizeof(*sin));

#ifdef NNG_ENABLE_IPV6
	case NNG_AF_INET6:
		sin6  = (void *) sa;
		nsin6 = &na->s_in6;
		memset(sin6, 0, sizeof(*sin6));
#ifdef SIN6_LEN
		sin6->sin6_len = sizeof(*sin6);
#endif
		sin6->sin6_family   = PF_INET6;
		sin6->sin6_port     = nsin6->sa_port;
		sin6->sin6_scope_id = nsin6->sa_scope;
		memcpy(sin6->sin6_addr.s6_addr, nsin6->sa_addr, 16);
		return (sizeof(*sin6));
#endif

	case NNG_AF_IPC:
		spath  = (void *) sa;
		nspath = &na->s_ipc;
		memset(spath, 0, sizeof(*spath));
		// Make sure that the path fits!
		sz = sizeof(spath->sun_path);
		if (nni_strlcpy(spath->sun_path, nspath->sa_path, sz) >= sz) {
			return (0);
		}
		spath->sun_family = PF_UNIX;
		return (sizeof(*spath));

	case NNG_AF_ABSTRACT:
		spath = (void *) sa;
		nsabs = &na->s_abstract;
		if (nsabs->sa_len >= sizeof(spath->sun_path)) {
			return (0);
		}
		memset(spath, 0, sizeof(*spath));
		spath->sun_family  = PF_UNIX;
		spath->sun_path[0] = '\0'; // abstract starts with nul

		// We support auto-bind with an empty string.  There is
		// a subtle caveat here, which is that we cannot bind to
		// the *empty* name.
		if (nsabs->sa_len == 0) {
			return (sizeof(sa_family_t)); // auto bind
		} else {
			memcpy(&spath->sun_path[1], nsabs->sa_name,
			    nsabs->sa_len);
			return (sizeof(sa_family_t) + 1 + nsabs->sa_len);
		}
	}
	return (0);
}

int
nni_posix_sockaddr2nn(nni_sockaddr *na, const void *sa, size_t sz)
{
	const struct sockaddr_in *sin;
	const struct sockaddr_un *spath;
	nng_sockaddr_in          *nsin;
	nng_sockaddr_path        *nspath;
	nng_sockaddr_abstract    *nsabs;
#ifdef NNG_ENABLE_IPV6
	const struct sockaddr_in6 *sin6;
	nng_sockaddr_in6          *nsin6;
#endif

	if ((na == NULL) || (sa == NULL)) {
		return (-1);
	}
	switch (((struct sockaddr *) sa)->sa_family) {
	case AF_INET:
		if (sz < sizeof(*sin)) {
			return (-1);
		}
		sin             = (void *) sa;
		nsin            = &na->s_in;
		nsin->sa_family = NNG_AF_INET;
		nsin->sa_port   = sin->sin_port;
		nsin->sa_addr   = sin->sin_addr.s_addr;
		break;

#ifdef NNG_ENABLE_IPV6
	case AF_INET6:
		if (sz < sizeof(*sin6)) {
			return (-1);
		}
		sin6             = (void *) sa;
		nsin6            = &na->s_in6;
		nsin6->sa_family = NNG_AF_INET6;
		nsin6->sa_port   = sin6->sin6_port;
		nsin6->sa_scope  = sin6->sin6_scope_id;
		memcpy(nsin6->sa_addr, sin6->sin6_addr.s6_addr, 16);
		break;
#endif

	case AF_UNIX:
		// AF_UNIX can be NNG_AF_IPC, or NNG_AF_ABSTRACT.
		spath = (void *) sa;
		if ((sz < sizeof(sa_family_t)) || (sz > sizeof(*spath))) {
			return (-1);
		}
		// Now we need to look more closely.
		sz -= sizeof(sa_family_t);
		if (sz == 0) {
			// Unnamed socket.  These will be treated using
			// auto-bind if we actually listen to them, and
			// it is impossible to connect them.
			nsabs            = &na->s_abstract;
			nsabs->sa_family = NNG_AF_ABSTRACT;
			nsabs->sa_len    = 0;
		} else if (spath->sun_path[0] == 0) {
			nsabs            = &na->s_abstract;
			nsabs->sa_family = NNG_AF_ABSTRACT;
			nsabs->sa_len    = sz - 1;
			memcpy(nsabs->sa_name, &spath->sun_path[1], sz - 1);
		} else {
			nspath            = &na->s_ipc;
			nspath->sa_family = NNG_AF_IPC;
			nni_strlcpy(nspath->sa_path, spath->sun_path,
			    sizeof(nspath->sa_path));
		}
		break;
	default:
		// We should never see this - the OS should always be
		// specific about giving us either AF_INET or AF_INET6.
		// Other address families are not handled here.
		return (-1);
	}
	return (0);
}

#endif // NNG_PLATFORM_POSIX
