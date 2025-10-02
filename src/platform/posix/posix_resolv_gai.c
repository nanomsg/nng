//
// Copyright 2025 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "core/defs.h"
#include "core/init.h"
#include "core/nng_impl.h"

#ifdef NNG_USE_POSIX_RESOLV_GAI

#include <ctype.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>

// We use a single resolver taskq - but we allocate a few threads
// for it to ensure that names can be looked up concurrently.  This isn't
// as elegant or scalable as a true asynchronous resolver would be, but
// it has the advantage of being fairly portable, and concurrent enough for
// the vast majority of use cases.  The total thread count can be
// changed with this define.  Note that some platforms may not have a
// thread-safe getaddrinfo().  In that case they should set this to 1.

#ifndef AI_NUMERICSERV
#define AI_NUMERICSERV 0
#endif

#ifndef NNG_HAVE_INET6
#ifdef HAVE_NNG_HAVE_INET6_BSD
#define NNG_HAVE_INET6
#include <netinet6/in6.h>
#else
#undef NNG_ENABLE_IPV6
#endif
#endif

static bool      resolv_fini = false;
static nni_list  resolv_aios;
static nni_thr  *resolv_thrs;
static nni_aio **resolv_active;
static int16_t   resolv_num_thr;
static nni_mtx   resolv_mtx;
static nni_cv    resolv_cv;

static void
resolv_cancel(nni_aio *aio, void *arg, nng_err rv)
{
	nni_resolv_item *item = arg;

	nni_mtx_lock(&resolv_mtx);
	if (item != nni_aio_get_prov_data(aio)) {
		// Already canceled?
		nni_mtx_unlock(&resolv_mtx);
		return;
	}
	nni_aio_set_prov_data(aio, NULL);
	if (nni_aio_list_active(aio)) {
		// We have not been picked up by a resolver thread yet,
		// so we can just discard everything.
		nni_aio_list_remove(aio);
	} else {
		// Remove it from the thread pending list.  We cannot abort
		// the actual lookup, but this abandons interest in it, and
		// the resolver thread will pick the next item when done.
		for (int i = 0; i < resolv_num_thr; i++) {
			if (resolv_active[i] == aio) {
				resolv_active[i] = NULL;
				break;
			}
		}
	}
	nni_mtx_unlock(&resolv_mtx);
	nni_aio_finish_error(aio, rv);
}

static int
posix_gai_errno(int rv)
{
	switch (rv) {
	case 0:
		return (0);

	case EAI_MEMORY:
		return (NNG_ENOMEM);

	case EAI_SYSTEM:
		return (nni_plat_errno(errno));

	case EAI_NONAME:
#ifdef EAI_NODATA
	case EAI_NODATA:
#endif
	case EAI_SERVICE:
		return (NNG_EADDRINVAL);

	case EAI_BADFLAGS:
		return (NNG_EINVAL);

	case EAI_SOCKTYPE:
		return (NNG_ENOTSUP);

#ifdef EAI_CANCELED
	case EAI_CANCELED:
		return (NNG_ECANCELED);
#endif

#ifdef EAI_AGAIN
	case EAI_AGAIN:
		// EAE_AGAIN means a temporary failure in name resolution.
		// While that doesn't mean the address is invalid, it's the
		// closest error code we currently have. This was previously
		// mapped to NNG_EAGAIN, but that error code is used to
		// indicate that non-blocking operations would block, so would
		// be confusing to callers.
		return (NNG_EADDRINVAL);
#endif

	default:
		return (NNG_ESYSERR + rv);
	}
}

void
nni_resolv(nni_resolv_item *item, nni_aio *aio)
{
	nni_aio_reset(aio);
	if (item->ri_host != NULL) {
		if ((strlen(item->ri_host) >= 256) ||
		    (strcmp(item->ri_host, "*") == 0)) {
			nni_aio_finish_error(aio, NNG_EADDRINVAL);
			return;
		}
	}

	nni_mtx_lock(&resolv_mtx);
	nni_aio_set_prov_data(aio, item);
	if (!nni_aio_start(aio, resolv_cancel, item)) {
		nni_mtx_unlock(&resolv_mtx);
		return;
	}

	if (resolv_fini) {
		nni_mtx_unlock(&resolv_mtx);
		nni_aio_finish_error(aio, NNG_ECLOSED);
		return;
	}
	nni_list_append(&resolv_aios, aio);
	nni_cv_wake1(&resolv_cv);
	nni_mtx_unlock(&resolv_mtx);
}

void
resolv_worker(void *index)
{
	int              tid = (int) (intptr_t) index;
	struct addrinfo  hints;
	struct addrinfo *results;
	struct addrinfo *probe;
	int              rv;
	char             serv[8];
	char             host[256];
	nni_aio         *aio;
	nni_resolv_item *item;

	nni_thr_set_name(NULL, "nng:resolver");

	nni_mtx_lock(&resolv_mtx);
	for (;;) {

		if ((aio = nni_list_first(&resolv_aios)) == NULL) {
			if (resolv_fini) {
				break;
			}
			nni_cv_wait(&resolv_cv);
			continue;
		}

		item = nni_aio_get_prov_data(aio);
		nni_aio_list_remove(aio);
		resolv_active[tid] = aio;

		snprintf(host, sizeof(host), "%s",
		    item->ri_host ? item->ri_host : "");
		snprintf(serv, sizeof(serv), "%u", item->ri_port);

		// We treat these all as IP addresses.  The service and the
		// host part are split.
		memset(&hints, 0, sizeof(hints));

		results = NULL;

		switch (item->ri_family) {
		case NNG_AF_INET:
			hints.ai_family = AF_INET;
			break;

#ifdef NNG_ENABLE_IPV6
		case NNG_AF_INET6:
			hints.ai_family = AF_INET6;
			break;
		case NNG_AF_UNSPEC:
			hints.ai_family = AF_UNSPEC;
			break;
#else
		case NNG_AF_UNSPEC:
			hints.ai_family = AF_INET;
			break;
#endif
		default:
			resolv_active[tid] = NULL;
			nni_aio_finish_error(aio, NNG_ENOTSUP);
			continue;
		}

#ifdef AI_ADDRCONFIG
		hints.ai_flags = AI_ADDRCONFIG;
#endif
		if (item->ri_passive) {
			hints.ai_flags |= AI_PASSIVE;
		}
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_flags |= AI_NUMERICSERV;

		// We can pass any non-zero service number, but we have to pass
		// *something*, in case we are using a NULL hostname.  The lock
		// is dropped to allow other submissions, and other threads to
		// process.
		nni_mtx_unlock(&resolv_mtx);
		rv = getaddrinfo(
		    host[0] != 0 ? host : NULL, serv, &hints, &results);
		nni_mtx_lock(&resolv_mtx);

		if ((aio = resolv_active[tid]) == NULL) {
			// no more interest (canceled), so ignore the result
			// and carry on
			if (rv == 0) {
				freeaddrinfo(results);
			}
			continue;
		}
		resolv_active[tid] = NULL;

		if (rv != 0) {
			rv = posix_gai_errno(rv);
			nni_aio_finish_error(aio, rv);
			continue;
		}

		// We only take the first matching address.  Presumably
		// DNS load balancing is done by the resolver/server.

		for (probe = results; probe != NULL; probe = probe->ai_next) {
			if (probe->ai_addr->sa_family == AF_INET) {
				break;
			}
#ifdef NNG_ENABLE_IPV6
			if (probe->ai_addr->sa_family == AF_INET6) {
				break;
			}
#endif
		}

		if (probe == NULL) {
			// no match
			nni_aio_finish_error(aio, NNG_EADDRINVAL);
			freeaddrinfo(results);
			continue;
		}

		item = nni_aio_get_prov_data(aio);
		nni_aio_set_prov_data(aio, NULL);
		NNI_ASSERT(item != NULL);

		(void) nni_posix_sockaddr2nn(
		    item->ri_sa, probe->ai_addr, probe->ai_addrlen);

		freeaddrinfo(results);
		nni_aio_finish(aio, 0, 0);
	}
	nni_mtx_unlock(&resolv_mtx);
}

int
parse_ip(const char *addr, nng_sockaddr *sa, bool want_port)
{
	struct addrinfo  hints;
	struct addrinfo *results;
	int              rv;
	char            *port;
	char            *host;
	char             buf[64];

#ifdef NNG_ENABLE_IPV6
	bool  v6      = false;
	bool  wrapped = false;
	char *s;
#endif

	if (addr == NULL) {
		addr = "";
	}

	snprintf(buf, sizeof(buf), "%s", addr);
	host = buf;
#ifdef NNG_ENABLE_IPV6
	if (*host == '[') {
		v6      = true;
		wrapped = true;
		host++;
	} else {
		for (s = host; *s != '\0'; s++) {
			if (*s == '.') {
				break;
			}
			if (*s == ':') {
				v6 = true;
				break;
			}
		}
	}
	for (port = host; *port != '\0'; port++) {
		if (wrapped) {
			if (*port == ']') {
				*port++ = '\0';
				wrapped = false;
				break;
			}
		} else if (!v6) {
			if (*port == ':') {
				break;
			}
		}
	}

	if (wrapped) {
		// Never got the closing bracket.
		rv = NNG_EADDRINVAL;
		goto done;
	}
#else  // NNG_ENABLE_IPV6
	for (port = host; *port != '\0'; port++) {
		if (*port == ':') {
			break;
		}
	}
#endif // NNG_ENABLE_IPV6

	if ((!want_port) && (*port != '\0')) {
		rv = NNG_EADDRINVAL;
		goto done;
	} else if (*port == ':') {
		*port++ = '\0';
	}

	if (*port == '\0') {
		port = "0";
	}

	memset(&hints, 0, sizeof(hints));
	hints.ai_flags = AI_NUMERICSERV | AI_NUMERICHOST | AI_PASSIVE;
#ifdef NNG_ENABLE_IPV6
	if (v6) {
		hints.ai_family = AF_INET6;
	}
#else
	hints.ai_family = AF_INET;
#endif
#ifdef AI_ADDRCONFIG
	hints.ai_flags |= AI_ADDRCONFIG;
#endif

	rv = getaddrinfo(host, port, &hints, &results);
	if ((rv != 0) || (results == NULL)) {
		rv = nni_plat_errno(rv);
		goto done;
	}
	nni_posix_sockaddr2nn(
	    sa, (void *) results->ai_addr, results->ai_addrlen);
	freeaddrinfo(results);

done:
	return (rv);
}

int
nni_parse_ip(const char *addr, nni_sockaddr *sa)
{
	return (parse_ip(addr, sa, false));
}

int
nni_parse_ip_port(const char *addr, nni_sockaddr *sa)
{
	return (parse_ip(addr, sa, true));
}

int
nni_get_port_by_name(const char *name, uint32_t *portp)
{
	struct servent *se;
	long            port;
	char           *end = NULL;

	port = strtol(name, &end, 10);
	if ((*end == '\0') && (port >= 0) && (port <= 0xffff)) {
		*portp = (uint16_t) port;
		return (0);
	}

	if ((se = getservbyname(name, "tcp")) != NULL) {
		*portp = (uint16_t) ntohs(se->s_port);
		return (0);
	}
	return (NNG_EADDRINVAL);
}

void
nni_posix_resolv_sysfini(void)
{
	nni_mtx_lock(&resolv_mtx);
	resolv_fini = true;
	nni_cv_wake(&resolv_cv);
	nni_mtx_unlock(&resolv_mtx);

	if (resolv_thrs != NULL) {
		for (int i = 0; i < resolv_num_thr; i++) {
			nni_thr_fini(&resolv_thrs[i]);
		}
		NNI_FREE_STRUCTS(resolv_thrs, resolv_num_thr);
	}
	if (resolv_active != NULL) {
		nni_free(resolv_active, sizeof(nni_aio *) * resolv_num_thr);
	}
	nni_cv_fini(&resolv_cv);
	nni_mtx_fini(&resolv_mtx);
}

int
nni_posix_resolv_sysinit(nng_init_params *params)
{
	nni_mtx_init(&resolv_mtx);
	nni_cv_init(&resolv_cv, &resolv_mtx);
	resolv_fini = false;
	nni_aio_list_init(&resolv_aios);

	resolv_num_thr = params->num_resolver_threads;
	if (resolv_num_thr < 1) {
		resolv_num_thr = 1;
	}
	params->num_resolver_threads = resolv_num_thr;
	// no limit on the maximum for now
	resolv_thrs   = NNI_ALLOC_STRUCTS(resolv_thrs, resolv_num_thr);
	resolv_active = nni_zalloc(sizeof(nni_aio *) * resolv_num_thr);
	if (resolv_thrs == NULL || resolv_active == NULL) {
		nni_posix_resolv_sysfini();
		return (NNG_ENOMEM);
	}

	for (int i = 0; i < resolv_num_thr; i++) {
		int rv = nni_thr_init(
		    &resolv_thrs[i], resolv_worker, (void *) (intptr_t) i);
		if (rv != 0) {
			nni_posix_resolv_sysfini();
			return (rv);
		}
	}
	for (int i = 0; i < resolv_num_thr; i++) {
		nni_thr_run(&resolv_thrs[i]);
	}

	return (0);
}

#endif // NNG_USE_POSIX_RESOLV_GAI
