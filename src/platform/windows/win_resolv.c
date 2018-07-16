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

#include <ctype.h>
#include <stdio.h>
#include <string.h>

#ifdef NNG_PLATFORM_WINDOWS

// Modern Windows has an asynchronous resolver, but there are problems
// with it, where looking up names in DNS can poison results for other
// uses, because the asynchronous resolver *only* considers DNS -- ignoring
// host file, WINS, or other naming services.  As a result, we just build
// our own limited asynchronous resolver with threads.

#ifndef NNG_WIN_RESOLV_CONCURRENCY
#define NNG_WIN_RESOLV_CONCURRENCY 4
#endif

static nni_mtx  resolv_mtx;
static nni_cv   resolv_cv;
static bool     resolv_fini;
static nni_list resolv_aios;
static nni_thr  resolv_thrs[NNG_WIN_RESOLV_CONCURRENCY];

typedef struct resolv_item resolv_item;
struct resolv_item {
	int          family;
	int          passive;
	const char * name;
	int          proto;
	uint16_t     port;
	nni_aio *    aio;
	nng_sockaddr sa;
};

static void
resolv_cancel(nni_aio *aio, int rv)
{
	resolv_item *item;

	nni_mtx_lock(&resolv_mtx);
	if ((item = nni_aio_get_prov_data(aio)) == NULL) {
		nni_mtx_unlock(&resolv_mtx);
		return;
	}
	nni_aio_set_prov_data(aio, NULL);
	if (nni_aio_list_active(aio)) {
		// We have not been picked up by a resolver thread yet,
		// so we can just discard everything.
		nni_aio_list_remove(aio);
		nni_mtx_unlock(&resolv_mtx);
		NNI_FREE_STRUCT(item);
	} else {
		// Resolver still working, so just unlink our AIO to
		// discard our interest in the results.
		item->aio = NULL;
		nni_mtx_unlock(&resolv_mtx);
	}
	nni_aio_finish_error(aio, rv);
}

static int
resolv_errno(int rv)
{
	switch (rv) {
	case 0:
		return (0);

	case WSA_NOT_ENOUGH_MEMORY:
		return (NNG_ENOMEM);

	case WSAHOST_NOT_FOUND:
	case WSATYPE_NOT_FOUND:
	case WSANO_DATA:
		return (NNG_EADDRINVAL);

	case WSAEINVAL:
		return (NNG_EINVAL);

	case WSAESOCKTNOSUPPORT:
	case WSAEAFNOSUPPORT:
		return (NNG_ENOTSUP);

	default:
		return (NNG_ESYSERR + rv);
	}
}

static int
resolv_task(resolv_item *item)
{
	struct addrinfo  hints;
	struct addrinfo *results;
	struct addrinfo *probe;
	int              rv;

	results = NULL;

	// We treat these all as IP addresses.  The service and the
	// host part are split.
	memset(&hints, 0, sizeof(hints));
	hints.ai_flags = AI_ADDRCONFIG | AI_NUMERICSERV;
	if (item->passive) {
		hints.ai_flags |= AI_PASSIVE;
	}
	hints.ai_protocol = item->proto;
	hints.ai_family   = item->family;

	if ((rv = getaddrinfo(item->name, "80", &hints, &results)) != 0) {
		rv = resolv_errno(rv);
		goto done;
	}

	// We only take the first matching address.  Presumably
	// DNS load balancing is done by the resolver/server.

	rv = NNG_EADDRINVAL;
	for (probe = results; probe != NULL; probe = probe->ai_next) {
		if ((probe->ai_addr->sa_family == AF_INET) ||
		    (probe->ai_addr->sa_family == AF_INET6)) {
			break;
		}
	}

	if (probe != NULL) {
		struct sockaddr_in * sin;
		struct sockaddr_in6 *sin6;
		nni_sockaddr *       sa = &item->sa;

		switch (probe->ai_addr->sa_family) {
		case AF_INET:
			rv                 = 0;
			sin                = (void *) probe->ai_addr;
			sa->s_in.sa_family = NNG_AF_INET;
			sa->s_in.sa_port   = item->port;
			sa->s_in.sa_addr   = sin->sin_addr.s_addr;
			break;
		case AF_INET6:
			rv                  = 0;
			sin6                = (void *) probe->ai_addr;
			sa->s_in6.sa_family = NNG_AF_INET6;
			sa->s_in6.sa_port   = item->port;
			memcpy(sa->s_in6.sa_addr, sin6->sin6_addr.s6_addr, 16);
			break;
		}
	}

done:

	if (results != NULL) {
		freeaddrinfo(results);
	}
	return (rv);
}

static void
resolv_ip(const char *host, const char *serv, int passive, int family,
    int proto, nni_aio *aio)
{
	resolv_item *item;
	int          fam;
	int          rv;
	int          port;

	if (nni_aio_begin(aio) != 0) {
		return;
	}
	switch (family) {
	case NNG_AF_INET:
		fam = AF_INET;
		break;
	case NNG_AF_INET6:
		fam = AF_INET6;
		break;
	case NNG_AF_UNSPEC:
		fam = AF_UNSPEC;
		break;
	default:
		nni_aio_finish_error(aio, NNG_ENOTSUP);
		return;
	}

	// We can't use the resolver to look up up ports with AI_NUMERICSERV,
	// because Windows' resolver is broken.  For example, the resolver
	// takes a port number of 1000000 and just rips off the high order
	// bits and lets it through!  (It seems to time out though, so
	// maybe it is ignoring AI_NUMERICSERV.)
	port = 0;
	if (serv != NULL) {
		while (isdigit(*serv)) {
			port *= 10;
			port += (*serv - '0');
			if (port > 0xffff) {
				// Port number out of range.
				nni_aio_finish_error(aio, NNG_EADDRINVAL);
				return;
			}
			serv++;
		}
		if (*serv != '\0') {
			nni_aio_finish_error(aio, NNG_EADDRINVAL);
			return;
		}
	}
	if ((port == 0) && (!passive)) {
		nni_aio_finish_error(aio, NNG_EADDRINVAL);
		return;
	}

	if ((item = NNI_ALLOC_STRUCT(item)) == NULL) {
		nni_aio_finish_error(aio, NNG_ENOMEM);
		return;
	}
	memset(&item->sa, 0, sizeof(item->sa));
	item->passive = passive;
	item->name    = host;
	item->proto   = proto;
	item->aio     = aio;
	item->family  = fam;
	item->port    = htons((uint16_t) port);

	nni_mtx_lock(&resolv_mtx);
	if (resolv_fini) {
		rv = NNG_ECLOSED;
	} else {
		rv = nni_aio_schedule(aio, resolv_cancel, item);
	}
	if (rv != 0) {
		nni_mtx_unlock(&resolv_mtx);
		NNI_FREE_STRUCT(item);
		nni_aio_finish_error(aio, rv);
		return;
	}
	nni_list_append(&resolv_aios, aio);
	nni_cv_wake1(&resolv_cv);
	nni_mtx_unlock(&resolv_mtx);
}

void
nni_tcp_resolv(
    const char *host, const char *serv, int family, int passive, nni_aio *aio)
{
	resolv_ip(host, serv, passive, family, IPPROTO_TCP, aio);
}

void
nni_udp_resolv(
    const char *host, const char *serv, int family, int passive, nni_aio *aio)
{
	resolv_ip(host, serv, passive, family, IPPROTO_UDP, aio);
}

void
resolv_worker(void *notused)
{

	NNI_ARG_UNUSED(notused);

	nni_mtx_lock(&resolv_mtx);
	for (;;) {
		nni_aio *    aio;
		resolv_item *item;
		int          rv;

		if ((aio = nni_list_first(&resolv_aios)) == NULL) {
			if (resolv_fini) {
				break;
			}
			nni_cv_wait(&resolv_cv);
			continue;
		}

		item = nni_aio_get_prov_data(aio);
		nni_aio_list_remove(aio);

		// Now attempt to do the work.  This runs synchronously.
		nni_mtx_unlock(&resolv_mtx);
		rv = resolv_task(item);
		nni_mtx_lock(&resolv_mtx);

		// Check to make sure we were not canceled.
		if ((aio = item->aio) != NULL) {
			nng_sockaddr *sa = nni_aio_get_input(aio, 0);
			nni_aio_set_prov_data(aio, NULL);
			item->aio = NULL;
			memcpy(sa, &item->sa, sizeof(*sa));
			nni_aio_finish(aio, rv, 0);

			NNI_FREE_STRUCT(item);
		}
	}
	nni_mtx_unlock(&resolv_mtx);
}

int
nni_ntop(const nni_sockaddr *sa, char *ipstr, char *portstr)
{
	void *   ap;
	uint16_t port;
	int      af;
	switch (sa->s_family) {
	case NNG_AF_INET:
		ap   = (void *) &sa->s_in.sa_addr;
		port = sa->s_in.sa_port;
		af   = AF_INET;
		break;
	case NNG_AF_INET6:
		ap   = (void *) &sa->s_in6.sa_addr;
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
			InetNtopA(af, ap, ipstr + 1, INET6_ADDRSTRLEN);
			l          = strlen(ipstr);
			ipstr[l++] = ']';
			ipstr[l++] = '\0';
		} else {
			InetNtopA(af, ap, ipstr, INET6_ADDRSTRLEN);
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

int
nni_win_resolv_sysinit(void)
{
	nni_mtx_init(&resolv_mtx);
	nni_cv_init(&resolv_cv, &resolv_mtx);
	nni_aio_list_init(&resolv_aios);

	resolv_fini = false;
	for (int i = 0; i < NNG_WIN_RESOLV_CONCURRENCY; i++) {
		int rv = nni_thr_init(&resolv_thrs[i], resolv_worker, NULL);
		if (rv != 0) {
			nni_win_resolv_sysfini();
			return (rv);
		}
	}
	for (int i = 0; i < NNG_WIN_RESOLV_CONCURRENCY; i++) {
		nni_thr_run(&resolv_thrs[i]);
	}
	return (0);
}

void
nni_win_resolv_sysfini(void)
{
	nni_mtx_lock(&resolv_mtx);
	resolv_fini = true;
	nni_cv_wake(&resolv_cv);
	nni_mtx_unlock(&resolv_mtx);
	for (int i = 0; i < NNG_WIN_RESOLV_CONCURRENCY; i++) {
		nni_thr_fini(&resolv_thrs[i]);
	}
	nni_cv_fini(&resolv_cv);
	nni_mtx_fini(&resolv_mtx);
}

#endif // NNG_PLATFORM_WINDOWS
