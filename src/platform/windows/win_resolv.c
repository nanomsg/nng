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

#ifdef NNG_PLATFORM_WINDOWS

// Modern Windows has an asynchronous resolver, but there are problems
// with it, where looking up names in DNS can poison results for other
// uses, because the asynchronous resolver *only* considers DNS -- ignoring
// host file, WINS, or other naming services.  As a result, we just build
// our own limited asynchronous using a taskq.

// We use a single resolver taskq - but we allocate a few threads
// for it to ensure that names can be looked up concurrently.  This isn't
// as elegant or scaleable as a true asynchronous resolver would be, but
// it has the advantage of being fairly portable, and concurrent enough for
// the vast, vast majority of use cases.  The total thread count can be
// changed with this define.

#ifndef NNG_WIN_RESOLV_CONCURRENCY
#define NNG_WIN_RESOLV_CONCURRENCY 4
#endif

static nni_taskq *nni_win_resolv_tq = NULL;
static nni_mtx    nni_win_resolv_mtx;

typedef struct nni_win_resolv_item nni_win_resolv_item;
struct nni_win_resolv_item {
	int         family;
	int         passive;
	const char *name;
	const char *serv;
	int         proto;
	nni_aio *   aio;
	nni_task    task;
};

static void
nni_win_resolv_finish(nni_win_resolv_item *item, int rv)
{
	nni_aio *aio = item->aio;

	nni_aio_set_prov_data(aio, NULL);
	nni_aio_finish(aio, rv, 0);
	NNI_FREE_STRUCT(item);
}

static void
nni_win_resolv_cancel(nni_aio *aio, int rv)
{
	nni_win_resolv_item *item;

	nni_mtx_lock(&nni_win_resolv_mtx);
	if ((item = nni_aio_get_prov_data(aio)) == NULL) {
		nni_mtx_unlock(&nni_win_resolv_mtx);
		return;
	}
	nni_aio_set_prov_data(aio, NULL);
	nni_mtx_unlock(&nni_win_resolv_mtx);
	nni_task_cancel(&item->task);
	NNI_FREE_STRUCT(item);
	nni_aio_finish_error(aio, rv);
}

static int
nni_win_gai_errno(int rv)
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

static void
nni_win_resolv_task(void *arg)
{
	nni_win_resolv_item *item = arg;
	nni_aio *            aio  = item->aio;
	struct addrinfo      hints;
	struct addrinfo *    results;
	struct addrinfo *    probe;
	int                  rv;

	results = NULL;

	// We treat these all as IP addresses.  The service and the
	// host part are split.
	memset(&hints, 0, sizeof(hints));
	if (item->passive) {
		hints.ai_flags |= AI_PASSIVE;
	}
	hints.ai_flags |= AI_ADDRCONFIG;
	hints.ai_protocol = item->proto;
	hints.ai_family   = item->family;
	if (item->family == AF_INET6) {
		hints.ai_flags |= AI_V4MAPPED;
	}

	rv = getaddrinfo(item->name, item->serv, &hints, &results);
	if (rv != 0) {
		rv = nni_win_gai_errno(rv);
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
		nni_sockaddr *       sa = nni_aio_get_input(aio, 0);

		switch (probe->ai_addr->sa_family) {
		case AF_INET:
			rv                 = 0;
			sin                = (void *) probe->ai_addr;
			sa->s_in.sa_family = NNG_AF_INET;
			sa->s_in.sa_port   = sin->sin_port;
			sa->s_in.sa_addr   = sin->sin_addr.s_addr;
			break;
		case AF_INET6:
			rv                  = 0;
			sin6                = (void *) probe->ai_addr;
			sa->s_in6.sa_family = NNG_AF_INET6;
			sa->s_in6.sa_port   = sin6->sin6_port;
			memcpy(sa->s_in6.sa_addr, sin6->sin6_addr.s6_addr, 16);
			break;
		}
	}

done:

	if (results != NULL) {
		freeaddrinfo(results);
	}
	nni_mtx_lock(&nni_win_resolv_mtx);
	nni_win_resolv_finish(item, rv);
	nni_mtx_unlock(&nni_win_resolv_mtx);
}

static void
nni_win_resolv_ip(const char *host, const char *serv, int passive, int family,
    int proto, nni_aio *aio)
{
	nni_win_resolv_item *item;
	int                  fam;

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

	if ((item = NNI_ALLOC_STRUCT(item)) == NULL) {
		nni_aio_finish_error(aio, NNG_ENOMEM);
		return;
	}

	nni_task_init(
	    nni_win_resolv_tq, &item->task, nni_win_resolv_task, item);

	item->passive = passive;
	item->name    = host;
	item->serv    = serv;
	item->proto   = proto;
	item->aio     = aio;
	item->family  = fam;

	nni_mtx_lock(&nni_win_resolv_mtx);
	nni_aio_schedule(aio, nni_win_resolv_cancel, item);
	nni_task_dispatch(&item->task);
	nni_mtx_unlock(&nni_win_resolv_mtx);
}

void
nni_plat_tcp_resolv(
    const char *host, const char *serv, int family, int passive, nni_aio *aio)
{
	nni_win_resolv_ip(host, serv, passive, family, IPPROTO_TCP, aio);
}

void
nni_plat_udp_resolv(
    const char *host, const char *serv, int family, int passive, nni_aio *aio)
{
	nni_win_resolv_ip(host, serv, passive, family, IPPROTO_UDP, aio);
}

int
nni_win_resolv_sysinit(void)
{
	int rv;

	nni_mtx_init(&nni_win_resolv_mtx);

	if ((rv = nni_taskq_init(&nni_win_resolv_tq, 4)) != 0) {
		nni_mtx_fini(&nni_win_resolv_mtx);
		return (rv);
	}
	return (0);
}

void
nni_win_resolv_sysfini(void)
{
	if (nni_win_resolv_tq != NULL) {
		nni_taskq_fini(nni_win_resolv_tq);
		nni_win_resolv_tq = NULL;
	}
	nni_mtx_fini(&nni_win_resolv_mtx);
}

#endif // NNG_PLATFORM_WINDOWS
