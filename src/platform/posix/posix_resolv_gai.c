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

#ifdef NNG_USE_POSIX_RESOLV_GAI
#include "platform/posix/posix_aio.h"

#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <unistd.h>

// We use a single resolver taskq - but we allocate a few threads
// for it to ensure that names can be looked up concurrently.  This isn't
// as elegant or scaleable as a true asynchronous resolver would be, but
// it has the advantage of being fairly portable, and concurrent enough for
// the vast, vast majority of use cases.  The total thread count can be
// changed with this define.  Note that some platforms may not have a
// thread-safe getaddrinfo().  In that case they should set this to 1.

#ifndef NNG_POSIX_RESOLV_CONCURRENCY
#define NNG_POSIX_RESOLV_CONCURRENCY 4
#endif

static nni_taskq *resolv_tq = NULL;
static nni_mtx    resolv_mtx;

typedef struct resolv_item resolv_item;
struct resolv_item {
	int          family;
	int          passive;
	const char * name;
	const char * serv;
	int          proto;
	nni_aio *    aio;
	nni_task *   task;
	nng_sockaddr sa;
};

static void
resolv_finish(resolv_item *item, int rv)
{
	nni_aio *aio;

	if (((aio = item->aio) != NULL) &&
	    (nni_aio_get_prov_data(aio) == item)) {
		nng_sockaddr *sa = nni_aio_get_input(aio, 0);
		nni_aio_set_prov_data(aio, NULL);
		item->aio = NULL;
		memcpy(sa, &item->sa, sizeof(*sa));
		nni_aio_finish(aio, rv, 0);
		nni_task_fini(item->task);
		NNI_FREE_STRUCT(item);
	}
}

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
	item->aio = NULL;
	nni_mtx_unlock(&resolv_mtx);
	nni_aio_finish_error(aio, rv);
}

static int
nni_posix_gai_errno(int rv)
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

	default:
		return (NNG_ESYSERR);
	}
}

static void
resolv_task(void *arg)
{
	resolv_item *    item = arg;
	struct addrinfo  hints;
	struct addrinfo *results;
	struct addrinfo *probe;
	int              rv;

	nni_mtx_lock(&resolv_mtx);
	if (item->aio == NULL) {
		nni_mtx_unlock(&resolv_mtx);
		// Caller canceled, and no longer cares about this.
		nni_task_fini(item->task);
		NNI_FREE_STRUCT(item);
		return;
	}
	nni_mtx_unlock(&resolv_mtx);

	results = NULL;

	// We treat these all as IP addresses.  The service and the
	// host part are split.
	memset(&hints, 0, sizeof(hints));
	hints.ai_flags = AI_NUMERICSERV;
#ifdef AI_ADDRCONFIG
	hints.ai_flags |= AI_ADDRCONFIG;
#endif
	if (item->passive) {
		hints.ai_flags |= AI_PASSIVE;
	}
	hints.ai_protocol = item->proto;
	hints.ai_family   = item->family;

	rv = getaddrinfo(item->name, item->serv, &hints, &results);
	if (rv != 0) {
		rv = nni_posix_gai_errno(rv);
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
		nng_sockaddr *       sa = &item->sa;

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

	nni_mtx_lock(&resolv_mtx);
	resolv_finish(item, rv);
	nni_mtx_unlock(&resolv_mtx);
}

static void
resolv_ip(const char *host, const char *serv, int passive, int family,
    int proto, nni_aio *aio)
{
	resolv_item *item;
	sa_family_t  fam;
	int          rv;

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

	if ((rv = nni_task_init(&item->task, resolv_tq, resolv_task, item)) !=
	    0) {
		NNI_FREE_STRUCT(item);
		nni_aio_finish_error(aio, rv);
		return;
	};

	// NB: host and serv must remain valid until this is completed.
	memset(&item->sa, 0, sizeof(item->sa));
	item->passive = passive;
	item->name    = host;
	item->serv    = serv;
	item->proto   = proto;
	item->aio     = aio;
	item->family  = fam;

	nni_mtx_lock(&resolv_mtx);
	if ((rv = nni_aio_schedule(aio, resolv_cancel, item)) != 0) {
		nni_mtx_unlock(&resolv_mtx);
		nni_task_fini(item->task);
		NNI_FREE_STRUCT(item);
		nni_aio_finish_error(aio, rv);
		return;
	}
	nni_task_dispatch(item->task);
	nni_mtx_unlock(&resolv_mtx);
}

void
nni_plat_tcp_resolv(
    const char *host, const char *serv, int family, int passive, nni_aio *aio)
{
	resolv_ip(host, serv, passive, family, IPPROTO_TCP, aio);
}

void
nni_plat_udp_resolv(
    const char *host, const char *serv, int family, int passive, nni_aio *aio)
{
	resolv_ip(host, serv, passive, family, IPPROTO_UDP, aio);
}

int
nni_posix_resolv_sysinit(void)
{
	int rv;

	nni_mtx_init(&resolv_mtx);

	if ((rv = nni_taskq_init(&resolv_tq, 4)) != 0) {
		nni_mtx_fini(&resolv_mtx);
		return (rv);
	}
	return (0);
}

void
nni_posix_resolv_sysfini(void)
{
	if (resolv_tq != NULL) {
		nni_taskq_fini(resolv_tq);
		resolv_tq = NULL;
	}
	nni_mtx_fini(&resolv_mtx);
}

#endif // NNG_USE_POSIX_RESOLV_GAI
