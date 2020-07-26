//
// Copyright 2020 Staysail Systems, Inc. <info@staysail.tech>
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

#ifndef NNG_RESOLV_CONCURRENCY
#define NNG_RESOLV_CONCURRENCY 4
#endif

static nni_mtx  resolv_mtx;
static nni_cv   resolv_cv;
static bool     resolv_fini;
static nni_list resolv_aios;
static nni_thr  resolv_thrs[NNG_RESOLV_CONCURRENCY];

typedef struct resolv_item resolv_item;
struct resolv_item {
	int          family;
	int          passive;
	char *       name;
	int          proto;
	int          socktype;
	uint16_t     port;
	nni_aio *    aio;
	nng_sockaddr sa;
};

static void
resolv_cancel(nni_aio *aio, void *arg, int rv)
{
	resolv_item *item = arg;

	nni_mtx_lock(&resolv_mtx);
	if (item != nni_aio_get_prov_extra(aio, 0)) {
		nni_mtx_unlock(&resolv_mtx);
		return;
	}
	nni_aio_set_prov_extra(aio, 0, NULL);
	if (nni_aio_list_active(aio)) {
		// We have not been picked up by a resolver thread yet,
		// so we can just discard everything.
		nni_aio_list_remove(aio);
		nni_mtx_unlock(&resolv_mtx);
		nni_strfree(item->name);
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
	hints.ai_socktype = item->socktype;

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

	if ((probe != NULL) && (item->aio != NULL)) {
		struct sockaddr_in * sin;
		struct sockaddr_in6 *sin6;
		nni_sockaddr         sa;

		switch (probe->ai_addr->sa_family) {
		case AF_INET:
			rv                = 0;
			sin               = (void *) probe->ai_addr;
			sa.s_in.sa_family = NNG_AF_INET;
			sa.s_in.sa_port   = item->port;
			sa.s_in.sa_addr   = sin->sin_addr.s_addr;
			nni_aio_set_sockaddr(item->aio, &sa);
			break;
		case AF_INET6:
			rv                 = 0;
			sin6               = (void *) probe->ai_addr;
			sa.s_in6.sa_family = NNG_AF_INET6;
			sa.s_in6.sa_port   = item->port;
			memcpy(sa.s_in6.sa_addr, sin6->sin6_addr.s6_addr, 16);
			nni_aio_set_sockaddr(item->aio, &sa);
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
    int proto, int socktype, nni_aio *aio)
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
	if (host == NULL) {
		item->name = NULL;
	} else if ((item->name = nni_strdup(host)) == NULL) {
		nni_aio_finish_error(aio, NNG_ENOMEM);
		NNI_FREE_STRUCT(item);
		return;
	}

	memset(&item->sa, 0, sizeof(item->sa));
	item->passive  = passive;
	item->proto    = proto;
	item->aio      = aio;
	item->family   = fam;
	item->socktype = socktype;
	item->port     = htons((uint16_t) port);

	nni_mtx_lock(&resolv_mtx);
	if (resolv_fini) {
		rv = NNG_ECLOSED;
	} else {
		nni_aio_set_prov_extra(aio, 0, item);
		rv = nni_aio_schedule(aio, resolv_cancel, item);
	}
	if (rv != 0) {
		nni_mtx_unlock(&resolv_mtx);
		nni_strfree(item->name);
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
	resolv_ip(host, serv, passive, family, IPPROTO_TCP, SOCK_STREAM, aio);
}

void
nni_udp_resolv(
    const char *host, const char *serv, int family, int passive, nni_aio *aio)
{
	resolv_ip(host, serv, passive, family, IPPROTO_UDP, SOCK_DGRAM, aio);
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

		item = nni_aio_get_prov_extra(aio, 0);
		nni_aio_list_remove(aio);

		// Now attempt to do the work.  This runs synchronously.
		nni_mtx_unlock(&resolv_mtx);
		rv = resolv_task(item);
		nni_mtx_lock(&resolv_mtx);

		// Check to make sure we were not canceled.
		if ((aio = item->aio) != NULL) {
			nni_aio_set_prov_extra(aio, 0, NULL);
			item->aio = NULL;

			nni_aio_finish(aio, rv, 0);
		}
		nni_strfree(item->name);
		NNI_FREE_STRUCT(item);
	}
	nni_mtx_unlock(&resolv_mtx);
}

int
parse_ip(const char *addr, nng_sockaddr *sa, bool want_port)
{
	struct addrinfo  hints;
	struct addrinfo *results;
	int              rv;
	bool             v6      = false;
	bool             wrapped = false;
	char *           port;
	char *           host;
	char *           buf;
	size_t           buf_len;

	if (addr == NULL) {
		addr = "";
	}

	buf_len = strlen(addr) + 1;
	if ((buf = nni_alloc(buf_len)) == NULL) {
		return (NNG_ENOMEM);
	}
	memcpy(buf, addr, buf_len);
	host = buf;
	if (*host == '[') {
		v6      = true;
		wrapped = true;
		host++;
	} else {
		char *s;
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
	hints.ai_flags =
	    AI_ADDRCONFIG | AI_NUMERICSERV | AI_NUMERICHOST | AI_PASSIVE;
	if (v6) {
		hints.ai_family = AF_INET6;
	}

	rv = getaddrinfo(host, port, &hints, &results);
	if ((rv != 0) || (results == NULL)) {
		rv = nni_win_error(rv);
		goto done;
	}
	nni_win_sockaddr2nn(sa, (void *) results->ai_addr);
	freeaddrinfo(results);

done:
	nni_free(buf, buf_len);
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
nni_win_resolv_sysinit(void)
{
	nni_mtx_init(&resolv_mtx);
	nni_cv_init(&resolv_cv, &resolv_mtx);
	nni_aio_list_init(&resolv_aios);

	resolv_fini = false;
	for (int i = 0; i < NNG_RESOLV_CONCURRENCY; i++) {
		int rv = nni_thr_init(&resolv_thrs[i], resolv_worker, NULL);
		if (rv != 0) {
			nni_win_resolv_sysfini();
			return (rv);
		}
	}
	for (int i = 0; i < NNG_RESOLV_CONCURRENCY; i++) {
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
	for (int i = 0; i < NNG_RESOLV_CONCURRENCY; i++) {
		nni_thr_fini(&resolv_thrs[i]);
	}
	nni_cv_fini(&resolv_cv);
	nni_mtx_fini(&resolv_mtx);
}

#endif // NNG_PLATFORM_WINDOWS
