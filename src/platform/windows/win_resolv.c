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

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#ifdef NNG_PLATFORM_WINDOWS

// Modern Windows has an asynchronous resolver, but there are problems
// with it, where looking up names in DNS can poison results for other
// uses, because the asynchronous resolver *only* considers DNS -- ignoring
// host file, WINS, or other naming services.  As a result, we just build
// our own limited asynchronous resolver with threads.

static nni_mtx  resolv_mtx  = NNI_MTX_INITIALIZER;
static nni_cv   resolv_cv   = NNI_CV_INITIALIZER(&resolv_mtx);
static bool     resolv_fini = false;
static nni_list resolv_aios;
static nni_thr *resolv_thrs;
static int16_t  resolv_num_thr;

typedef struct resolv_item resolv_item;
struct resolv_item {
	int           family;
	bool          passive;
	char          host[256];
	char          serv[8];
	nni_aio      *aio;
	nng_sockaddr *sa;
};

static void
resolv_free_item(resolv_item *item)
{
	NNI_FREE_STRUCT(item);
}

static void
resolv_cancel(nni_aio *aio, void *arg, int rv)
{
	resolv_item *item = arg;

	nni_mtx_lock(&resolv_mtx);
	if (item != nni_aio_get_prov_data(aio)) {
		nni_mtx_unlock(&resolv_mtx);
		return;
	}
	nni_aio_set_prov_data(aio, NULL);
	if (nni_aio_list_active(aio)) {
		// We have not been picked up by a resolver thread yet,
		// so we can just discard everything.
		nni_aio_list_remove(aio);
		nni_mtx_unlock(&resolv_mtx);
		resolv_free_item(item);
	} else {
		// Resolver still working, so just unlink our AIO to
		// discard our interest in the results.
		item->aio = NULL;
		item->sa  = NULL;
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

	memset(&hints, 0, sizeof(hints));
	hints.ai_flags = AI_ADDRCONFIG;
	if (item->passive) {
		hints.ai_flags |= AI_PASSIVE;
	}
	hints.ai_family   = item->family;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags |= AI_NUMERICSERV;

	if ((rv = getaddrinfo(item->host[0] != 0 ? item->host : NULL,
	         item->serv, &hints, &results)) != 0) {
		rv = resolv_errno(rv);
		goto done;
	}

	// We only take the first matching address.  Presumably
	// DNS load balancing is done by the resolver/server.

	rv = NNG_EADDRINVAL;
	for (probe = results; probe != NULL; probe = probe->ai_next) {
		if (probe->ai_addr->sa_family == AF_INET) {
			break;
		}
#if NNG_ENABLE_IPV6
		if (probe->ai_addr->sa_family == AF_INET6) {
			break;
		}
#endif
	}

	nni_mtx_lock(&resolv_mtx);
	if ((probe != NULL) && (item->aio != NULL)) {
		struct sockaddr_in *sin;
#ifdef NNG_ENABLE_IPV6
		struct sockaddr_in6 *sin6;
#endif
		nni_sockaddr *sa;

		sa = item->sa;

		switch (probe->ai_addr->sa_family) {
		case AF_INET:
			rv                 = 0;
			sin                = (void *) probe->ai_addr;
			sa->s_in.sa_family = NNG_AF_INET;
			sa->s_in.sa_port   = sin->sin_port;
			sa->s_in.sa_addr   = sin->sin_addr.s_addr;
			break;
#ifdef NNG_ENABLE_IPV6
		case AF_INET6:
			rv                  = 0;
			sin6                = (void *) probe->ai_addr;
			sa->s_in6.sa_family = NNG_AF_INET6;
			sa->s_in6.sa_port   = sin6->sin6_port;
			sa->s_in6.sa_scope  = sin6->sin6_scope_id;
			memcpy(sa->s_in6.sa_addr, sin6->sin6_addr.s6_addr, 16);
			break;
#endif
		}
	}
	nni_mtx_unlock(&resolv_mtx);

done:

	if (results != NULL) {
		freeaddrinfo(results);
	}
	return (rv);
}

void
nni_resolv_ip(const char *host, uint16_t port, int family, bool passive,
    nng_sockaddr *sa, nni_aio *aio)
{
	resolv_item *item;
	int          fam;
	int          rv;

	if (nni_aio_begin(aio) != 0) {
		return;
	}
	if (host != NULL) {
		if ((strlen(host) >= sizeof(item->host)) ||
		    (strcmp(host, "*") == 0)) {
			nni_aio_finish_error(aio, NNG_EADDRINVAL);
			return;
		}
	}
	switch (family) {
	case NNG_AF_INET:
		fam = AF_INET;
		break;
#ifdef NNG_ENABLE_IPV6
	case NNG_AF_INET6:
		fam = AF_INET6;
		break;
	case NNG_AF_UNSPEC:
		fam = AF_UNSPEC;
		break;
#else
	case NNG_AF_UNSPEC:
		fam = AF_INET;
		break;
#endif
	default:
		nni_aio_finish_error(aio, NNG_ENOTSUP);
		return;
	}

	if ((item = NNI_ALLOC_STRUCT(item)) == NULL) {
		nni_aio_finish_error(aio, NNG_ENOMEM);
		return;
	}

	snprintf(item->serv, sizeof(item->serv), "%u", port);
	if (host == NULL) {
		item->host[0] = '\0';
	} else {
		snprintf(item->host, sizeof(item->host), "%s", host);
	}

	item->sa      = sa;
	item->passive = passive;
	item->aio     = aio;
	item->family  = fam;

	nni_mtx_lock(&resolv_mtx);
	if (resolv_fini) {
		rv = NNG_ECLOSED;
	} else {
		nni_aio_set_prov_data(aio, item);
		rv = nni_aio_schedule(aio, resolv_cancel, item);
	}
	if (rv != 0) {
		nni_mtx_unlock(&resolv_mtx);
		resolv_free_item(item);
		nni_aio_finish_error(aio, rv);
		return;
	}
	nni_list_append(&resolv_aios, aio);
	nni_cv_wake1(&resolv_cv);
	nni_mtx_unlock(&resolv_mtx);
}

void
resolv_worker(void *notused)
{

	NNI_ARG_UNUSED(notused);

	nni_mtx_lock(&resolv_mtx);
	for (;;) {
		nni_aio     *aio;
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
			nni_aio_set_prov_data(aio, NULL);
			item->aio = NULL;
			item->sa  = NULL;

			nni_aio_finish(aio, rv, 0);
		}
		resolv_free_item(item);
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
	char            *buf;
	size_t           buf_len;
#ifdef NNG_ENABLE_IPV6
	bool  v6      = false;
	bool  wrapped = false;
	char *s;
#endif

	if (addr == NULL) {
		addr = "";
	}

	buf_len = strlen(addr) + 1;
	if ((buf = nni_alloc(buf_len)) == NULL) {
		return (NNG_ENOMEM);
	}
	memcpy(buf, addr, buf_len);
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
#else // NNG_ENABLE_IPV6
	for (port = host; *port != '\0'; port++) {
		if (*port == ':') {
			break;
		}
	}
#endif

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
#ifdef NNG_ENABLE_IPV6
	if (v6) {
		hints.ai_family = AF_INET6;
	}
#else
	hints.ai_family = AF_INET;
#endif

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

int
nni_win_resolv_sysinit(nng_init_params *params)
{
	nni_aio_list_init(&resolv_aios);
	resolv_fini = false;

	resolv_num_thr = params->num_resolver_threads;
	if (resolv_num_thr < 1) {
		resolv_num_thr = 1;
	}
	params->num_resolver_threads = resolv_num_thr;

	// no limit on the maximum for now
	resolv_thrs = NNI_ALLOC_STRUCTS(resolv_thrs, resolv_num_thr);
	if (resolv_thrs == NULL) {
		return (NNG_ENOMEM);
	}

	for (int16_t i = 0; i < resolv_num_thr; i++) {
		int rv = nni_thr_init(&resolv_thrs[i], resolv_worker, NULL);
		if (rv != 0) {
			nni_win_resolv_sysfini();
			return (rv);
		}
		nni_thr_set_name(&resolv_thrs[i], "nng:resolver");
	}
	for (int i = 0; i < resolv_num_thr; i++) {
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
	for (int i = 0; i < resolv_num_thr; i++) {
		nni_thr_fini(&resolv_thrs[i]);
	}
	NNI_FREE_STRUCTS(resolv_thrs, resolv_num_thr);
}

#endif // NNG_PLATFORM_WINDOWS
