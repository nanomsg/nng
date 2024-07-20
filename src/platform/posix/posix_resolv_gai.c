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

#ifdef NNG_USE_POSIX_RESOLV_GAI

#include <ctype.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
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
#undef NNG_ENABLE_IPV6
#endif

static nni_mtx  resolv_mtx  = NNI_MTX_INITIALIZER;
static nni_cv   resolv_cv   = NNI_CV_INITIALIZER(&resolv_mtx);
static bool     resolv_fini = false;
static nni_list resolv_aios;
static nni_thr *resolv_thrs;
static int      resolv_num_thr;

typedef struct resolv_item resolv_item;
struct resolv_item {
	int           family;
	bool          passive;
	char         *host;
	char         *serv;
	nni_aio      *aio;
	nng_sockaddr *sa;
};

static void
resolv_free_item(resolv_item *item)
{
	nni_strfree(item->serv);
	nni_strfree(item->host);
	NNI_FREE_STRUCT(item);
}

static void
resolv_cancel(nni_aio *aio, void *arg, int rv)
{
	resolv_item *item = arg;

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
		nni_mtx_unlock(&resolv_mtx);
		resolv_free_item(item);
	} else {
		// This case indicates the resolver is still processing our
		// node. We can discard our interest in the result, but we
		// can't interrupt the resolver itself.  (Too bad, name
		// resolution is utterly synchronous for now.)
		item->aio = NULL;
		item->sa  = NULL;
		nni_mtx_unlock(&resolv_mtx);
	}
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
		return (NNG_EAGAIN);
#endif

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
#ifdef AI_ADDRCONFIG
	hints.ai_flags = AI_ADDRCONFIG;
#endif
	if (item->passive) {
		hints.ai_flags |= AI_PASSIVE;
	}
	hints.ai_family   = item->family;
	hints.ai_socktype = SOCK_STREAM;

	// Check to see if this is a numeric port number, and if it is
	// make sure that it's in the valid range (because Windows may
	// incorrectly simple do a conversion and mask off upper bits.
	if (item->serv != NULL) {
		long  port;
		char *end;
		port = strtol(item->serv, &end, 10);
		if (*end == '\0') { // we fully converted it as a number...
			hints.ai_flags |= AI_NUMERICSERV;

			// Not a valid port number.  Fail.
			if ((port < 0) || (port > 0xffff)) {
				rv = NNG_EADDRINVAL;
				goto done;
			}
		}
	}

	// We can pass any non-zero service number, but we have to pass
	// *something*, in case we are using a NULL hostname.
	if ((rv = getaddrinfo(item->host, item->serv, &hints, &results)) !=
	    0) {
		rv = posix_gai_errno(rv);
		goto done;
	}

	// We only take the first matching address.  Presumably
	// DNS load balancing is done by the resolver/server.

	rv = NNG_EADDRINVAL;
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

	nni_mtx_lock(&resolv_mtx);
	if ((probe != NULL) && (item->aio != NULL)) {
		struct sockaddr_in *sin;
#ifdef NNG_ENABLE_IPV6
		struct sockaddr_in6 *sin6;
#endif
		nng_sockaddr *sa = item->sa;

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
nni_resolv_ip(const char *host, const char *serv, uint16_t af, bool passive,
    nng_sockaddr *sa, nni_aio *aio)
{
	resolv_item *item;
	sa_family_t  fam;
	int          rv;

	if (nni_aio_begin(aio) != 0) {
		return;
	}
	switch (af) {
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

	if (serv == NULL || strcmp(serv, "") == 0) {
		item->serv = NULL;
	} else if ((item->serv = nni_strdup(serv)) == NULL) {
		nni_aio_finish_error(aio, NNG_ENOMEM);
		resolv_free_item(item);
		return;
	}
	if (host == NULL) {
		item->host = NULL;
	} else if ((item->host = nni_strdup(host)) == NULL) {
		nni_aio_finish_error(aio, NNG_ENOMEM);
		resolv_free_item(item);
		return;
	}

	item->aio     = aio;
	item->family  = fam;
	item->passive = passive;
	item->sa      = sa;

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
resolv_worker(void *unused)
{

	NNI_ARG_UNUSED(unused);

	nni_thr_set_name(NULL, "nng:resolver");

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
nni_posix_resolv_sysinit(void)
{
	resolv_fini = false;
	nni_aio_list_init(&resolv_aios);

#ifndef NNG_RESOLV_CONCURRENCY
#define NNG_RESOLV_CONCURRENCY 4
#endif

	resolv_num_thr = (int) nni_init_get_param(
	    NNG_INIT_NUM_RESOLVER_THREADS, NNG_RESOLV_CONCURRENCY);
	if (resolv_num_thr < 1) {
		resolv_num_thr = 1;
	}
	// no limit on the maximum for now
	nni_init_set_effective(NNG_INIT_NUM_RESOLVER_THREADS, resolv_num_thr);
	resolv_thrs = NNI_ALLOC_STRUCTS(resolv_thrs, resolv_num_thr);
	if (resolv_thrs == NULL) {
		return (NNG_ENOMEM);
	}

	for (int i = 0; i < resolv_num_thr; i++) {
		int rv = nni_thr_init(&resolv_thrs[i], resolv_worker, NULL);
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
}

#endif // NNG_USE_POSIX_RESOLV_GAI
