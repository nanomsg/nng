//
// Copyright 2025 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
// Copyright 2018 Devolutions <info@devolutions.net>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

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

#ifndef SOCK_CLOEXEC
#define SOCK_CLOEXEC 0
#endif

#ifndef NNG_HAVE_INET6
#ifdef NNG_HAVE_INET6_BSD
#define NNG_HAVE_INET6
#include <netinet6/in6.h>
#else
#undef NNG_ENABLE_IPV6
#endif
#endif

#include "../../core/aio.h"
#include "../../core/defs.h"
#include "../../core/list.h"
#include "../../core/options.h"
#include "../../core/platform.h"
#include "../../core/url.h"

#include "posix_tcp.h"

typedef struct tcp_listener {
	nng_stream_listener ops;
	nng_sockaddr        sa;
	nni_posix_pfd       pfd;
	nni_list            acceptq;
	bool                started;
	bool                closed;
	bool                nodelay;
	bool                keepalive;
	nni_mtx             mtx;
} tcp_listener;

static void
tcp_listener_doclose(tcp_listener *l)
{
	nni_aio *aio;

	l->closed = true;
	while ((aio = nni_list_first(&l->acceptq)) != NULL) {
		nni_aio_list_remove(aio);
		nni_aio_finish_error(aio, NNG_ECLOSED);
	}

	nni_posix_pfd_close(&l->pfd);
}

void
tcp_listener_close(void *arg)
{
	tcp_listener *l = arg;
	nni_mtx_lock(&l->mtx);
	tcp_listener_doclose(l);
	nni_mtx_unlock(&l->mtx);
}

static void
tcp_listener_doaccept(tcp_listener *l)
{
	nni_aio *aio;

	while ((aio = nni_list_first(&l->acceptq)) != NULL) {
		int           newfd;
		int           fd;
		int           rv;
		int           nd;
		int           ka;
		nni_tcp_conn *c;

		fd = nni_posix_pfd_fd(&l->pfd);

#ifdef NNG_USE_ACCEPT4
		newfd = accept4(fd, NULL, NULL, SOCK_CLOEXEC);
		if ((newfd < 0) && ((errno == ENOSYS) || (errno == ENOTSUP))) {
			newfd = accept(fd, NULL, NULL);
		}
#else
		newfd = accept(fd, NULL, NULL);
#endif
		if (newfd < 0) {
			switch (errno) {
			case EAGAIN:
#ifdef EWOULDBLOCK
#if EWOULDBLOCK != EAGAIN
			case EWOULDBLOCK:
#endif
#endif
				rv = nni_posix_pfd_arm(&l->pfd, NNI_POLL_IN);
				if (rv != 0) {
					nni_aio_list_remove(aio);
					nni_aio_finish_error(aio, rv);
					continue;
				}
				// Come back later...
				return;
			case ECONNABORTED:
			case ECONNRESET:
				// Eat them, they aren't interesting.
				continue;
			default:
				// Error this one, but keep moving to the next.
				rv = nni_plat_errno(errno);
				NNI_ASSERT(rv != 0);
				nni_aio_list_remove(aio);
				nni_aio_finish_error(aio, rv);
				continue;
			}
		}

		if ((rv = nni_posix_tcp_alloc(&c, NULL, newfd)) != 0) {
			close(newfd);
			nni_aio_list_remove(aio);
			nni_aio_finish_error(aio, rv);
			continue;
		}

		ka = l->keepalive ? 1 : 0;
		nd = l->nodelay ? 1 : 0;
		nni_aio_list_remove(aio);
		nni_posix_tcp_start(c, nd, ka);
		nni_aio_set_output(aio, 0, c);
		nni_aio_finish(aio, 0, 0);
	}
}

static void
tcp_listener_cb(void *arg, unsigned events)
{
	tcp_listener *l = arg;

	nni_mtx_lock(&l->mtx);
	if (((events & NNI_POLL_INVAL) != 0) || (l->closed)) {
		tcp_listener_doclose(l);
		nni_mtx_unlock(&l->mtx);
		return;
	}

	// Anything else will turn up in accept.
	tcp_listener_doaccept(l);
	nni_mtx_unlock(&l->mtx);
}

static void
tcp_listener_cancel(nni_aio *aio, void *arg, nng_err rv)
{
	tcp_listener *l = arg;

	// This is dead easy, because we'll ignore the completion if there
	// isn't anything to do the accept on!
	NNI_ASSERT(rv != 0);
	nni_mtx_lock(&l->mtx);
	if (nni_aio_list_active(aio)) {
		nni_aio_list_remove(aio);
		nni_aio_finish_error(aio, rv);
	}
	nni_mtx_unlock(&l->mtx);
}

static nng_err
tcp_listener_listen(void *arg)
{
	tcp_listener           *l = arg;
	socklen_t               len;
	struct sockaddr_storage ss;
	nng_err                 rv;
	int                     fd;

	if (((len = nni_posix_nn2sockaddr(&ss, &l->sa)) == 0) ||
#ifdef NNG_ENABLE_IPV6
	    ((ss.ss_family != AF_INET) && (ss.ss_family != AF_INET6))
#else
	    (ss.ss_family != AF_INET)
#endif
	) {
		return (NNG_EADDRINVAL);
	}

	nni_mtx_lock(&l->mtx);
	if (l->started) {
		nni_mtx_unlock(&l->mtx);
		return (NNG_ESTATE);
	}
	if (l->closed) {
		nni_mtx_unlock(&l->mtx);
		return (NNG_ECLOSED);
	}

	if ((fd = socket(ss.ss_family, SOCK_STREAM | SOCK_CLOEXEC, 0)) < 0) {
		nni_mtx_unlock(&l->mtx);
		return (nni_plat_errno(errno));
	}

// On the Windows Subsystem for Linux, SO_REUSEADDR behaves like Windows
// SO_REUSEADDR, which is almost completely different (and wrong!) from
// traditional SO_REUSEADDR.
#if defined(SO_REUSEADDR) && !defined(NNG_PLATFORM_WSL)
	{
		int on = 1;
		// If for some reason this doesn't work, it's probably ok.
		// Second bind will fail.
		(void) setsockopt(
		    fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
	}
#endif

	if (bind(fd, (struct sockaddr *) &ss, len) < 0) {
		rv = nni_plat_errno(errno);
		(void) close(fd);
		nni_mtx_unlock(&l->mtx);
		return (rv);
	}

	// Listen -- 128 depth is probably sufficient.  If it isn't, other
	// bad things are going to happen.
	if (listen(fd, 128) != 0) {
		rv = nni_plat_errno(errno);
		(void) close(fd);
		nni_mtx_unlock(&l->mtx);
		return (rv);
	}

	nni_posix_pfd_init(&l->pfd, fd, tcp_listener_cb, l);

	l->started = true;
	nni_mtx_unlock(&l->mtx);

	return (NNG_OK);
}

static void
tcp_listener_stop(void *arg)
{
	tcp_listener *l = arg;
	nni_mtx_lock(&l->mtx);
	tcp_listener_doclose(l);
	nni_mtx_unlock(&l->mtx);

	nni_posix_pfd_stop(&l->pfd);
}

static void
tcp_listener_free(void *arg)
{
	tcp_listener *l = arg;

	tcp_listener_stop(l); // should usually already be stopped
	nni_posix_pfd_fini(&l->pfd);
	nni_mtx_fini(&l->mtx);
	NNI_FREE_STRUCT(l);
}

static void
tcp_listener_accept(void *arg, nni_aio *aio)
{
	tcp_listener *l = arg;

	// Accept is simpler than the connect case.  With accept we just
	// need to wait for the socket to be readable to indicate an incoming
	// connection is ready for us.  There isn't anything else for us to
	// do really, as that will have been done in listen.
	nni_aio_reset(aio);
	nni_mtx_lock(&l->mtx);

	if (!l->started) {
		nni_mtx_unlock(&l->mtx);
		nni_aio_finish_error(aio, NNG_ESTATE);
		return;
	}
	if (l->closed) {
		nni_mtx_unlock(&l->mtx);
		nni_aio_finish_error(aio, NNG_ECLOSED);
		return;
	}
	if (!nni_aio_start(aio, tcp_listener_cancel, l)) {
		nni_mtx_unlock(&l->mtx);
		return;
	}
	nni_aio_list_append(&l->acceptq, aio);
	if (nni_list_first(&l->acceptq) == aio) {
		tcp_listener_doaccept(l);
	}
	nni_mtx_unlock(&l->mtx);
}

static nng_err
tcp_listener_set_nodelay(void *arg, const void *buf, size_t sz, nni_type t)
{
	tcp_listener *l = arg;
	nng_err       rv;
	bool          b;

	if (((rv = nni_copyin_bool(&b, buf, sz, t)) != NNG_OK) ||
	    (l == NULL)) {
		return (rv);
	}
	nni_mtx_lock(&l->mtx);
	l->nodelay = b;
	nni_mtx_unlock(&l->mtx);
	return (NNG_OK);
}

static nng_err
tcp_listener_get_nodelay(void *arg, void *buf, size_t *szp, nni_type t)
{
	bool          b;
	tcp_listener *l = arg;
	nni_mtx_lock(&l->mtx);
	b = l->nodelay;
	nni_mtx_unlock(&l->mtx);
	return (nni_copyout_bool(b, buf, szp, t));
}

static nng_err
tcp_listener_set_keepalive(void *arg, const void *buf, size_t sz, nni_type t)
{
	tcp_listener *l = arg;
	nng_err       rv;
	bool          b;

	if (((rv = nni_copyin_bool(&b, buf, sz, t)) != NNG_OK) ||
	    (l == NULL)) {
		return (rv);
	}
	nni_mtx_lock(&l->mtx);
	l->keepalive = b;
	nni_mtx_unlock(&l->mtx);
	return (NNG_OK);
}

static nng_err
tcp_listener_get_keepalive(void *arg, void *buf, size_t *szp, nni_type t)
{
	bool          b;
	tcp_listener *l = arg;
	nni_mtx_lock(&l->mtx);
	b = l->keepalive;
	nni_mtx_unlock(&l->mtx);
	return (nni_copyout_bool(b, buf, szp, t));
}

static nng_err
tcp_listener_get_port(void *arg, void *buf, size_t *szp, nni_type t)
{
	tcp_listener           *l = arg;
	int                     port;
	struct sockaddr_storage ss;
	socklen_t               len = sizeof(ss);

	nni_mtx_lock(&l->mtx);
	if (!l->started) {
		nni_mtx_unlock(&l->mtx);
		return (NNG_ESTATE);
	}
	(void) getsockname(nni_posix_pfd_fd(&l->pfd), (void *) &ss, &len);
	nni_mtx_unlock(&l->mtx);

	switch (ss.ss_family) {
	case AF_INET:
		port =
		    htons(((struct sockaddr_in *) ((void *) (&ss)))->sin_port);
		break;
	case AF_INET6:
		port = htons(
		    ((struct sockaddr_in6 *) ((void *) (&ss)))->sin6_port);
		break;
	default:
		port = 0;
		break;
	}

	return (nni_copyout_int(port, buf, szp, t));
}

static nng_err
tcp_listener_set_listen_fd(void *arg, const void *buf, size_t sz, nni_type t)
{
	tcp_listener           *l = arg;
	int                     fd;
	struct sockaddr_storage ss;
	socklen_t               len = sizeof(ss);
	nng_err                 rv;

	if ((rv = nni_copyin_int(&fd, buf, sz, 0, NNI_MAXINT, t)) != NNG_OK) {
		return (rv);
	}

	if (getsockname(fd, (void *) &ss, &len) != 0) {
		return (nni_plat_errno(errno));
	}

	if (((nni_posix_sockaddr2nn(&l->sa, &ss, len)) != 0) ||
#ifdef NNG_ENABLE_IPV6
	    ((ss.ss_family != AF_INET) && (ss.ss_family != AF_INET6))
#else
	    (ss.ss_family != AF_INET)
#endif
	) {
		return (NNG_EADDRINVAL);
	}

	nni_mtx_lock(&l->mtx);
	if (l->started) {
		nni_mtx_unlock(&l->mtx);
		return (NNG_EBUSY);
	}
	if (l->closed) {
		nni_mtx_unlock(&l->mtx);
		return (NNG_ECLOSED);
	}
	nni_posix_pfd_init(&l->pfd, fd, tcp_listener_cb, l);
	l->started = true;
	nni_mtx_unlock(&l->mtx);
	return (NNG_OK);
}

#ifdef NNG_TEST_LIB
// this is readable only for test code -- user code should never rely on this
static nng_err
tcp_listener_get_listen_fd(void *arg, void *buf, size_t *szp, nni_type t)
{
	nng_err       rv;
	tcp_listener *l = arg;
	nni_mtx_lock(&l->mtx);
	NNI_ASSERT(l->started);
	NNI_ASSERT(!l->closed);
	rv = nni_copyout_int(nni_posix_pfd_fd(&l->pfd), buf, szp, t);
	nni_mtx_unlock(&l->mtx);
	return (rv);
}
#endif

static const nni_option tcp_listener_options[] = {
	{
	    .o_name = NNG_OPT_TCP_NODELAY,
	    .o_set  = tcp_listener_set_nodelay,
	    .o_get  = tcp_listener_get_nodelay,
	},
	{
	    .o_name = NNG_OPT_TCP_KEEPALIVE,
	    .o_set  = tcp_listener_set_keepalive,
	    .o_get  = tcp_listener_get_keepalive,
	},
	{
	    .o_name = NNG_OPT_BOUND_PORT,
	    .o_get  = tcp_listener_get_port,
	},
	{
	    .o_name = NNG_OPT_LISTEN_FD,
	    .o_set  = tcp_listener_set_listen_fd,
#ifdef NNG_TEST_LIB
	    .o_get = tcp_listener_get_listen_fd,
#endif
	},
	{
	    .o_name = NULL,
	},
};

static nng_err
tcp_listener_get(
    void *arg, const char *name, void *buf, size_t *szp, nni_type t)
{
	return (nni_getopt(tcp_listener_options, name, arg, buf, szp, t));
}

static nng_err
tcp_listener_set(
    void *arg, const char *name, const void *buf, size_t sz, nni_type t)
{
	return (nni_setopt(tcp_listener_options, name, arg, buf, sz, t));
}

static nng_err
tcp_listener_alloc_addr(nng_stream_listener **lp, const nng_sockaddr *sa)
{
	tcp_listener *l;

	if ((l = NNI_ALLOC_STRUCT(l)) == NULL) {
		return (NNG_ENOMEM);
	}

	nni_mtx_init(&l->mtx);
	nni_aio_list_init(&l->acceptq);

	l->closed  = false;
	l->started = false;
	l->nodelay = true;
	l->sa      = *sa;

	l->ops.sl_free   = tcp_listener_free;
	l->ops.sl_close  = tcp_listener_close;
	l->ops.sl_stop   = tcp_listener_stop;
	l->ops.sl_listen = tcp_listener_listen;
	l->ops.sl_accept = tcp_listener_accept;
	l->ops.sl_get    = tcp_listener_get;
	l->ops.sl_set    = tcp_listener_set;

	*lp = (void *) l;
	return (NNG_OK);
}

nng_err
nni_tcp_listener_alloc(nng_stream_listener **lp, const nng_url *url)
{
	nng_err      rv;
	nng_sockaddr sa;

	if ((rv = nni_url_to_address(&sa, url)) != NNG_OK) {
		return (rv);
	}

	return (tcp_listener_alloc_addr(lp, &sa));
}
