//
// Copyright 2020 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
// Copyright 2018 Devolutions <info@devolutions.net>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "core/nng_impl.h"

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

#include "posix_tcp.h"

struct nni_tcp_listener {
	nni_posix_pfd *pfd;
	nni_list       acceptq;
	bool           started;
	bool           closed;
	bool           nodelay;
	bool           keepalive;
	nni_mtx        mtx;
};

int
nni_tcp_listener_init(nni_tcp_listener **lp)
{
	nni_tcp_listener *l;
	if ((l = NNI_ALLOC_STRUCT(l)) == NULL) {
		return (NNG_ENOMEM);
	}

	nni_mtx_init(&l->mtx);

	l->pfd     = NULL;
	l->closed  = false;
	l->started = false;

	nni_aio_list_init(&l->acceptq);
	*lp = l;
	return (0);
}

static void
tcp_listener_doclose(nni_tcp_listener *l)
{
	nni_aio *aio;

	l->closed = true;
	while ((aio = nni_list_first(&l->acceptq)) != NULL) {
		nni_aio_list_remove(aio);
		nni_aio_finish_error(aio, NNG_ECLOSED);
	}

	if (l->pfd != NULL) {
		nni_posix_pfd_close(l->pfd);
	}
}

void
nni_tcp_listener_close(nni_tcp_listener *l)
{
	nni_mtx_lock(&l->mtx);
	tcp_listener_doclose(l);
	nni_mtx_unlock(&l->mtx);
}

static void
tcp_listener_doaccept(nni_tcp_listener *l)
{
	nni_aio *aio;

	while ((aio = nni_list_first(&l->acceptq)) != NULL) {
		int            newfd;
		int            fd;
		int            rv;
		int            nd;
		int            ka;
		nni_posix_pfd *pfd;
		nni_tcp_conn * c;

		fd = nni_posix_pfd_fd(l->pfd);

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
				rv = nni_posix_pfd_arm(l->pfd, NNI_POLL_IN);
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

		if ((rv = nni_posix_tcp_alloc(&c, NULL)) != 0) {
			close(newfd);
			nni_aio_list_remove(aio);
			nni_aio_finish_error(aio, rv);
			continue;
		}

		if ((rv = nni_posix_pfd_init(&pfd, newfd)) != 0) {
			close(newfd);
			nng_stream_free(&c->stream);
			nni_aio_list_remove(aio);
			nni_aio_finish_error(aio, rv);
			continue;
		}

		nni_posix_tcp_init(c, pfd);

		ka = l->keepalive ? 1 : 0;
		nd = l->nodelay ? 1 : 0;
		nni_aio_list_remove(aio);
		nni_posix_tcp_start(c, nd, ka);
		nni_aio_set_output(aio, 0, c);
		nni_aio_finish(aio, 0, 0);
	}
}

static void
tcp_listener_cb(nni_posix_pfd *pfd, unsigned events, void *arg)
{
	nni_tcp_listener *l = arg;
	NNI_ARG_UNUSED(pfd);

	nni_mtx_lock(&l->mtx);
	if ((events & NNI_POLL_INVAL) != 0) {
		tcp_listener_doclose(l);
		nni_mtx_unlock(&l->mtx);
		return;
	}

	// Anything else will turn up in accept.
	tcp_listener_doaccept(l);
	nni_mtx_unlock(&l->mtx);
}

static void
tcp_listener_cancel(nni_aio *aio, void *arg, int rv)
{
	nni_tcp_listener *l = arg;

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

int
nni_tcp_listener_listen(nni_tcp_listener *l, const nni_sockaddr *sa)
{
	socklen_t               len;
	struct sockaddr_storage ss;
	int                     rv;
	int                     fd;
	nni_posix_pfd *         pfd;

	if (((len = nni_posix_nn2sockaddr(&ss, sa)) == 0) ||
	    ((ss.ss_family != AF_INET) && (ss.ss_family != AF_INET6))) {
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

	if ((rv = nni_posix_pfd_init(&pfd, fd)) != 0) {
		nni_mtx_unlock(&l->mtx);
		(void) close(fd);
		return (rv);
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
		nni_mtx_unlock(&l->mtx);
		nni_posix_pfd_fini(pfd);
		return (rv);
	}

	// Listen -- 128 depth is probably sufficient.  If it isn't, other
	// bad things are going to happen.
	if (listen(fd, 128) != 0) {
		rv = nni_plat_errno(errno);
		nni_mtx_unlock(&l->mtx);
		nni_posix_pfd_fini(pfd);
		return (rv);
	}

	nni_posix_pfd_set_cb(pfd, tcp_listener_cb, l);

	l->pfd     = pfd;
	l->started = true;
	nni_mtx_unlock(&l->mtx);

	return (0);
}

void
nni_tcp_listener_fini(nni_tcp_listener *l)
{
	nni_posix_pfd *pfd;

	nni_mtx_lock(&l->mtx);
	tcp_listener_doclose(l);
	pfd = l->pfd;
	nni_mtx_unlock(&l->mtx);

	if (pfd != NULL) {
		nni_posix_pfd_fini(pfd);
	}
	nni_mtx_fini(&l->mtx);
	NNI_FREE_STRUCT(l);
}

void
nni_tcp_listener_accept(nni_tcp_listener *l, nni_aio *aio)
{
	int rv;

	// Accept is simpler than the connect case.  With accept we just
	// need to wait for the socket to be readable to indicate an incoming
	// connection is ready for us.  There isn't anything else for us to
	// do really, as that will have been done in listen.
	if (nni_aio_begin(aio) != 0) {
		return;
	}
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
	if ((rv = nni_aio_schedule(aio, tcp_listener_cancel, l)) != 0) {
		nni_mtx_unlock(&l->mtx);
		nni_aio_finish_error(aio, rv);
		return;
	}
	nni_aio_list_append(&l->acceptq, aio);
	if (nni_list_first(&l->acceptq) == aio) {
		tcp_listener_doaccept(l);
	}
	nni_mtx_unlock(&l->mtx);
}

static int
tcp_listener_get_locaddr(void *arg, void *buf, size_t *szp, nni_type t)
{
	nni_tcp_listener *l = arg;
	nng_sockaddr      sa;
	nni_mtx_lock(&l->mtx);
	if (l->started) {
		struct sockaddr_storage ss;
		socklen_t               len = sizeof(ss);
		(void) getsockname(
		    nni_posix_pfd_fd(l->pfd), (void *) &ss, &len);
		(void) nni_posix_sockaddr2nn(&sa, &ss);
	} else {
		sa.s_family = NNG_AF_UNSPEC;
	}
	nni_mtx_unlock(&l->mtx);
	return (nni_copyout_sockaddr(&sa, buf, szp, t));
}

static int
tcp_listener_set_nodelay(void *arg, const void *buf, size_t sz, nni_type t)
{
	nni_tcp_listener *l = arg;
	int               rv;
	bool              b;

	if (((rv = nni_copyin_bool(&b, buf, sz, t)) != 0) || (l == NULL)) {
		return (rv);
	}
	nni_mtx_lock(&l->mtx);
	l->nodelay = b;
	nni_mtx_unlock(&l->mtx);
	return (0);
}

static int
tcp_listener_get_nodelay(void *arg, void *buf, size_t *szp, nni_type t)
{
	bool              b;
	nni_tcp_listener *l = arg;
	nni_mtx_lock(&l->mtx);
	b = l->nodelay;
	nni_mtx_unlock(&l->mtx);
	return (nni_copyout_bool(b, buf, szp, t));
}

static int
tcp_listener_set_keepalive(void *arg, const void *buf, size_t sz, nni_type t)
{
	nni_tcp_listener *l = arg;
	int               rv;
	bool              b;

	if (((rv = nni_copyin_bool(&b, buf, sz, t)) != 0) || (l == NULL)) {
		return (rv);
	}
	nni_mtx_lock(&l->mtx);
	l->keepalive = b;
	nni_mtx_unlock(&l->mtx);
	return (0);
}

static int
tcp_listener_get_keepalive(void *arg, void *buf, size_t *szp, nni_type t)
{
	bool              b;
	nni_tcp_listener *l = arg;
	nni_mtx_lock(&l->mtx);
	b = l->keepalive;
	nni_mtx_unlock(&l->mtx);
	return (nni_copyout_bool(b, buf, szp, t));
}

static const nni_option tcp_listener_options[] = {
	{
	    .o_name = NNG_OPT_LOCADDR,
	    .o_get  = tcp_listener_get_locaddr,
	},
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
	    .o_name = NULL,
	},
};

int
nni_tcp_listener_getopt(
    nni_tcp_listener *l, const char *name, void *buf, size_t *szp, nni_type t)
{
	return (nni_getopt(tcp_listener_options, name, l, buf, szp, t));
}

int
nni_tcp_listener_setopt(nni_tcp_listener *l, const char *name, const void *buf,
    size_t sz, nni_type t)
{
	return (nni_setopt(tcp_listener_options, name, l, buf, sz, t));
}
