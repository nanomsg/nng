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

#ifdef NNG_PLATFORM_POSIX

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
				rv = nni_posix_pfd_arm(l->pfd, POLLIN);
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

		if ((rv = nni_posix_pfd_init(&pfd, newfd)) != 0) {
			close(newfd);
			nni_aio_list_remove(aio);
			nni_aio_finish_error(aio, rv);
			continue;
		}

		if ((rv = nni_posix_tcp_conn_init(&c, pfd)) != 0) {
			nni_posix_pfd_fini(pfd);
			nni_aio_list_remove(aio);
			nni_aio_finish_error(aio, rv);
			continue;
		}

		nni_aio_list_remove(aio);
		nni_posix_tcp_conn_start(c);
		nni_aio_set_output(aio, 0, c);
		nni_aio_finish(aio, 0, 0);
	}
}

static void
tcp_listener_cb(nni_posix_pfd *pfd, int events, void *arg)
{
	nni_tcp_listener *l = arg;
	NNI_ARG_UNUSED(pfd);

	nni_mtx_lock(&l->mtx);
	if (events & POLLNVAL) {
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
nni_tcp_listener_listen(nni_tcp_listener *l, nni_sockaddr *sa)
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

	// Lets get the bound sockname, and pass that back to the caller.
	// This permits ephemeral port binding to work.
	// If this fails for some reason, we just don't update the
	// sockaddr structure.  This is kind of suboptimal, but failures
	// here should never occur.
	len = sizeof(ss);
	(void) getsockname(fd, (void *) &ss, &len);
	(void) nni_posix_sockaddr2nn(sa, &ss);

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

#endif // NNG_PLATFORM_POSIX
