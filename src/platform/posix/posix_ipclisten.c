//
// Copyright 2020 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
// Copyright 2019 Devolutions <info@devolutions.net>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "core/nng_impl.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <unistd.h>

#ifndef SOCK_CLOEXEC
#define SOCK_CLOEXEC 0
#endif

#include "posix_ipc.h"

typedef struct {
	nng_stream_listener sl;
	nni_posix_pfd *     pfd;
	nng_sockaddr        sa;
	nni_list            acceptq;
	bool                started;
	bool                closed;
	char *              path;
	mode_t              perms;
	nni_mtx             mtx;
} ipc_listener;

static void
ipc_listener_doclose(ipc_listener *l)
{
	nni_aio *aio;
	char *   path;

	l->closed = true;
	while ((aio = nni_list_first(&l->acceptq)) != NULL) {
		nni_aio_list_remove(aio);
		nni_aio_finish_error(aio, NNG_ECLOSED);
	}

	if (l->pfd != NULL) {
		nni_posix_pfd_close(l->pfd);
	}
	if (l->started && ((path = l->path) != NULL)) {
		l->path = NULL;
		(void) unlink(path);
		nni_strfree(path);
	}
}

static void
ipc_listener_close(void *arg)
{
	ipc_listener *l = arg;
	nni_mtx_lock(&l->mtx);
	ipc_listener_doclose(l);
	nni_mtx_unlock(&l->mtx);
}

static void
ipc_listener_doaccept(ipc_listener *l)
{
	nni_aio *aio;

	while ((aio = nni_list_first(&l->acceptq)) != NULL) {
		int            newfd;
		int            fd;
		int            rv;
		nni_posix_pfd *pfd;
		nni_ipc_conn * c;

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

		if ((rv = nni_posix_ipc_alloc(&c, &l->sa, NULL)) != 0) {
			(void) close(newfd);
			nni_aio_list_remove(aio);
			nni_aio_finish_error(aio, rv);
			continue;
		}

		if ((rv = nni_posix_pfd_init(&pfd, newfd)) != 0) {
			nng_stream_free(&c->stream);
			nni_aio_list_remove(aio);
			nni_aio_finish_error(aio, rv);
			continue;
		}

		nni_posix_ipc_init(c, pfd);

		nni_aio_list_remove(aio);
		nni_posix_ipc_start(c);
		nni_aio_set_output(aio, 0, c);
		nni_aio_finish(aio, 0, 0);
	}
}

static void
ipc_listener_cb(nni_posix_pfd *pfd, unsigned events, void *arg)
{
	ipc_listener *l = arg;
	NNI_ARG_UNUSED(pfd);

	nni_mtx_lock(&l->mtx);
	if ((events & NNI_POLL_INVAL) != 0) {
		ipc_listener_doclose(l);
		nni_mtx_unlock(&l->mtx);
		return;
	}

	// Anything else will turn up in accept.
	ipc_listener_doaccept(l);
	nni_mtx_unlock(&l->mtx);
}

static void
ipc_listener_cancel(nni_aio *aio, void *arg, int rv)
{
	ipc_listener *l = arg;

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

static int
ipc_remove_stale(const char *path)
{
	int                fd;
	struct sockaddr_un sa;
	size_t             sz;

	if (path == NULL) {
		return (0);
	}

	sa.sun_family = AF_UNIX;
	sz            = sizeof(sa.sun_path);

	if (nni_strlcpy(sa.sun_path, path, sz) >= sz) {
		return (NNG_EADDRINVAL);
	}

	if ((fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0)) < 0) {
		return (nni_plat_errno(errno));
	}

	// There is an assumption here that connect() returns immediately
	// (even when non-blocking) when a server is absent.  This seems
	// to be true for the platforms we've tried.  If it doesn't work,
	// then the cleanup will fail.  As this is supposed to be an
	// exceptional case, don't worry.
	(void) fcntl(fd, F_SETFL, O_NONBLOCK);
	if (connect(fd, (void *) &sa, sizeof(sa)) < 0) {
		if (errno == ECONNREFUSED) {
			(void) unlink(path);
		}
	}
	(void) close(fd);
	return (0);
}

static int
ipc_listener_get_addr(void *arg, void *buf, size_t *szp, nni_type t)
{
	ipc_listener *l = arg;
	return (nni_copyout_sockaddr(&l->sa, buf, szp, t));
}

static int
ipc_listener_set_perms(void *arg, const void *buf, size_t sz, nni_type t)
{
	ipc_listener *l = arg;
	int           mode;
	int           rv;

	if ((rv = nni_copyin_int(&mode, buf, sz, 0, S_IFMT, t)) != 0) {
		return (rv);
	}
	if (l->sa.s_family == NNG_AF_ABSTRACT) {
		// We ignore permissions on abstract sockets.
		// They succeed, but have no effect.
		return (0);
	}
	if ((mode & S_IFMT) != 0) {
		return (NNG_EINVAL);
	}
	mode |= S_IFSOCK; // set IFSOCK to ensure non-zero
	nni_mtx_lock(&l->mtx);
	if (l->started) {
		nni_mtx_unlock(&l->mtx);
		return (NNG_EBUSY);
	}
	l->perms = mode;
	nni_mtx_unlock(&l->mtx);
	return (0);
}

static const nni_option ipc_listener_options[] = {
	{
	    .o_name = NNG_OPT_LOCADDR,
	    .o_get  = ipc_listener_get_addr,
	},
	{
	    .o_name = NNG_OPT_IPC_PERMISSIONS,
	    .o_set  = ipc_listener_set_perms,
	},
	{
	    .o_name = NULL,
	},
};

static int
ipc_listener_get(
    void *arg, const char *name, void *buf, size_t *szp, nni_type t)
{
	ipc_listener *l = arg;
	return (nni_getopt(ipc_listener_options, name, l, buf, szp, t));
}

static int
ipc_listener_set(
    void *arg, const char *name, const void *buf, size_t sz, nni_type t)
{
	ipc_listener *l = arg;
	return (nni_setopt(ipc_listener_options, name, l, buf, sz, t));
}

static int
ipc_listener_chmod(ipc_listener *l, const char *path)
{
	if (path == NULL) {
		return (0);
	}
	if (l->perms == 0) {
		return (0);
	}
	if (chmod(path, l->perms & ~S_IFMT) != 0) {
		return (-1);
	}
	return (0);
}

int
ipc_listener_listen(void *arg)
{
	ipc_listener *          l = arg;
	socklen_t               len;
	struct sockaddr_storage ss;
	int                     rv;
	int                     fd;
	nni_posix_pfd *         pfd;
	char *                  path;

	if ((len = nni_posix_nn2sockaddr(&ss, &l->sa)) < sizeof(sa_family_t)) {
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

	switch (l->sa.s_family) {
	case NNG_AF_IPC:
		if ((path = nni_strdup(l->sa.s_ipc.sa_path)) == NULL) {
			nni_mtx_unlock(&l->mtx);
			return (NNG_ENOMEM);
		}
		break;
	case NNG_AF_ABSTRACT:
		path = NULL;
		break;
	default:
		nni_mtx_unlock(&l->mtx);
		return (NNG_EADDRINVAL);
	}

	if ((fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0)) < 0) {
		rv = nni_plat_errno(errno);
		nni_mtx_unlock(&l->mtx);
		nni_strfree(path);
		return (rv);
	}

	if ((rv = bind(fd, (struct sockaddr *) &ss, len)) != 0) {
		if ((l->sa.s_family == NNG_AF_IPC) &&
		    ((errno == EEXIST) || (errno == EADDRINUSE))) {
			ipc_remove_stale(path);
			rv = bind(fd, (struct sockaddr *) &ss, len);
		}
		if (rv != 0) {
			nni_strfree(path);
			path = NULL;
		}
	}

	if ((rv != 0) ||
	    (ipc_listener_chmod(l, path) != 0) ||
	    (listen(fd, 128) != 0)) {
		rv = nni_plat_errno(errno);
	}
	if ((rv != 0) || ((rv = nni_posix_pfd_init(&pfd, fd)) != 0)) {
		nni_mtx_unlock(&l->mtx);
		(void) close(fd);
		if (path != NULL) {
			unlink(path);
		}
		nni_strfree(path);
		return (rv);
	}

#ifdef NNG_HAVE_ABSTRACT_SOCKETS
	// If the original address was for a system assigned value,
	// then figure out what we got.  This is analogous to TCP
	// binding to port 0.
	if ((l->sa.s_family == NNG_AF_ABSTRACT) &&
	    (l->sa.s_abstract.sa_len == 0)) {
		struct sockaddr_un *su = (void *) &ss;
		len                    = sizeof(ss);
		if ((getsockname(fd, (struct sockaddr *) &ss, &len) == 0) &&
		    (len > sizeof(sa_family_t)) &&
		    (len <= sizeof(l->sa.s_abstract.sa_name)) &&
		    (su->sun_path[0] == '\0')) {
			len -= sizeof(sa_family_t);
			len--; // don't count the leading NUL.
			l->sa.s_abstract.sa_len = len;
			memcpy(
			    l->sa.s_abstract.sa_name, &su->sun_path[1], len);
		}
	}
#endif

	nni_posix_pfd_set_cb(pfd, ipc_listener_cb, l);

	l->pfd     = pfd;
	l->started = true;
	l->path    = path;
	nni_mtx_unlock(&l->mtx);

	return (0);
}

static void
ipc_listener_free(void *arg)
{
	ipc_listener * l = arg;
	nni_posix_pfd *pfd;

	nni_mtx_lock(&l->mtx);
	ipc_listener_doclose(l);
	pfd = l->pfd;
	nni_mtx_unlock(&l->mtx);

	if (pfd != NULL) {
		nni_posix_pfd_fini(pfd);
	}
	nni_mtx_fini(&l->mtx);
	NNI_FREE_STRUCT(l);
}

static void
ipc_listener_accept(void *arg, nni_aio *aio)
{
	ipc_listener *l = arg;
	int           rv;

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
	if ((rv = nni_aio_schedule(aio, ipc_listener_cancel, l)) != 0) {
		nni_mtx_unlock(&l->mtx);
		nni_aio_finish_error(aio, rv);
		return;
	}
	nni_aio_list_append(&l->acceptq, aio);
	if (nni_list_first(&l->acceptq) == aio) {
		ipc_listener_doaccept(l);
	}
	nni_mtx_unlock(&l->mtx);
}

int
nni_ipc_listener_alloc(nng_stream_listener **lp, const nng_url *url)
{
	ipc_listener *l;
	size_t        len;

	if ((l = NNI_ALLOC_STRUCT(l)) == NULL) {
		return (NNG_ENOMEM);
	}

	if ((strcmp(url->u_scheme, "ipc") == 0) ||
	    (strcmp(url->u_scheme, "unix") == 0)) {
		if ((url->u_path == NULL) ||
		    ((len = strlen(url->u_path)) == 0) ||
		    (len > NNG_MAXADDRLEN)) {
			NNI_FREE_STRUCT(l);
			return (NNG_EADDRINVAL);
		}
		l->sa.s_ipc.sa_family = NNG_AF_IPC;
		nni_strlcpy(l->sa.s_ipc.sa_path, url->u_path, NNG_MAXADDRLEN);

#ifdef NNG_HAVE_ABSTRACT_SOCKETS
	} else if (strcmp(url->u_scheme, "abstract") == 0) {
		// path is url encoded.
		len = nni_url_decode(l->sa.s_abstract.sa_name, url->u_path,
		    sizeof(l->sa.s_abstract.sa_name));
		if (len == (size_t) -1) {
			NNI_FREE_STRUCT(l);
			return (NNG_EADDRINVAL);
		}

		l->sa.s_abstract.sa_family = NNG_AF_ABSTRACT;
		l->sa.s_abstract.sa_len    = len;
#endif

	} else {
		NNI_FREE_STRUCT(l);
		return (NNG_EADDRINVAL);
	}

	nni_mtx_init(&l->mtx);
	nni_aio_list_init(&l->acceptq);

	l->pfd          = NULL;
	l->closed       = false;
	l->started      = false;
	l->perms        = 0;
	l->sl.sl_free   = ipc_listener_free;
	l->sl.sl_close  = ipc_listener_close;
	l->sl.sl_listen = ipc_listener_listen;
	l->sl.sl_accept = ipc_listener_accept;
	l->sl.sl_get    = ipc_listener_get;
	l->sl.sl_set    = ipc_listener_set;

	*lp = (void *) l;
	return (0);
}
