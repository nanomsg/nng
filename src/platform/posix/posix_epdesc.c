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
#include "platform/posix/posix_aio.h"
#include "platform/posix/posix_pollq.h"

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <unistd.h>

#ifdef sun
#undef sun
#endif

#ifdef SOCK_CLOEXEC
#define NNI_STREAM_SOCKTYPE (SOCK_STREAM | SOCK_CLOEXEC)
#else
#define NNI_STREAM_SOCKTYPE SOCK_STREAM
#endif

struct nni_posix_epdesc {
	nni_posix_pfd *         pfd;
	nni_list                connectq;
	nni_list                acceptq;
	bool                    closed;
	bool                    started;
	bool                    ipcbound; // if true unlink socket on exit
	struct sockaddr_storage locaddr;
	struct sockaddr_storage remaddr;
	socklen_t               loclen;
	socklen_t               remlen;
	mode_t                  perms; // UNIX sockets only
	int                     mode;  // end point mode (dialer/listener)
	nni_mtx                 mtx;
};

static void nni_epdesc_connect_cb(nni_posix_pfd *, int, void *);
static void nni_epdesc_accept_cb(nni_posix_pfd *, int, void *);

static void
nni_epdesc_cancel(nni_aio *aio, int rv)
{
	nni_posix_epdesc *ed  = nni_aio_get_prov_data(aio);
	nni_posix_pfd *   pfd = NULL;

	NNI_ASSERT(rv != 0);
	nni_mtx_lock(&ed->mtx);
	if (nni_aio_list_active(aio)) {
		nni_aio_list_remove(aio);
		nni_aio_finish_error(aio, rv);
	}
	if ((ed->mode == NNI_EP_MODE_DIAL) && nni_list_empty(&ed->connectq) &&
	    ((pfd = ed->pfd) != NULL)) {
		nni_posix_pfd_close(pfd);
	}
	nni_mtx_unlock(&ed->mtx);
}

static void
nni_epdesc_finish(nni_aio *aio, int rv, nni_posix_pfd *newpfd)
{
	nni_posix_pipedesc *pd = NULL;

	// acceptq or connectq.
	nni_aio_list_remove(aio);

	if (rv != 0) {
		NNI_ASSERT(newpfd == NULL);
		nni_aio_finish_error(aio, rv);
		return;
	}

	NNI_ASSERT(newpfd != NULL);
	if ((rv = nni_posix_pipedesc_init(&pd, newpfd)) != 0) {
		nni_posix_pfd_fini(newpfd);
		nni_aio_finish_error(aio, rv);
		return;
	}
	nni_aio_set_output(aio, 0, pd);
	nni_aio_finish(aio, 0, 0);
}

static void
nni_epdesc_doaccept(nni_posix_epdesc *ed)
{
	nni_aio *aio;

	while ((aio = nni_list_first(&ed->acceptq)) != NULL) {
		int            newfd;
		int            fd;
		int            rv;
		nni_posix_pfd *pfd;

		fd = nni_posix_pfd_fd(ed->pfd);

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
				rv = nni_posix_pfd_arm(ed->pfd, POLLIN);
				if (rv != 0) {
					nni_epdesc_finish(aio, rv, NULL);
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
				nni_epdesc_finish(aio, rv, NULL);
				continue;
			}
		}

		if ((rv = nni_posix_pfd_init(&pfd, newfd)) != 0) {
			close(newfd);
			nni_epdesc_finish(aio, rv, NULL);
			continue;
		}

		nni_epdesc_finish(aio, 0, pfd);
	}
}

static void
nni_epdesc_doclose(nni_posix_epdesc *ed)
{
	nni_aio *aio;

	ed->closed = true;
	while ((aio = nni_list_first(&ed->acceptq)) != NULL) {
		nni_epdesc_finish(aio, NNG_ECLOSED, 0);
	}
	while ((aio = nni_list_first(&ed->connectq)) != NULL) {
		nni_epdesc_finish(aio, NNG_ECLOSED, 0);
	}

	if (ed->pfd != NULL) {

		nni_posix_pfd_close(ed->pfd);
	}

	// clean up stale UNIX socket when closing the server.
	if (ed->ipcbound) {
		struct sockaddr_un *sun = (void *) &ed->locaddr;
		(void) unlink(sun->sun_path);
	}
}

static void
nni_epdesc_accept_cb(nni_posix_pfd *pfd, int events, void *arg)
{
	nni_posix_epdesc *ed = arg;

	nni_mtx_lock(&ed->mtx);
	if (events & POLLNVAL) {
		nni_epdesc_doclose(ed);
		nni_mtx_unlock(&ed->mtx);
		return;
	}
	NNI_ASSERT(pfd == ed->pfd);

	// Anything else will turn up in accept.
	nni_epdesc_doaccept(ed);
	nni_mtx_unlock(&ed->mtx);
}

void
nni_posix_epdesc_close(nni_posix_epdesc *ed)
{
	nni_mtx_lock(&ed->mtx);
	nni_epdesc_doclose(ed);
	nni_mtx_unlock(&ed->mtx);
}

int
nni_posix_epdesc_listen(nni_posix_epdesc *ed)
{
	int                      len;
	struct sockaddr_storage *ss;
	int                      rv;
	int                      fd;
	nni_posix_pfd *          pfd;

	nni_mtx_lock(&ed->mtx);

	if (ed->started) {
		nni_mtx_unlock(&ed->mtx);
		return (NNG_ESTATE);
	}
	if (ed->closed) {
		nni_mtx_unlock(&ed->mtx);
		return (NNG_ECLOSED);
	}
	if ((len = ed->loclen) == 0) {
		nni_mtx_unlock(&ed->mtx);
		return (NNG_EADDRINVAL);
	}

	ss  = &ed->locaddr;
	len = ed->loclen;

	if ((fd = socket(ss->ss_family, NNI_STREAM_SOCKTYPE, 0)) < 0) {
		nni_mtx_unlock(&ed->mtx);
		return (nni_plat_errno(errno));
	}

	if ((rv = nni_posix_pfd_init(&pfd, fd)) != 0) {
		nni_mtx_unlock(&ed->mtx);
		nni_posix_pfd_fini(pfd);
		return (rv);
	}

#if defined(SO_REUSEADDR) && !defined(NNG_PLATFORM_WSL)
	if (ss->ss_family != AF_UNIX) {
		int on = 1;
		// If for some reason this doesn't work, it's probably ok.
		// Second bind will fail.
		(void) setsockopt(
		    fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
	}
#endif

	if (bind(fd, (struct sockaddr *) ss, len) < 0) {
		rv = nni_plat_errno(errno);
		nni_mtx_unlock(&ed->mtx);
		nni_posix_pfd_fini(pfd);
		return (rv);
	}

	// For UNIX domain sockets, optionally set the permission bits.
	// This is done after the bind and before listen, and on the file
	// rather than the file descriptor.
	// Experiments have shown that chmod() works correctly, provided that
	// it is done *before* the listen() operation, whereas fchmod seems to
	// have no impact.  This behavior was observed on both macOS and Linux.
	// YMMV on other platforms.
	if (ss->ss_family == AF_UNIX) {
		ed->ipcbound = true;
		if (ed->perms != 0) {
			struct sockaddr_un *sun   = (void *) ss;
			mode_t              perms = ed->perms & ~(S_IFMT);
			if ((rv = chmod(sun->sun_path, perms)) != 0) {
				rv = nni_plat_errno(errno);
				nni_mtx_unlock(&ed->mtx);
				nni_posix_pfd_fini(pfd);
				return (rv);
			}
		}
	}

	// Listen -- 128 depth is probably sufficient.  If it isn't, other
	// bad things are going to happen.
	if (listen(fd, 128) != 0) {
		rv = nni_plat_errno(errno);
		nni_mtx_unlock(&ed->mtx);
		nni_posix_pfd_fini(pfd);
		return (rv);
	}

	nni_posix_pfd_set_cb(pfd, nni_epdesc_accept_cb, ed);

	ed->pfd     = pfd;
	ed->started = true;
	nni_mtx_unlock(&ed->mtx);

	return (0);
}

void
nni_posix_epdesc_accept(nni_posix_epdesc *ed, nni_aio *aio)
{
	int rv;

	// Accept is simpler than the connect case.  With accept we just
	// need to wait for the socket to be readable to indicate an incoming
	// connection is ready for us.  There isn't anything else for us to
	// do really, as that will have been done in listen.
	if (nni_aio_begin(aio) != 0) {
		return;
	}
	nni_mtx_lock(&ed->mtx);

	if (!ed->started) {
		nni_mtx_unlock(&ed->mtx);
		nni_aio_finish_error(aio, NNG_ESTATE);
		return;
	}
	if (ed->closed) {
		nni_mtx_unlock(&ed->mtx);
		nni_aio_finish_error(aio, NNG_ECLOSED);
		return;
	}
	if ((rv = nni_aio_schedule(aio, nni_epdesc_cancel, ed)) != 0) {
		nni_mtx_unlock(&ed->mtx);
		nni_aio_finish_error(aio, rv);
		return;
	}
	nni_aio_list_append(&ed->acceptq, aio);
	if (nni_list_first(&ed->acceptq) == aio) {
		nni_epdesc_doaccept(ed);
	}
	nni_mtx_unlock(&ed->mtx);
}

int
nni_posix_epdesc_sockname(nni_posix_epdesc *ed, nni_sockaddr *sa)
{
	struct sockaddr_storage ss;
	socklen_t               sslen = sizeof(ss);
	int                     fd    = -1;

	nni_mtx_lock(&ed->mtx);
	if (ed->pfd != NULL) {
		fd = nni_posix_pfd_fd(ed->pfd);
	}
	nni_mtx_unlock(&ed->mtx);

	if (getsockname(fd, (void *) &ss, &sslen) != 0) {
		return (nni_plat_errno(errno));
	}
	return (nni_posix_sockaddr2nn(sa, &ss));
}

static void
nni_epdesc_connect_start(nni_posix_epdesc *ed)
{
	nni_posix_pfd *pfd;
	int            fd;
	int            rv;
	nni_aio *      aio;

loop:
	if ((aio = nni_list_first(&ed->connectq)) == NULL) {
		return;
	}

	NNI_ASSERT(ed->pfd == NULL);
	if (ed->closed) {
		nni_epdesc_finish(aio, NNG_ECLOSED, NULL);
		goto loop;
	}
	ed->started = true;

	if ((fd = socket(ed->remaddr.ss_family, NNI_STREAM_SOCKTYPE, 0)) < 0) {
		rv = nni_plat_errno(errno);
		nni_epdesc_finish(aio, rv, NULL);
		goto loop;
	}

	if ((rv = nni_posix_pfd_init(&pfd, fd)) != 0) {
		(void) close(fd);
		nni_epdesc_finish(aio, rv, NULL);
		goto loop;
	}
	// Possibly bind.
	if ((ed->loclen != 0) &&
	    (bind(fd, (void *) &ed->locaddr, ed->loclen) != 0)) {
		rv = nni_plat_errno(errno);
		nni_epdesc_finish(aio, rv, NULL);
		nni_posix_pfd_fini(pfd);
		goto loop;
	}

	if ((rv = connect(fd, (void *) &ed->remaddr, ed->remlen)) == 0) {
		// Immediate connect, cool!  This probably only happens on
		// loopback, and probably not on every platform.
		nni_epdesc_finish(aio, 0, pfd);
		goto loop;
	}

	if (errno != EINPROGRESS) {
		// Some immediate failure occurred.
		if (errno == ENOENT) { // For UNIX domain sockets
			rv = NNG_ECONNREFUSED;
		} else {
			rv = nni_plat_errno(errno);
		}
		nni_epdesc_finish(aio, rv, NULL);
		nni_posix_pfd_fini(pfd);
		goto loop;
	}
	nni_posix_pfd_set_cb(pfd, nni_epdesc_connect_cb, ed);
	if ((rv = nni_posix_pfd_arm(pfd, POLLOUT)) != 0) {
		nni_epdesc_finish(aio, rv, NULL);
		nni_posix_pfd_fini(pfd);
		goto loop;
	}
	ed->pfd = pfd;
	// all done... wait for this to signal via callback
}

void
nni_posix_epdesc_connect(nni_posix_epdesc *ed, nni_aio *aio)
{
	int rv;

	if (nni_aio_begin(aio) != 0) {
		return;
	}
	nni_mtx_lock(&ed->mtx);
	if (ed->closed) {
		nni_mtx_unlock(&ed->mtx);
		nni_aio_finish_error(aio, NNG_ECLOSED);
		return;
	}
	if ((rv = nni_aio_schedule(aio, nni_epdesc_cancel, ed)) != 0) {
		nni_mtx_unlock(&ed->mtx);
		nni_aio_finish_error(aio, rv);
		return;
	}

	ed->started = true;
	nni_list_append(&ed->connectq, aio);
	if (nni_list_first(&ed->connectq) == aio) {
		// If there was a stale pfd (probably from an aborted or
		// canceled connect attempt), discard it so we start fresh.
		if (ed->pfd != NULL) {
			nni_posix_pfd_fini(ed->pfd);
			ed->pfd = NULL;
		}
		nni_epdesc_connect_start(ed);
	}
	nni_mtx_unlock(&ed->mtx);
}

static void
nni_epdesc_connect_cb(nni_posix_pfd *pfd, int events, void *arg)
{
	nni_posix_epdesc *ed = arg;
	nni_aio *         aio;
	socklen_t         sz;
	int               rv;
	int               fd;

	nni_mtx_lock(&ed->mtx);
	if ((ed->closed) || ((aio = nni_list_first(&ed->connectq)) == NULL) ||
	    (pfd != ed->pfd)) {
		// Spurious completion.  Just ignore it.
		nni_mtx_unlock(&ed->mtx);
		return;
	}

	fd = nni_posix_pfd_fd(pfd);
	sz = sizeof(rv);

	if ((events & POLLNVAL) != 0) {
		rv = EBADF;

	} else if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &rv, &sz) < 0) {
		rv = errno;
	}

	switch (rv) {
	case 0:
		// Good connect!
		ed->pfd = NULL;
		nni_epdesc_finish(aio, 0, pfd);
		break;
	case EINPROGRESS: // still connecting... come back later
		nni_mtx_unlock(&ed->mtx);
		return;
	default:
		ed->pfd = NULL;
		nni_epdesc_finish(aio, nni_plat_errno(rv), NULL);
		nni_posix_pfd_fini(pfd);
		break;
	}

	// Start another connect running, if any is waiting.
	nni_epdesc_connect_start(ed);
	nni_mtx_unlock(&ed->mtx);
}

int
nni_posix_epdesc_init(nni_posix_epdesc **edp, int mode)
{
	nni_posix_epdesc *ed;

	if ((ed = NNI_ALLOC_STRUCT(ed)) == NULL) {
		return (NNG_ENOMEM);
	}

	nni_mtx_init(&ed->mtx);

	ed->pfd     = NULL;
	ed->closed  = false;
	ed->started = false;
	ed->perms   = 0; // zero means use default (no change)
	ed->mode    = mode;

	nni_aio_list_init(&ed->connectq);
	nni_aio_list_init(&ed->acceptq);
	*edp = ed;
	return (0);
}

void
nni_posix_epdesc_set_local(nni_posix_epdesc *ed, void *sa, size_t len)
{
	if ((len < 1) || (len > sizeof(struct sockaddr_storage))) {
		return;
	}
	nni_mtx_lock(&ed->mtx);
	memcpy(&ed->locaddr, sa, len);
	ed->loclen = len;
	nni_mtx_unlock(&ed->mtx);
}

void
nni_posix_epdesc_set_remote(nni_posix_epdesc *ed, void *sa, size_t len)
{
	if ((len < 1) || (len > sizeof(struct sockaddr_storage))) {
		return;
	}
	nni_mtx_lock(&ed->mtx);
	memcpy(&ed->remaddr, sa, len);
	ed->remlen = len;
	nni_mtx_unlock(&ed->mtx);
}

int
nni_posix_epdesc_set_permissions(nni_posix_epdesc *ed, mode_t mode)
{
	nni_mtx_lock(&ed->mtx);
	if (ed->mode != NNI_EP_MODE_LISTEN) {
		nni_mtx_unlock(&ed->mtx);
		return (NNG_ENOTSUP);
	}
	if (ed->started) {
		nni_mtx_unlock(&ed->mtx);
		return (NNG_EBUSY);
	}
	if ((mode & S_IFMT) != 0) {
		nni_mtx_unlock(&ed->mtx);
		return (NNG_EINVAL);
	}
	ed->perms = mode | S_IFSOCK; // we set IFSOCK to ensure non-zero
	nni_mtx_unlock(&ed->mtx);
	return (0);
}

void
nni_posix_epdesc_fini(nni_posix_epdesc *ed)
{
	nni_posix_pfd *pfd;

	nni_mtx_lock(&ed->mtx);
	nni_epdesc_doclose(ed);
	pfd = ed->pfd;
	nni_mtx_unlock(&ed->mtx);

	if (pfd != NULL) {
		nni_posix_pfd_fini(pfd);
	}
	nni_mtx_fini(&ed->mtx);
	NNI_FREE_STRUCT(ed);
}

#endif // NNG_PLATFORM_POSIX
