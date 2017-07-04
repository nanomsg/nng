//
// Copyright 2017 Garrett D'Amore <garrett@damore.org>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "core/nng_impl.h"
#include "platform/posix/posix_aio.h"
#include "platform/posix/posix_pollq.h"

#ifdef PLATFORM_POSIX_EPDESC

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <fcntl.h>
#include <unistd.h>
#include <poll.h>


struct nni_posix_epdesc {
	int			fd;
	int			index;
	nni_list		connectq;
	nni_list		acceptq;
	nni_posix_pollq_node	node;
	nni_posix_pollq *	pq;
	struct sockaddr_storage locaddr;
	struct sockaddr_storage remaddr;
	socklen_t		loclen;
	socklen_t		remlen;
	nni_mtx			mtx;
};


#if 0
static void
nni_posix_epdesc_cancel(nni_aio *aio)
{
	nni_posix_epdesc *ed;
	nni_posix_pollq *pq;

	ed = aio->a_prov_data;
	pq = ed->pq;

	nni_mtx_lock(&pq->mtx);
	nni_list_node_remove(&aio->a_prov_node);
	nni_mtx_unlock(&pq->mtx);
}


static void
nni_posix_epdesc_finish(nni_aio *aio, int rv, int newfd)
{
	nni_posix_epdesc *ed;
	nni_posix_pipedesc *pd;

	ed = aio->a_prov_data;

	// acceptq or connectq.
	if (nni_list_active(&ed->connectq, aio)) {
		nni_list_remove(&ed->connectq, aio);
	}

	if (rv == 0) {
		rv = nni_posix_pipedesc_init(&pd, newfd);
		if (rv != 0) {
			(void) close(newfd);
		} else {
			aio->a_pipe = pipe;
		}
	}
	// Abuse the count to hold our new fd.  This is only for accept.
	nni_aio_finish(aio, rv, 0);
}


static void
nni_posix_poll_connect(nni_posix_epdesc *ed)
{
	nni_aio *aio;
	socklen_t sz;
	int rv;

	// Note that normally there will only be a single connect AIO...
	// A socket that is here will have *initiated* with a connect()
	// call, which returned EINPROGRESS.  When the connection attempt
	// is done, either way, the descriptor will be noted as writable.
	// getsockopt() with SOL_SOCKET, SO_ERROR to determine the actual
	// status of the connection attempt...
	while ((aio = nni_list_first(&ed->connectq)) != NULL) {
		rv = -1;
		sz = sizeof (rv);
		if (getsockopt(ed->fd, SOL_SOCKET, SO_ERROR, &rv, &sz) < 0) {
			rv = errno;
		}
		switch (rv) {
		case 0:
			// Success!
			nni_posix_epdesc_finish(aio, 0, ed->fd);
			continue;

		case EINPROGRESS:
			// Still in progress... keep trying
			return;

		default:
			nni_posix_epdesc_finish(aio, nni_plat_errno(rv), 0);
			continue;
		}
	}
}


static void
nni_posix_poll_accept(nni_posix_epdesc *ed)
{
	nni_aio *aio;
	int newfd;
	struct sockaddr_storage ss;
	socklen_t slen;

	while ((aio = nni_list_first(&ed->acceptq)) != NULL) {
		// We could argue that knowing the remote peer address would
		// be nice.  But frankly if someone wants it, they can just
		// do getpeername().

#ifdef NNG_USE_ACCEPT4
		newfd = accept4(ed->fd, NULL, NULL, SOCK_CLOEXEC);
		if ((newfd < 0) &&
		    ((errno == ENOSYS) || (errno == ENOTSUP))) {
			newfd = accept(ed->fd, NULL, NULL);
		}
#else
		newfd = accept(ed->fd, NULL, NULL);
#endif

		if (newfd >= 0) {
			// successful connection request!
			nni_posix_epdesc_finish(aio, 0, newfd);
			continue;
		}

		if ((errno == EWOULDBLOCK) || (errno == EAGAIN)) {
			// Well, let's try later.  Note that EWOULDBLOCK
			// is required by standards, but some platforms may
			// use EAGAIN.  The values may be the same, so we
			// can't use switch.
			return;
		}

		if (errno == ECONNABORTED) {
			// Let's just eat this one.  Perhaps it may be
			// better to report it to the application, but we
			// think most applications don't want to see this.
			// Only someone with a packet trace is going to
			// notice this.
			continue;
		}

		nni_posix_epdesc_finish(aio, nni_plat_errno(errno), 0);
	}
}


static void
nni_posix_poll_epclose(nni_posix_epdesc *ed)
{
	nni_aio *aio;

	while ((aio = nni_list_first(&ed->acceptq)) != NULL) {
		nni_posix_epdesc_finish(aio, NNG_ECLOSED, 0);
	}
	while ((aio = nni_list_first(&ed->connectq)) != NULL) {
		nni_posix_epdesc_finish(aio, NNG_ECLOSED, 0);
	}
}


static int
nni_posix_epdesc_add(nni_posix_pollq *pq, nni_posix_epdesc *ed)
{
	int rv;

	// Add epdesc to the pollq if it isn't already there.
	if (!nni_list_active(&pq->eds, ed)) {
		if ((rv = nni_posix_poll_grow(pq)) != 0) {
			return (rv);
		}
		nni_list_append(&pq->eds, ed);
		pq->neds++;
	}
	return (0);
}


void
nni_posix_epdesc_connect(nni_posix_epdesc *ed, nni_aio *aio)
{
	// NB: We assume that the FD is already set to nonblocking mode.
	int rv;
	nni_posix_pollq *pq = ed->pq;
	int wake;

	nni_mtx_lock(&pq->mtx);
	// If we can't start, it means that the AIO was stopped.
	if ((rv = nni_aio_start(aio, nni_posix_epdesc_cancel, ed)) != 0) {
		nni_mtx_unlock(&pq->mtx);
		return;
	}
	if (ed->fd < 0) {
		nni_posix_epdesc_finish(aio, NNG_ECLOSED, 0);
		nni_mtx_unlock(&pq->mtx);
		return;
	}
	rv = connect(ed->fd, (void *) &ed->remaddr, ed->remlen);
	if (rv == 0) {
		// Immediate connect, cool!  This probably only happens on
		// loopback, and probably not on every platform.
		nni_posix_epdesc_finish(aio, 0, 0);
		nni_mtx_unlock(&pq->mtx);
		return;
	}
	if (errno != EINPROGRESS) {
		// Some immediate failure occurred.
		nni_posix_epdesc_finish(aio, nni_plat_errno(errno), 0);
		nni_mtx_unlock(&pq->mtx);
		return;
	}

	// We have to submit to the pollq, because the connection is pending.
	if ((rv = nni_posix_epdesc_add(pq, ed)) != 0) {
		nni_posix_epdesc_finish(aio, rv, 0);
		nni_mtx_unlock(&pq->mtx);
		return;
	}

	NNI_ASSERT(!nni_list_active(&ed->connectq, aio));
	wake = nni_list_empty(&ed->connectq);
	nni_aio_list_append(&ed->connectq, aio);
	if (wake) {
		nni_plat_pipe_raise(pq->wakewfd);
	}
	nni_mtx_unlock(&pq->mtx);
}


void
nni_posix_epdesc_accept(nni_posix_epdesc *ed, nni_aio *aio)
{
	// NB: We assume that the FD is already set to nonblocking mode.
	int rv;
	int wake;
	nni_posix_pollq *pq = ed->pq;

	// Accept is simpler than the connect case.  With accept we just
	// need to wait for the socket to be readable to indicate an incoming
	// connection is ready for us.  There isn't anything else for us to
	// do really, as that will have been done in listen.
	nni_mtx_lock(&pq->mtx);
	// If we can't start, it means that the AIO was stopped.
	if ((rv = nni_aio_start(aio, nni_posix_epdesc_cancel, ed)) != 0) {
		nni_mtx_unlock(&pq->mtx);
		return;
	}

	if (ed->fd < 0) {
		nni_mtx_unlock(&pq->mtx);
		nni_posix_epdesc_finish(aio, NNG_ECLOSED, 0);
		return;
	}

	// We have to submit to the pollq, because the connection is pending.
	if ((rv = nni_posix_epdesc_add(pq, ed)) != 0) {
		nni_posix_epdesc_finish(aio, rv, 0);
		nni_mtx_lock(&pq->mtx);
	}
	NNI_ASSERT(!nni_list_active(&ed->acceptq, aio));
	wake = nni_list_empty(&ed->acceptq);
	nni_aio_list_append(&ed->acceptq, aio);
	if (wake) {
		nni_plat_pipe_raise(pq->wakewfd);
	}
	nni_mtx_unlock(&pq->mtx);
}


#endif

int
nni_posix_epdesc_init(nni_posix_epdesc **edp, int fd)
{
	nni_posix_epdesc *ed;
	int rv;

	if ((ed = NNI_ALLOC_STRUCT(ed)) == NULL) {
		return (NNG_ENOMEM);
	}

	if ((rv = nni_mtx_init(&ed->mtx)) != 0) {
		NNI_FREE_STRUCT(ed);
		return (rv);
	}

	// We could randomly choose a different pollq, or for efficiencies
	// sake we could take a modulo of the file desc number to choose
	// one.  For now we just have a global pollq.  Note that by tying
	// the ed to a single pollq we may get some kind of cache warmth.

	ed->pq = nni_posix_pollq_get(fd);
	ed->fd = fd;
	ed->node.index = 0;
	ed->node.cb = NULL; // XXXX:
	ed->node.data = ed;

	// Ensure we are in non-blocking mode.
	(void) fcntl(fd, F_SETFL, O_NONBLOCK);

	nni_aio_list_init(&ed->connectq);
	nni_aio_list_init(&ed->acceptq);

	*edp = ed;
	return (0);
}


void
nni_posix_epdesc_fini(nni_posix_epdesc *ed)
{
	// XXX: MORE WORK HERE.
	nni_mtx_fini(&ed->mtx);
	NNI_FREE_STRUCT(ed);
}


#else

// Suppress empty symbols warnings in ranlib.
int nni_posix_epdesc_not_used = 0;

#endif // PLATFORM_POSIX_EPDESC
