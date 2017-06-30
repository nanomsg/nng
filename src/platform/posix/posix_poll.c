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

#ifdef NNG_USE_POSIX_AIOPOLL

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <fcntl.h>
#include <unistd.h>
#include <poll.h>


// POSIX AIO using poll().  We use a single poll thread to perform
// I/O operations for the entire system.  This isn't entirely scalable,
// and it might be a good idea to create a few threads and group the
// I/O operations into separate pollers to limit the amount of work each
// thread does, and to scale across multiple cores.  For now we don't
// worry about it.

typedef struct nni_posix_pollq   nni_posix_pollq;

// nni_posix_pipedesc is a descriptor kept one per transport pipe (i.e. open
// file descriptor for TCP socket, etc.)  This contains the list of pending
// aios for that underlying socket, as well as the socket itself.
struct nni_posix_pipedesc {
	int			fd;
	int			index;
	nni_list		readq;
	nni_list		writeq;
	nni_list_node		node;
	nni_posix_pollq *	pq;
	int			nonblocking;
};


struct nni_posix_epdesc {
	int			fd;
	int			index;
	nni_list		connectq;
	nni_list		acceptq;
	nni_list_node		node;
	nni_posix_pollq *	pq;
	struct sockaddr_storage locaddr;
	struct sockaddr_storage remaddr;
	socklen_t		loclen;
	socklen_t		remlen;
};


// nni_posix_pollq is a work structure used by the poller thread, that keeps
// track of all the underlying pipe handles and so forth being used by poll().
struct nni_posix_pollq {
	nni_mtx		mtx;
	struct pollfd * fds;
	struct pollfd * newfds;
	int		nfds;
	int		nnewfds;
	int		wakewfd;        // write side of waker pipe
	int		wakerfd;        // read side of waker pipe
	int		close;          // request for worker to exit
	int		started;
	nni_thr		thr;            // worker thread
	nni_list	pds;            // nni_posix_pipedescs.
	int		npds;           // length of pds list
	nni_list	eds;            // nni_posix_epdescs
	int		neds;           // length of eds list
};

static nni_posix_pollq nni_posix_global_pollq;


static int
nni_posix_poll_grow(nni_posix_pollq *pq)
{
	int grow = pq->npds + pq->neds + 2; // one for us, one for waker
	int noldfds;
	struct pollfd *oldfds;
	struct pollfd *newfds;

	if ((grow < pq->nfds) || (grow < pq->nnewfds)) {
		return (0);
	}

	grow = grow + 128;

	// Maybe we are adding a *lot* of pipes at once, and have to grow
	// multiple times before the poller gets scheduled.  In that case
	// toss the old array before we finish.
	oldfds = pq->newfds;
	noldfds = pq->nnewfds;

	if ((newfds = nni_alloc(grow * sizeof (struct pollfd))) == NULL) {
		return (NNG_ENOMEM);
	}


	pq->newfds = newfds;
	pq->nnewfds = grow;

	if (noldfds != 0) {
		nni_free(oldfds, noldfds * sizeof (struct pollfd));
	}
	return (0);
}


static void
nni_posix_epdesc_cancel(nni_aio *aio)
{
	nni_posix_epdesc *ed;
	nni_posix_pollq *pq;

	ed = aio->a_prov_data;
	pq = ed->pq;

	nni_mtx_lock(&pq->mtx);
	// This will remove the aio from either the read or the write
	// list; it doesn't matter which.
	if (nni_list_active(&ed->connectq, aio)) {
		nni_list_remove(&ed->connectq, aio);
	}
	nni_mtx_unlock(&pq->mtx);
}


static void
nni_posix_epdesc_finish(nni_aio *aio, int rv, int newfd)
{
	nni_posix_epdesc *ed;

	ed = aio->a_prov_data;
	if (nni_list_active(&ed->connectq, aio)) {
		nni_list_remove(&ed->connectq, aio);
	}

	// Abuse the count to hold our new fd.  This is only for accept.
	nni_aio_finish(aio, rv, newfd);
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
			nni_posix_epdesc_finish(aio, 0, 0);
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
			// We abuse the count to hold our new file descriptor.
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
	wake = nni_list_first(&ed->connectq) == NULL ? 1 : 0;
	nni_list_append(&ed->connectq, aio);
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
	wake = nni_list_first(&ed->acceptq) == NULL ? 1 : 0;
	nni_list_append(&ed->acceptq, aio);
	if (wake) {
		nni_plat_pipe_raise(pq->wakewfd);
	}
	nni_mtx_unlock(&pq->mtx);
}


int
nni_posix_epdesc_init(nni_posix_epdesc **edp, int fd)
{
	nni_posix_epdesc *ed;


	if ((ed = NNI_ALLOC_STRUCT(ed)) == NULL) {
		return (NNG_ENOMEM);
	}

	// We could randomly choose a different pollq, or for efficiencies
	// sake we could take a modulo of the file desc number to choose
	// one.  For now we just have a global pollq.  Note that by tying
	// the ed to a single pollq we may get some kind of cache warmth.

	ed->pq = &nni_posix_global_pollq;
	ed->fd = fd;
	ed->index = 0;

	// Ensure we are in non-blocking mode.
	(void) fcntl(fd, F_SETFL, O_NONBLOCK);

	NNI_LIST_INIT(&ed->connectq, nni_aio, a_prov_node);
	NNI_LIST_INIT(&ed->acceptq, nni_aio, a_prov_node);

	*edp = ed;
	return (0);
}


void
nni_posix_epdesc_fini(nni_posix_epdesc *ed)
{
	nni_aio *aio;
	nni_posix_pollq *pq = ed->pq;

	nni_mtx_lock(&pq->mtx);

	// This removes any aios from our list.
	nni_posix_poll_epclose(ed);

	if (nni_list_active(&pq->eds, ed)) {
		nni_list_remove(&pq->eds, ed);
		pq->neds--;
	}
	nni_mtx_unlock(&pq->mtx);

	NNI_FREE_STRUCT(ed);
}


static void
nni_posix_pipedesc_finish(nni_aio *aio, int rv)
{
	nni_posix_pipedesc *pd;

	pd = aio->a_prov_data;
	if (nni_list_active(&pd->readq, aio)) {
		nni_list_remove(&pd->readq, aio);
	}
	nni_aio_finish(aio, rv, aio->a_count);
}


static void
nni_posix_poll_write(nni_posix_pipedesc *pd)
{
	int n;
	int rv;
	int i;
	struct iovec iovec[4];
	struct iovec *iovp;
	nni_aio *aio;

	while ((aio = nni_list_first(&pd->writeq)) != NULL) {
		for (i = 0; i < aio->a_niov; i++) {
			iovec[i].iov_len = aio->a_iov[i].iov_len;
			iovec[i].iov_base = aio->a_iov[i].iov_buf;
		}
		iovp = &iovec[0];
		rv = 0;

		n = writev(pd->fd, iovp, aio->a_niov);
		if (n < 0) {
			if ((errno == EAGAIN) || (errno == EINTR)) {
				// Can't write more right now.  We're done
				// on this fd for now.
				return;
			}
			rv = nni_plat_errno(errno);

			nni_posix_pipedesc_finish(aio, rv);
			return;
		}

		aio->a_count += n;

		while (n > 0) {
			// If we didn't write the first full iov,
			// then we're done for now.  Record progress
			// and return to caller.
			if (n < aio->a_iov[0].iov_len) {
				aio->a_iov[0].iov_buf += n;
				aio->a_iov[0].iov_len -= n;
				return;
			}

			// We consumed the full iovec, so just move the
			// remaininng ones up, and decrement count handled.
			n -= aio->a_iov[0].iov_len;
			for (i = 1; i < aio->a_niov; i++) {
				aio->a_iov[i-1] = aio->a_iov[i];
			}
			NNI_ASSERT(aio->a_niov > 0);
			aio->a_niov--;
		}

		// We completed the entire operation on this aioq.
		nni_list_remove(&pd->writeq, aio);
		nni_posix_pipedesc_finish(aio, 0);

		// Go back to start of loop to see if there is another
		// aioq ready for us to process.
	}
}


static void
nni_posix_poll_read(nni_posix_pipedesc *pd)
{
	int n;
	int rv;
	int i;
	struct iovec iovec[4];
	struct iovec *iovp;
	nni_aio *aio;

	while ((aio = nni_list_first(&pd->readq)) != NULL) {
		for (i = 0; i < aio->a_niov; i++) {
			iovec[i].iov_len = aio->a_iov[i].iov_len;
			iovec[i].iov_base = aio->a_iov[i].iov_buf;
		}
		iovp = &iovec[0];
		rv = 0;

		n = readv(pd->fd, iovp, aio->a_niov);
		if (n < 0) {
			if ((errno == EAGAIN) || (errno == EINTR)) {
				// Can't write more right now.  We're done
				// on this fd for now.
				return;
			}
			rv = nni_plat_errno(errno);

			nni_posix_pipedesc_finish(aio, rv);
			return;
		}

		if (n == 0) {
			// No bytes indicates a closed descriptor.
			nni_posix_pipedesc_finish(aio, NNG_ECLOSED);
			return;
		}

		aio->a_count += n;

		while (n > 0) {
			// If we didn't write the first full iov,
			// then we're done for now.  Record progress
			// and return to caller.
			if (n < aio->a_iov[0].iov_len) {
				aio->a_iov[0].iov_buf += n;
				aio->a_iov[0].iov_len -= n;
				return;
			}

			// We consumed the full iovec, so just move the
			// remaininng ones up, and decrement count handled.
			n -= aio->a_iov[0].iov_len;
			for (i = 1; i < aio->a_niov; i++) {
				aio->a_iov[i-1] = aio->a_iov[i];
			}
			NNI_ASSERT(aio->a_niov > 0);
			aio->a_niov--;
		}

		// We completed the entire operation on this aioq.
		nni_posix_pipedesc_finish(aio, 0);

		// Go back to start of loop to see if there is another
		// aioq ready for us to process.
	}
}


static void
nni_posix_poll_close(nni_posix_pipedesc *pd)
{
	nni_aio *aio;

	while ((aio = nni_list_first(&pd->readq)) != NULL) {
		nni_posix_pipedesc_finish(aio, NNG_ECLOSED);
	}
	while ((aio = nni_list_first(&pd->writeq)) != NULL) {
		nni_posix_pipedesc_finish(aio, NNG_ECLOSED);
	}
}


void
nni_posix_pipedesc_close(nni_posix_pipedesc *pd)
{
	nni_posix_pollq *pq;

	pq = pd->pq;
	nni_mtx_lock(&pq->mtx);
	pd->fd = -1;
	nni_posix_poll_close(pd);
	if (nni_list_active(&pq->pds, pd)) {
		nni_list_remove(&pq->pds, pd);
		pq->npds--;
	}
	nni_mtx_unlock(&pq->mtx);
}


static void
nni_posix_poll_thr(void *arg)
{
	nni_posix_pollq *pollq = arg;
	nni_posix_pipedesc *pd, *nextpd;
	nni_posix_epdesc *ed, *nexted;


	nni_mtx_lock(&pollq->mtx);
	for (;;) {
		int rv;
		int nfds;
		struct pollfd *fds;

		if (pollq->close) {
			break;
		}

		if (pollq->newfds != NULL) {
			// We have "grown" by the caller.  Free up the old
			// space, and start using the new.
			nni_free(pollq->fds,
			    pollq->nfds * sizeof (struct pollfd));
			pollq->fds = pollq->newfds;
			pollq->nfds = pollq->nnewfds;
			pollq->newfds = NULL;
		}
		fds = pollq->fds;
		nfds = 0;

		// The waker pipe is set up so that we will be woken
		// when it is written (this allows us to be signaled).
		fds[nfds].fd = pollq->wakerfd;
		fds[nfds].events = POLLIN;
		fds[nfds].revents = 0;
		nfds++;

		// Set up the poll list.
		NNI_LIST_FOREACH (&pollq->pds, pd) {
			fds[nfds].fd = pd->fd;
			fds[nfds].events = 0;
			fds[nfds].revents = 0;
			if (nni_list_first(&pd->readq) != NULL) {
				fds[nfds].events |= POLLIN;
			}
			if (nni_list_first(&pd->writeq) != NULL) {
				fds[nfds].events |= POLLOUT;
			}
			pd->index = nfds;
			nfds++;
		}
		NNI_LIST_FOREACH (&pollq->eds, ed) {
			fds[nfds].fd = ed->fd;
			fds[nfds].events = 0;
			fds[nfds].revents = 0;
			if (nni_list_first(&ed->connectq) != NULL) {
				fds[nfds].events |= POLLOUT;
			}
			if (nni_list_first(&ed->acceptq) != NULL) {
				fds[nfds].events |= POLLIN;
			}
			ed->index = nfds;
			nfds++;
		}

		// Now poll it.  We block indefinitely, since we use separate
		// timeouts to wake and remove the elements from the list.
		nni_mtx_unlock(&pollq->mtx);
		rv = poll(fds, nfds, -1);
		nni_mtx_lock(&pollq->mtx);

		if (rv < 0) {
			// This shouldn't happen really.  If it does, we
			// just try again.  (EINTR is probably the only
			// reasonable failure here, unless internal memory
			// allocations fail in the kernel, leading to EAGAIN.)
			continue;
		}


		// If the waker pipe was signaled, read from it.
		if (fds[0].revents & POLLIN) {
			NNI_ASSERT(fds[0].fd == pollq->wakerfd);
			nni_plat_pipe_clear(pollq->wakerfd);
		}

		// Now we iterate through all the pipedescs.  Note that one
		// may have been added or removed.  New pipedescs will have
		// their index set to -1.  Removed ones will just be absent.
		// Note that we may remove the pipedesc from the list, so we
		// have to use a custom iterator.
		nextpd = nni_list_first(&pollq->pds);
		while ((pd = nextpd) != NULL) {
			int index;

			// Save the nextpd for our next iteration.  This
			// way we can remove the PD from the list without
			// breaking the iteration.

			nextpd = nni_list_next(&pollq->pds, pd);
			if ((index = pd->index) < 1) {
				continue;
			}
			pd->index = 0;
			if (fds[index].revents & POLLIN) {
				// process the read q.
				nni_posix_poll_read(pd);
			}
			if (fds[index].revents & POLLOUT) {
				// process the write q.
				nni_posix_poll_write(pd);
			}
			if (fds[index].revents & (POLLHUP|POLLERR|POLLNVAL)) {
				// the pipe is closed.  wake all the
				// aios with NNG_ECLOSED.
				nni_posix_poll_close(pd);
			}

			// If we have completed all the AIOs outstanding,
			// then remove this pipedesc from the pollq.
			if ((nni_list_first(&pd->readq) == NULL) &&
			    (nni_list_first(&pd->writeq) == NULL)) {
				nni_list_remove(&pollq->pds, pd);
				pollq->npds--;
			}
		}
		// Same thing for ep descs.
		nexted = nni_list_first(&pollq->eds);
		while ((ed = nexted) != NULL) {
			int index;

			nexted = nni_list_next(&pollq->eds, ed);
			if ((index = ed->index) < 1) {
				continue;
			}
			ed->index = 0;
			if (fds[index].revents & POLLIN) {
				nni_posix_poll_accept(ed);
			}
			if (fds[index].revents & POLLOUT) {
				nni_posix_poll_connect(ed);
			}
			if (fds[index].revents & (POLLHUP|POLLERR|POLLNVAL)) {
				nni_posix_poll_epclose(ed);
			}
			if ((nni_list_first(&ed->connectq) == NULL) &&
			    (nni_list_first(&ed->acceptq) == NULL)) {
				nni_list_remove(&pollq->eds, ed);
				pollq->neds--;
			}
		}
	}
	nni_mtx_unlock(&pollq->mtx);
}


static void
nni_posix_pipedesc_cancel(nni_aio *aio)
{
	nni_posix_pipedesc *pd;
	nni_posix_pollq *pq;

	pd = aio->a_prov_data;
	pq = pd->pq;

	nni_mtx_lock(&pq->mtx);
	// This will remove the aio from either the read or the write
	// list; it doesn't matter which.
	if (nni_list_active(&pd->readq, aio)) {
		nni_list_remove(&pd->readq, aio);
	}
	nni_mtx_unlock(&pq->mtx);
}


static void
nni_posix_pipedesc_submit(nni_posix_pipedesc *pd, nni_list *l, nni_aio *aio)
{
	int wake;
	int rv;
	nni_posix_pollq *pq = pd->pq;

	nni_mtx_lock(&pq->mtx);
	if ((rv = nni_aio_start(aio, nni_posix_pipedesc_cancel, pd)) != 0) {
		nni_mtx_unlock(&pq->mtx);
		return;
	}
	if (pd->fd < 0) {
		nni_posix_pipedesc_finish(aio, NNG_ECLOSED);
		nni_mtx_unlock(&pq->mtx);
		return;
	}
	// XXX: We really should just make all the FDs nonblocking, but we
	// need to fix the negotiation phase.
	if (pd->nonblocking == 0) {
		(void) fcntl(pd->fd, F_SETFL, O_NONBLOCK);
		pd->nonblocking = 1;
	}
	if (!nni_list_active(&pq->pds, pd)) {
		if ((rv = nni_posix_poll_grow(pq)) != 0) {
			nni_posix_pipedesc_finish(aio, rv);
			nni_mtx_unlock(&pq->mtx);
			return;
		}

		nni_list_append(&pq->pds, pd);
		pq->npds++;
	}
	NNI_ASSERT(!nni_list_active(l, aio));
	// Only wake if we aren't already waiting for this type of I/O on
	// this descriptor.
	wake = nni_list_first(l) == NULL ? 1 : 0;
	nni_list_append(l, aio);

	if (wake) {
		nni_plat_pipe_raise(pq->wakewfd);
	}
	nni_mtx_unlock(&pq->mtx);
}


int
nni_posix_pipedesc_init(nni_posix_pipedesc **pdp, int fd)
{
	nni_posix_pipedesc *pd;


	if ((pd = NNI_ALLOC_STRUCT(pd)) == NULL) {
		return (NNG_ENOMEM);
	}

	// We could randomly choose a different pollq, or for efficiencies
	// sake we could take a modulo of the file desc number to choose
	// one.  For now we just have a global pollq.  Note that by tying
	// the pd to a single pollq we may get some kind of cache warmth.

	pd->pq = &nni_posix_global_pollq;
	pd->fd = fd;
	pd->index = 0;
	pd->nonblocking = 0;

	NNI_LIST_INIT(&pd->readq, nni_aio, a_prov_node);
	NNI_LIST_INIT(&pd->writeq, nni_aio, a_prov_node);

	*pdp = pd;
	return (0);
}


void
nni_posix_pipedesc_fini(nni_posix_pipedesc *pd)
{
	nni_aio *aio;
	nni_posix_pollq *pq = pd->pq;

	nni_mtx_lock(&pq->mtx);

	// This removes any aios from our list.
	nni_posix_poll_close(pd);

	if (nni_list_active(&pq->pds, pd)) {
		nni_list_remove(&pq->pds, pd);
		pq->npds--;
	}
	nni_mtx_unlock(&pq->mtx);

	NNI_FREE_STRUCT(pd);
}


static void
nni_posix_pollq_fini(nni_posix_pollq *pq)
{
	if (pq->started) {
		nni_mtx_lock(&pq->mtx);
		pq->close = 1;
		pq->started = 0;
		nni_plat_pipe_raise(pq->wakewfd);

		// All pipes should have been closed before this is called.
		NNI_ASSERT(nni_list_first(&pq->pds) == NULL);
		nni_mtx_unlock(&pq->mtx);
	}

	nni_thr_fini(&pq->thr);
	if (pq->wakewfd >= 0) {
		nni_plat_pipe_close(pq->wakewfd, pq->wakerfd);
		pq->wakewfd = pq->wakerfd = -1;
	}
	nni_free(pq->newfds, pq->nnewfds * sizeof (struct pollfd));
	nni_free(pq->fds, pq->nfds * sizeof (struct pollfd));
	nni_mtx_fini(&pq->mtx);
}


static int
nni_posix_pollq_init(nni_posix_pollq *pq)
{
	int rv;

	NNI_LIST_INIT(&pq->pds, nni_posix_pipedesc, node);
	pq->wakewfd = -1;
	pq->wakerfd = -1;
	pq->close = 0;

	if (((rv = nni_mtx_init(&pq->mtx)) != 0) ||
	    ((rv = nni_posix_poll_grow(pq)) != 0) ||
	    ((rv = nni_plat_pipe_open(&pq->wakewfd, &pq->wakerfd)) != 0) ||
	    ((rv = nni_thr_init(&pq->thr, nni_posix_poll_thr, pq)) != 0)) {
		nni_posix_pollq_fini(pq);
		return (rv);
	}
	pq->started = 1;
	nni_thr_run(&pq->thr);
	return (0);
}


int
nni_posix_pipedesc_sysinit(void)
{
	int rv;

	rv = nni_posix_pollq_init(&nni_posix_global_pollq);
	return (rv);
}


void
nni_posix_pipedesc_sysfini(void)
{
	nni_posix_pollq_fini(&nni_posix_global_pollq);
}


// extern int nni_posix_aio_ep_init(nni_posix_aio_ep *, int);
// extern void nni_posix_aio_ep_fini(nni_posix_aio_ep *);

void
nni_posix_pipedesc_read(nni_posix_pipedesc *pd, nni_aio *aio)
{
	nni_posix_pipedesc_submit(pd, &pd->readq, aio);
}


void
nni_posix_pipedesc_write(nni_posix_pipedesc *pd, nni_aio *aio)
{
	nni_posix_pipedesc_submit(pd, &pd->writeq, aio);
}


// extern int nni_posix_aio_connect();
// extern int nni_posix_aio_accept();

#else

// Suppress empty symbols warnings in ranlib.
int nni_posix_poll_not_used = 0;

#endif // NNG_USE_POSIX_AIOPOLL
