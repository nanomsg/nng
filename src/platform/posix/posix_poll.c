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
	nni_list	pds;            // linked list of nni_posix_pipedescs.
	int		npds;           // number of pipe descriptors
};

static nni_posix_pollq nni_posix_global_pollq;

static void
nni_posix_poll_finish(nni_aio *aio, int rv)
{
	nni_posix_pipedesc *pd;

	pd = aio->a_prov_data;
	if (nni_list_active(&pd->readq, aio)) {
		nni_list_remove(&pd->readq, aio);
	}
	aio->a_prov_data = NULL;
	aio->a_prov_cancel = NULL;
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
			nni_list_remove(&pd->writeq, aio);

			nni_posix_poll_finish(aio, rv);
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
		nni_posix_poll_finish(aio, 0);

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

			nni_posix_poll_finish(aio, rv);
			return;
		}

		if (n == 0) {
			// No bytes indicates a closed descriptor.
			nni_posix_poll_finish(aio, NNG_ECLOSED);
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
		nni_posix_poll_finish(aio, 0);

		// Go back to start of loop to see if there is another
		// aioq ready for us to process.
	}
}


static void
nni_posix_poll_close(nni_posix_pipedesc *pd)
{
	nni_aio *aio;

	while ((aio = nni_list_first(&pd->readq)) != NULL) {
		nni_posix_poll_finish(aio, NNG_ECLOSED);
	}
	while ((aio = nni_list_first(&pd->writeq)) != NULL) {
		nni_posix_poll_finish(aio, NNG_ECLOSED);
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
	}
	nni_mtx_unlock(&pq->mtx);
}


static void
nni_posix_poll_thr(void *arg)
{
	nni_posix_pollq *pollq = arg;
	nni_posix_pipedesc *pd, *nextpd;

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


static int
nni_posix_poll_grow(nni_posix_pollq *pq)
{
	int grow = pq->npds + 2; // one for us, one for waker
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
nni_posix_pipedesc_submit(nni_posix_pipedesc *pd, nni_list *l, nni_aio *aio)
{
	int wake;
	int rv;
	nni_posix_pollq *pq = pd->pq;

	// XXX: this should be done only once, after tcp negot. is done
	// or at init if we can get tcp negot. to be async.
	(void) fcntl(pd->fd, F_SETFL, O_NONBLOCK);

	nni_mtx_lock(&pq->mtx);
	if (pd->fd < 0) {
		nni_mtx_unlock(&pq->mtx);
		nni_aio_finish(aio, NNG_ECLOSED, aio->a_count);
	}
	if ((rv = nni_aio_start(aio, nni_posix_pipedesc_cancel, pd)) != 0) {
		nni_mtx_unlock(&pq->mtx);
		return;
	}
	if (!nni_list_active(&pq->pds, pd)) {
		if ((rv = nni_posix_poll_grow(pq)) != 0) {
			nni_aio_finish(aio, rv, aio->a_count);
			nni_mtx_unlock(&pq->mtx);
			return;
		}

		nni_list_append(&pq->pds, pd);
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

int
nni_posix_pipedesc_read(nni_posix_pipedesc *pd, nni_aio *aio)
{
	aio->a_count = 0;

	nni_posix_pipedesc_submit(pd, &pd->readq, aio);
	return (0);
}


int
nni_posix_pipedesc_write(nni_posix_pipedesc *pd, nni_aio *aio)
{
	aio->a_count = 0;
	nni_posix_pipedesc_submit(pd, &pd->writeq, aio);
	return (0);
}


// extern int nni_posix_aio_connect();
// extern int nni_posix_aio_accept();

#else

// Suppress empty symbols warnings in ranlib.
int nni_posix_poll_not_used = 0;

#endif // NNG_USE_POSIX_AIOPOLL
