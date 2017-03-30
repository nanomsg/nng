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

#ifdef NNG_USE_POSIX_AIOTHR

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <fcntl.h>
#include <unistd.h>

// POSIX AIO using threads.  This allows us to use normal synchronous AIO,
// along with underlying threads, to simulate asynchronous I/O.  This will be
// unscalable for systems where threads are a finite resource, but it should
// be sufficient for systems where threads are efficient, and cheap, or for
// applications that do not need excessive amounts of open files.  It also
// serves as a model upon which we can build more scalable forms of asynch
// I/O, using non-blocking I/O and pollers.


// nni_plat_aiothr_write is used to attempt a write, sending
// as much as it can.  On success, it returns 0, otherwise an errno. It will
// retry if EINTR is received.
static int
nni_plat_aiothr_write(int fd, nni_aio *aio)
{
	int n;
	int rv;
	int i;
	struct iovec iovec[4];
	struct iovec *iovp;
	int niov = aio->a_niov;
	int progress = 0;

	for (i = 0; i < niov; i++) {
		iovec[i].iov_len = aio->a_iov[i].iov_len;
		iovec[i].iov_base = aio->a_iov[i].iov_buf;
	}
	iovp = &iovec[0];
	rv = 0;

	while (niov != 0) {
		n = writev(fd, iovp, niov);
		if (n < 0) {
			if (errno == EINTR) {
				continue;
			}
			rv = nni_plat_errno(errno);
			break;
		}

		aio->a_count += n;
		progress += n;
		while (n) {
			// If we didn't finish it yet, try again.
			if (n < iovp->iov_len) {
				iovp->iov_len -= n;
				iovp->iov_base += n;
				break;
			}

			n -= iovp->iov_len;
			iovp++;
			niov--;
		}
	}

	// Either we got it all, or we didn't.
	if ((rv != 0) && (progress != 0)) {
		for (i = 0; i < niov; i++) {
			aio->a_iov[i].iov_len = iovp[i].iov_len;
			aio->a_iov[i].iov_buf = iovp[i].iov_base;
		}
		aio->a_niov = niov;
	}

	return (rv);
}


// nni_plat_aiothr_read is used to attempt a read, sending as much as it can
// (limited by the requested read).  On success, it returns 0, otherwise an
// errno. It will retry if EINTR is received.
static int
nni_plat_aiothr_read(int fd, nni_aio *aio)
{
	int n;
	int rv;
	int i;
	struct iovec iovec[4];
	struct iovec *iovp;
	int niov = aio->a_niov;
	int progress = 0;

	for (i = 0; i < niov; i++) {
		iovec[i].iov_len = aio->a_iov[i].iov_len;
		iovec[i].iov_base = aio->a_iov[i].iov_buf;
	}
	iovp = &iovec[0];
	rv = 0;

	while (niov != 0) {
		n = readv(fd, iovp, niov);
		if (n < 0) {
			if (errno == EINTR) {
				continue;
			}
			rv = nni_plat_errno(errno);
			break;
		}
		if (n == 0) {
			rv = NNG_ECLOSED;
			break;
		}

		aio->a_count += n;
		progress += n;
		while (n) {
			// If we didn't finish it yet, try again.
			if (n < iovp->iov_len) {
				iovp->iov_len -= n;
				iovp->iov_base += n;
				break;
			}

			n -= iovp->iov_len;
			iovp++;
			niov--;
		}
	}

	// Either we got it all, or we didn't.
	if ((rv != 0) && (progress != 0)) {
		for (i = 0; i < niov; i++) {
			aio->a_iov[i].iov_len = iovp[i].iov_len;
			aio->a_iov[i].iov_buf = iovp[i].iov_base;
		}
		aio->a_niov = niov;
	}

	return (rv);
}


static void
nni_plat_aiothr_dothr(nni_posix_aioq *q, int (*fn)(int, nni_aio *))
{
	nni_aio *aio;
	int rv;

	nni_mtx_lock(&q->aq_lk);
	for (;;) {
		if (q->aq_fd < 0) {
			break;
		}
		if ((aio = nni_list_first(&q->aq_aios)) == NULL) {
			nni_cv_wait(&q->aq_cv);
			continue;
		}
		rv = fn(q->aq_fd, aio);
		if (rv == NNG_EAGAIN) {
			continue;
		}
		if (rv == NNG_ECLOSED) {
			break;
		}

		nni_list_remove(&q->aq_aios, aio);

		// Call the callback.
		nni_aio_finish(aio, rv, aio->a_count);
	}

	while ((aio = nni_list_first(&q->aq_aios)) != NULL) {
		nni_list_remove(&q->aq_aios, aio);
		nni_aio_finish(aio, NNG_ECLOSED, aio->a_count);
	}

	nni_mtx_unlock(&q->aq_lk);
}


static void
nni_plat_aiothr_readthr(void *arg)
{
	nni_plat_aiothr_dothr(arg, nni_plat_aiothr_read);
}


static void
nni_plat_aiothr_writethr(void *arg)
{
	nni_plat_aiothr_dothr(arg, nni_plat_aiothr_write);
}


static int
nni_posix_aioq_init(nni_posix_aioq *q, int fd, nni_cb cb)
{
	int rv;

	NNI_LIST_INIT(&q->aq_aios, nni_aio, a_prov_node);
	if ((rv = nni_mtx_init(&q->aq_lk)) != 0) {
		return (rv);
	}
	if ((rv = nni_cv_init(&q->aq_cv, &q->aq_lk)) != 0) {
		nni_mtx_fini(&q->aq_lk);
		return (rv);
	}
	if ((rv = nni_thr_init(&q->aq_thr, cb, q)) != 0) {
		nni_cv_fini(&q->aq_cv);
		nni_mtx_fini(&q->aq_lk);
		return (rv);
	}
	q->aq_fd = fd;
	return (0);
}


static void
nni_posix_aioq_start(nni_posix_aioq *q)
{
	nni_thr_run(&q->aq_thr);
}


static void
nni_posix_aioq_fini(nni_posix_aioq *q)
{
	if (q->aq_fd > 0) {
		nni_mtx_lock(&q->aq_lk);
		q->aq_fd = -1;
		nni_cv_wake(&q->aq_cv);
		nni_mtx_unlock(&q->aq_lk);

		nni_thr_fini(&q->aq_thr);
		nni_cv_fini(&q->aq_cv);
		nni_mtx_fini(&q->aq_lk);
	}
}


int
nni_posix_aio_pipe_init(nni_posix_aio_pipe *p, int fd)
{
	int rv;

	rv = nni_posix_aioq_init(&p->ap_readq, fd, nni_plat_aiothr_readthr);
	if (rv != 0) {
		return (rv);
	}
	rv = nni_posix_aioq_init(&p->ap_writeq, fd, nni_plat_aiothr_writethr);
	if (rv != 0) {
		nni_posix_aioq_fini(&p->ap_readq);
		return (rv);
	}
	nni_posix_aioq_start(&p->ap_readq);
	nni_posix_aioq_start(&p->ap_writeq);
	return (0);
}


void
nni_posix_aio_pipe_fini(nni_posix_aio_pipe *p)
{
	nni_posix_aioq_fini(&p->ap_readq);
	nni_posix_aioq_fini(&p->ap_writeq);
}


// extern int nni_posix_aio_ep_init(nni_posix_aio_ep *, int);
// extern void nni_posix_aio_ep_fini(nni_posix_aio_ep *);

static int
nni_posix_aio_submit(nni_posix_aioq *q, nni_aio *aio)
{
	nni_mtx_lock(&q->aq_lk);
	if (q->aq_fd < 0) {
		nni_mtx_unlock(&q->aq_lk);
		return (NNG_ECLOSED);
	}
	nni_list_append(&q->aq_aios, aio);
	nni_cv_wake(&q->aq_cv);
	nni_mtx_unlock(&q->aq_lk);
	return (0);
}


int
nni_posix_aio_read(nni_posix_aio_pipe *p, nni_aio *aio)
{
	return (nni_posix_aio_submit(&p->ap_readq, aio));
}


int
nni_posix_aio_write(nni_posix_aio_pipe *p, nni_aio *aio)
{
	return (nni_posix_aio_submit(&p->ap_writeq, aio));
}


// extern int nni_posix_aio_connect();
// extern int nni_posix_aio_accept();

#else

// Suppress empty symbols warnings in ranlib.
int nni_posix_aiothr_not_used = 0;

#endif // NNG_USE_POSIX_AIOTHR
