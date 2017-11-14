//
// Copyright 2017 Garrett D'Amore <garrett@damore.org>
// Copyright 2017 Capitar IT Group BV <info@capitar.com>
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
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

// nni_posix_pipedesc is a descriptor kept one per transport pipe (i.e. open
// file descriptor for TCP socket, etc.)  This contains the list of pending
// aios for that underlying socket, as well as the socket itself.
struct nni_posix_pipedesc {
	nni_posix_pollq_node node;
	nni_list             readq;
	nni_list             writeq;
	int                  closed;
	nni_mtx              mtx;
};

static void
nni_posix_pipedesc_finish(nni_aio *aio, int rv)
{
	nni_aio_list_remove(aio);
	nni_aio_finish(aio, rv, aio->a_count);
}

static void
nni_posix_pipedesc_doclose(nni_posix_pipedesc *pd)
{
	nni_aio *aio;
	int      fd;

	pd->closed = 1;
	while ((aio = nni_list_first(&pd->readq)) != NULL) {
		nni_posix_pipedesc_finish(aio, NNG_ECLOSED);
	}
	while ((aio = nni_list_first(&pd->writeq)) != NULL) {
		nni_posix_pipedesc_finish(aio, NNG_ECLOSED);
	}
	if ((fd = pd->node.fd) != -1) {
		// Let any peer know we are closing.
		pd->node.fd = -1;
		(void) shutdown(fd, SHUT_RDWR);
		(void) close(fd);
	}
}

static void
nni_posix_pipedesc_dowrite(nni_posix_pipedesc *pd)
{
	int          n;
	struct iovec iovec[4];
	nni_aio *    aio;
	int          niov;

	while ((aio = nni_list_first(&pd->writeq)) != NULL) {
		int i;
		for (niov = 0, i = 0; i < aio->a_niov; i++) {
			iovec[niov].iov_len  = aio->a_iov[i].iov_len;
			iovec[niov].iov_base = aio->a_iov[i].iov_buf;
			niov++;
		}
		if (niov == 0) {
			nni_posix_pipedesc_finish(aio, NNG_EINVAL);
			continue;
		}

		n = writev(pd->node.fd, iovec, niov);
		if (n < 0) {
			if ((errno == EAGAIN) || (errno == EINTR)) {
				// Can't write more right now.  We're done
				// on this fd for now.
				return;
			}
			nni_posix_pipedesc_finish(aio, nni_plat_errno(errno));
			nni_posix_pipedesc_doclose(pd);
			return;
		}

		aio->a_count += n;

		// We completed the entire operation on this aioq.
		nni_posix_pipedesc_finish(aio, 0);

		// Go back to start of loop to see if there is another
		// aio ready for us to process.
	}
}

static void
nni_posix_pipedesc_doread(nni_posix_pipedesc *pd)
{
	int          n;
	struct iovec iovec[4];
	nni_aio *    aio;
	int          niov;

	while ((aio = nni_list_first(&pd->readq)) != NULL) {
		int i;
		for (i = 0, niov = 0; i < aio->a_niov; i++) {
			if (aio->a_iov[i].iov_len != 0) {
				iovec[niov].iov_len  = aio->a_iov[i].iov_len;
				iovec[niov].iov_base = aio->a_iov[i].iov_buf;
				niov++;
			}
		}
		if (niov == 0) {
			nni_posix_pipedesc_finish(aio, NNG_EINVAL);
			continue;
		}

		n = readv(pd->node.fd, iovec, niov);
		if (n < 0) {
			if ((errno == EAGAIN) || (errno == EINTR)) {
				// Can't write more right now.  We're done
				// on this fd for now.
				return;
			}
			nni_posix_pipedesc_finish(aio, nni_plat_errno(errno));
			nni_posix_pipedesc_doclose(pd);
			return;
		}

		if (n == 0) {
			// No bytes indicates a closed descriptor.
			nni_posix_pipedesc_finish(aio, NNG_ECLOSED);
			nni_posix_pipedesc_doclose(pd);
			return;
		}

		aio->a_count += n;

		// We completed the entire operation on this aioq.
		nni_posix_pipedesc_finish(aio, 0);

		// Go back to start of loop to see if there is another
		// aio ready for us to process.
	}
}

static void
nni_posix_pipedesc_cb(void *arg)
{
	nni_posix_pipedesc *pd     = arg;
	int                 events = 0;

	nni_mtx_lock(&pd->mtx);
	if (pd->node.revents & POLLIN) {
		nni_posix_pipedesc_doread(pd);
	}
	if (pd->node.revents & POLLOUT) {
		nni_posix_pipedesc_dowrite(pd);
	}
	if (pd->node.revents & (POLLHUP | POLLERR | POLLNVAL)) {
		nni_posix_pipedesc_doclose(pd);
	} else {
		if (!nni_list_empty(&pd->writeq)) {
			events |= POLLOUT;
		}
		if (!nni_list_empty(&pd->readq)) {
			events |= POLLIN;
		}
		if (events) {
			nni_posix_pollq_arm(&pd->node, events);
		}
	}
	nni_mtx_unlock(&pd->mtx);
}

void
nni_posix_pipedesc_close(nni_posix_pipedesc *pd)
{
	nni_posix_pollq_disarm(&pd->node, POLLIN | POLLOUT);

	nni_mtx_lock(&pd->mtx);
	nni_posix_pipedesc_doclose(pd);
	nni_mtx_unlock(&pd->mtx);
}

static void
nni_posix_pipedesc_cancel(nni_aio *aio, int rv)
{
	nni_posix_pipedesc *pd = aio->a_prov_data;

	nni_mtx_lock(&pd->mtx);
	if (nni_aio_list_active(aio)) {
		nni_aio_list_remove(aio);
		nni_aio_finish_error(aio, rv);
	}
	nni_mtx_unlock(&pd->mtx);
}

void
nni_posix_pipedesc_recv(nni_posix_pipedesc *pd, nni_aio *aio)
{
	int rv;

	nni_mtx_lock(&pd->mtx);
	if ((rv = nni_aio_start(aio, nni_posix_pipedesc_cancel, pd)) != 0) {
		nni_mtx_unlock(&pd->mtx);
		return;
	}
	if (pd->closed) {
		nni_posix_pipedesc_finish(aio, NNG_ECLOSED);
		nni_mtx_unlock(&pd->mtx);
		return;
	}

	nni_aio_list_append(&pd->readq, aio);
	// If we are only job on the list, go ahead and try to do an immediate
	// transfer. This allows for faster completions in many cases.  We
	// also need not arm a list if it was already armed.
	if (nni_list_first(&pd->readq) == aio) {
		nni_posix_pipedesc_doread(pd);
		// If we are still the first thing on the list, that means we
		// didn't finish the job, so arm the poller to complete us.
		if (nni_list_first(&pd->readq) == aio) {
			nni_posix_pollq_arm(&pd->node, POLLIN);
		}
	}
	nni_mtx_unlock(&pd->mtx);
}

void
nni_posix_pipedesc_send(nni_posix_pipedesc *pd, nni_aio *aio)
{
	int rv;

	nni_mtx_lock(&pd->mtx);
	if ((rv = nni_aio_start(aio, nni_posix_pipedesc_cancel, pd)) != 0) {
		nni_mtx_unlock(&pd->mtx);
		return;
	}
	if (pd->closed) {
		nni_posix_pipedesc_finish(aio, NNG_ECLOSED);
		nni_mtx_unlock(&pd->mtx);
		return;
	}

	nni_aio_list_append(&pd->writeq, aio);
	if (nni_list_first(&pd->writeq) == aio) {
		nni_posix_pipedesc_dowrite(pd);
		// If we are still the first thing on the list, that means we
		// didn't finish the job, so arm the poller to complete us.
		if (nni_list_first(&pd->writeq) == aio) {
			nni_posix_pollq_arm(&pd->node, POLLOUT);
		}
	}
	nni_mtx_unlock(&pd->mtx);
}

int
nni_posix_pipedesc_peername(nni_posix_pipedesc *pd, nni_sockaddr *sa)
{
	struct sockaddr_storage ss;
	socklen_t               sslen = sizeof(ss);

	if (getpeername(pd->node.fd, (void *) &ss, &sslen) != 0) {
		return (nni_plat_errno(errno));
	}
	return (nni_posix_sockaddr2nn(sa, &ss));
}

int
nni_posix_pipedesc_sockname(nni_posix_pipedesc *pd, nni_sockaddr *sa)
{
	struct sockaddr_storage ss;
	socklen_t               sslen = sizeof(ss);

	if (getsockname(pd->node.fd, (void *) &ss, &sslen) != 0) {
		return (nni_plat_errno(errno));
	}
	return (nni_posix_sockaddr2nn(sa, &ss));
}

int
nni_posix_pipedesc_init(nni_posix_pipedesc **pdp, int fd)
{
	nni_posix_pipedesc *pd;
	int                 rv;

	if ((pd = NNI_ALLOC_STRUCT(pd)) == NULL) {
		return (NNG_ENOMEM);
	}

	// We could randomly choose a different pollq, or for efficiencies
	// sake we could take a modulo of the file desc number to choose
	// one.  For now we just have a global pollq.  Note that by tying
	// the pd to a single pollq we may get some kind of cache warmth.

	pd->closed    = 0;
	pd->node.fd   = fd;
	pd->node.cb   = nni_posix_pipedesc_cb;
	pd->node.data = pd;

	(void) fcntl(fd, F_SETFL, O_NONBLOCK);

#ifdef SO_NOSIGPIPE
	// Darwin lacks MSG_NOSIGNAL, but has a socket option.
	int one = 1;
	(void) setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
#endif

	nni_mtx_init(&pd->mtx);
	nni_aio_list_init(&pd->readq);
	nni_aio_list_init(&pd->writeq);

	rv = nni_posix_pollq_add(nni_posix_pollq_get(fd), &pd->node);
	if (rv != 0) {
		nni_mtx_fini(&pd->mtx);
		NNI_FREE_STRUCT(pd);
		return (rv);
	}
	*pdp = pd;
	return (0);
}

void
nni_posix_pipedesc_fini(nni_posix_pipedesc *pd)
{
	// Make sure no other polling activity is pending.
	nni_posix_pipedesc_close(pd);
	nni_posix_pollq_remove(&pd->node);
	if (pd->node.fd >= 0) {
		(void) close(pd->node.fd);
	}

	nni_mtx_fini(&pd->mtx);

	NNI_FREE_STRUCT(pd);
}

#endif // NNG_PLATFORM_POSIX
