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

#ifdef PLATFORM_POSIX_UDP
#include "platform/posix/posix_aio.h"
#include "platform/posix/posix_pollq.h"

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

// UDP support.

// If we can suppress SIGPIPE on send, please do so.
#ifdef MSG_NOSIGNAL
#define NNI_MSG_NOSIGNAL MSG_NOSIGNAL
#else
#define NNI_MSG_NOSIGNAL 0
#endif

struct nni_plat_udp {
	nni_posix_pollq_node udp_pitem;
	int                  udp_fd;
	int                  udp_closed;
	nni_list             udp_recvq;
	nni_list             udp_sendq;
	nni_mtx              udp_mtx;
};

static void
nni_posix_udp_doclose(nni_plat_udp *udp)
{
	nni_aio *aio;

	udp->udp_closed = 1;
	while ((aio = nni_list_first(&udp->udp_recvq)) != NULL) {
		nni_list_remove(&udp->udp_recvq, aio);
		nni_aio_finish(aio, NNG_ECLOSED, 0);
	}
	while ((aio = nni_list_first(&udp->udp_sendq)) != NULL) {
		nni_list_remove(&udp->udp_recvq, aio);
		nni_aio_finish(aio, NNG_ECLOSED, 0);
	}
	// Underlying socket left open until close API called.
}

static void
nni_posix_udp_dorecv(nni_plat_udp *udp)
{
	nni_aio *               aio;
	struct sockaddr_storage ss;
	struct msghdr           hdr;
	int                     niov;
	int                     rv;
	nni_list *              q = &udp->udp_recvq;

	// While we're able to recv, do so.
	while ((aio = nni_list_first(q)) != NULL) {
		nni_list_remove(q, aio);

		for (niov = 0; niov < aio->a_niov; niov++) {
			hdr.msg_iov[niov].iov_base = aio->a_iov[niov].iov_buf;
			hdr.msg_iov[niov].iov_len  = aio->a_iov[niov].iov_len;
		}
		hdr.msg_iovlen     = niov;
		hdr.msg_name       = &ss;
		hdr.msg_namelen    = sizeof(ss);
		hdr.msg_flags      = 0;
		hdr.msg_control    = NULL;
		hdr.msg_controllen = 0;
		rv                 = recvmsg(udp->udp_fd, &hdr, 0);
		if (rv < 0) {
			if ((errno == EAGAIN) || (errno == EWOULDBLOCK)) {
				// No data available at socket.  Return
				// the AIO to the head of the queue.
				nni_list_prepend(q, aio);
				return;
			}
			rv = nni_plat_errno(errno);
			nni_aio_finish(aio, rv, 0);
			continue;
		}

		// We need to store the address information.
		// It is incumbent on the AIO submitter to supply
		// storage for the address.
		if (aio->a_naddrs > 0) {
			nni_posix_sockaddr2nn(&aio->a_addrs[0], (void *) &ss);
		}

		nni_aio_finish(aio, 0, rv);
	}
}

static void
nni_posix_udp_dosend(nni_plat_udp *udp)
{
	// XXX: TBD.
	nni_aio *               aio;
	struct sockaddr_storage ss;
	struct msghdr           hdr;
	int                     niov;
	int                     rv;
	int                     len;
	nni_list *              q = &udp->udp_sendq;

	// While we're able to recv, do so.
	while ((aio = nni_list_first(q)) != NULL) {
		nni_list_remove(q, aio);

		if (aio->a_naddrs < 1) {
			// No incoming address?
			nni_aio_finish(aio, NNG_EADDRINVAL, 0);
			return;
		}
		len = nni_posix_nn2sockaddr(&ss, &aio->a_addrs[0]);
		if (len < 0) {
			nni_aio_finish(aio, NNG_EADDRINVAL, 0);
			return;
		}

		for (niov = 0; niov < aio->a_niov; niov++) {
			hdr.msg_iov[niov].iov_base = aio->a_iov[niov].iov_buf;
			hdr.msg_iov[niov].iov_len  = aio->a_iov[niov].iov_len;
		}
		hdr.msg_iovlen     = niov;
		hdr.msg_name       = &ss;
		hdr.msg_namelen    = len;
		hdr.msg_flags      = NNI_MSG_NOSIGNAL;
		hdr.msg_control    = NULL;
		hdr.msg_controllen = 0;

		rv = sendmsg(udp->udp_fd, &hdr, 0);
		if (rv < 0) {
			if ((errno == EAGAIN) || (errno == EWOULDBLOCK)) {
				// Cannot send (buffers full), return to
				// head of queue.
				nni_list_prepend(q, aio);
				return;
			}
			rv = nni_plat_errno(errno);
			nni_aio_finish(aio, rv, 0);
			continue;
		}

		nni_aio_finish(aio, 0, rv);
	}
}

// This function is called by the poller on activity on the FD.
static void
nni_posix_udp_cb(void *arg)
{
	nni_plat_udp *udp = arg;
	int           revents;
	int           events = 0;

	nni_mtx_lock(&udp->udp_mtx);
	revents = udp->udp_pitem.revents;
	if (revents & POLLIN) {
		nni_posix_udp_dorecv(udp);
	}
	if (revents & POLLOUT) {
		nni_posix_udp_dosend(udp);
	}
	if (revents & (POLLHUP | POLLERR | POLLNVAL)) {
		nni_posix_udp_doclose(udp);
	} else {
		if (!nni_list_empty(&udp->udp_sendq)) {
			events |= POLLOUT;
		}
		if (!nni_list_empty(&udp->udp_recvq)) {
			events |= POLLIN;
		}
		if (events) {
			nni_posix_pollq_arm(&udp->udp_pitem, events);
		}
	}
	nni_mtx_unlock(&udp->udp_mtx);
}

int
nni_plat_udp_open(nni_plat_udp **upp, nni_sockaddr *bindaddr)
{
	nni_plat_udp *          udp;
	int                     salen;
	struct sockaddr_storage sa;
	int                     rv;

	if ((salen = nni_posix_nn2sockaddr(&sa, bindaddr)) < 0) {
		return (NNG_EADDRINVAL);
	}

	// UDP opens can actually run synchronously.
	if ((udp = NNI_ALLOC_STRUCT(udp)) != NULL) {
		return (NNG_ENOMEM);
	}
	if ((rv = nni_mtx_init(&udp->udp_mtx)) != 0) {
		NNI_FREE_STRUCT(udp);
		return (rv);
	}

	udp->udp_fd = socket(sa.ss_family, SOCK_DGRAM, IPPROTO_UDP);
	if (udp->udp_fd < 0) {
		rv = nni_plat_errno(errno);
		nni_mtx_fini(&udp->udp_mtx);
		NNI_FREE_STRUCT(udp);
		return (rv);
	}

	if (bind(udp->udp_fd, (void *) &sa, salen) != 0) {
		rv = nni_plat_errno(errno);
		(void) close(udp->udp_fd);
		nni_mtx_fini(&udp->udp_mtx);
		NNI_FREE_STRUCT(udp);
		return (rv);
	}
	udp->udp_pitem.fd   = udp->udp_fd;
	udp->udp_pitem.cb   = nni_posix_udp_cb;
	udp->udp_pitem.data = udp;

	nni_aio_list_init(&udp->udp_recvq);
	nni_aio_list_init(&udp->udp_sendq);

	rv = nni_posix_pollq_add(
	    nni_posix_pollq_get(udp->udp_fd), &udp->udp_pitem);
	if (rv != 0) {
		(void) close(udp->udp_fd);
		nni_mtx_fini(&udp->udp_mtx);
		NNI_FREE_STRUCT(udp);
		return (rv);
	}

	*upp = udp;
	return (0);
}

void
nni_plat_udp_close(nni_plat_udp *udp)
{
	nni_aio *aio;

	nni_mtx_lock(&udp->udp_mtx);
	if (udp->udp_closed) {
		// The only way this happens is in response to a callback that
		// is being canceled.  Double close from user code is a bug.
		nni_mtx_unlock(&udp->udp_mtx);
		return;
	}

	// We're no longer interested in events.
	nni_posix_pollq_remove(&udp->udp_pitem);

	nni_posix_udp_doclose(udp);
	nni_mtx_unlock(&udp->udp_mtx);

	(void) close(udp->udp_fd);
	nni_mtx_fini(&udp->udp_mtx);
	NNI_FREE_STRUCT(udp);
}

void
nni_plat_udp_cancel(nni_aio *aio)
{
	nni_plat_udp *udp = aio->a_prov_data;

	nni_mtx_lock(&udp->udp_mtx);
	nni_aio_list_remove(aio);
	nni_mtx_unlock(&udp->udp_mtx);
}

void
nni_plat_udp_recv(nni_plat_udp *udp, nni_aio *aio)
{
	nni_mtx_lock(&udp->udp_mtx);
	if (nni_aio_start(aio, nni_plat_udp_cancel, udp) != 0) {
		nni_mtx_unlock(&udp->udp_mtx);
		return;
	}

	if (udp->udp_closed) {
		nni_aio_finish(aio, NNG_ECLOSED, 0);
		nni_mtx_unlock(&udp->udp_mtx);
		return;
	}

	nni_list_append(&udp->udp_recvq, aio);
	nni_posix_pollq_arm(&udp->udp_pitem, POLLIN);
	nni_mtx_unlock(&udp->udp_mtx);
}

void
nni_plat_udp_send(nni_plat_udp *udp, nni_aio *aio)
{
	nni_mtx_lock(&udp->udp_mtx);
	if (nni_aio_start(aio, nni_plat_udp_cancel, udp) != 0) {
		nni_mtx_unlock(&udp->udp_mtx);
		return;
	}

	if (udp->udp_closed) {
		nni_aio_finish(aio, NNG_ECLOSED, 0);
		nni_mtx_unlock(&udp->udp_mtx);
		return;
	}

	nni_list_append(&udp->udp_sendq, aio);
	nni_posix_pollq_arm(&udp->udp_pitem, POLLIN);
	nni_mtx_unlock(&udp->udp_mtx);
}

#else

// Suppress empty symbols warnings in ranlib.
int nni_posix_udp_not_used = 0;

#endif // PLATFORM_POSIX_UDP
