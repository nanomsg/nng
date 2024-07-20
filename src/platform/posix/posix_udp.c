//
// Copyright 2024 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "core/nng_impl.h"
#include "platform/posix/posix_impl.h"
#include <nng/nng.h>
#include <sys/errno.h>

#ifdef NNG_PLATFORM_POSIX
#include "platform/posix/posix_pollq.h"

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

// UDP support.

// If we can suppress SIGPIPE on send, please do so.
#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

#ifndef NNG_HAVE_INET6
#undef NNG_ENABLE_IPV6
#endif

// Linux has IPV6_ADD_MEMBERSHIP and IPV6_DROP_MEMBERSHIP
#ifndef IPV6_JOIN_GROUP
#ifdef IPV6_ADD_MEMBERSHIP
#define IPV6_JOIN_GROUP IPV6_ADD_MEMBERSHIP
#endif
#endif
#ifndef IPV6_LEAVE_GROUP
#ifdef IPV6_DROP_MEMBERSHIP
#define IPV6_LEAVE_GROUP IPV6_DROP_MEMBERSHIP
#endif
#endif

struct nni_plat_udp {
	nni_posix_pfd *udp_pfd;
	int            udp_fd;
	nni_list       udp_recvq;
	nni_list       udp_sendq;
	nni_mtx        udp_mtx;
};

static void
nni_posix_udp_doerror(nni_plat_udp *udp, int rv)
{
	nni_aio *aio;

	while (((aio = nni_list_first(&udp->udp_recvq)) != NULL) ||
	    ((aio = nni_list_first(&udp->udp_sendq)) != NULL)) {
		nni_aio_list_remove(aio);
		nni_aio_finish_error(aio, rv);
	}
}

static void
nni_posix_udp_doclose(nni_plat_udp *udp)
{
	nni_posix_udp_doerror(udp, NNG_ECLOSED);
}

static void
nni_posix_udp_dorecv(nni_plat_udp *udp)
{
	nni_aio  *aio;
	nni_list *q = &udp->udp_recvq;
	// While we're able to recv, do so.
	while ((aio = nni_list_first(q)) != NULL) {
		struct iovec            iov[4];
		unsigned                niov;
		nni_iov                *aiov;
		struct sockaddr_storage ss;
		nng_sockaddr           *sa;
		struct msghdr           hdr = { .msg_name = NULL };
		int                     rv  = 0;
		int                     cnt = 0;

		nni_aio_get_iov(aio, &niov, &aiov);

		for (unsigned i = 0; i < niov; i++) {
			iov[i].iov_base = aiov[i].iov_buf;
			iov[i].iov_len  = aiov[i].iov_len;
		}
		hdr.msg_iov     = iov;
		hdr.msg_iovlen  = niov;
		hdr.msg_name    = &ss;
		hdr.msg_namelen = sizeof(ss);

		if ((cnt = recvmsg(udp->udp_fd, &hdr, 0)) < 0) {
			if ((errno == EAGAIN) || (errno == EWOULDBLOCK)) {
				// No data available at socket.  Leave
				// the AIO at the head of the queue.
				return;
			}
			rv = nni_plat_errno(errno);
		} else if ((sa = nni_aio_get_input(aio, 0)) != NULL) {
			// We need to store the address information.
			// It is incumbent on the AIO submitter to supply
			// storage for the address.
			nni_posix_sockaddr2nn(
			    sa, (void *) &ss, hdr.msg_namelen);
		}
		nni_list_remove(q, aio);
		nni_aio_finish(aio, rv, cnt);
	}
}

static void
nni_posix_udp_dosend(nni_plat_udp *udp)
{
	nni_aio  *aio;
	nni_list *q = &udp->udp_sendq;

	// While we're able to send, do so.
	while ((aio = nni_list_first(q)) != NULL) {
		struct sockaddr_storage ss;

		int len;
		int rv  = 0;
		int cnt = 0;

		len = nni_posix_nn2sockaddr(&ss, nni_aio_get_input(aio, 0));
		if (len < 1) {
			rv = NNG_EADDRINVAL;
		} else {
			unsigned     niov;
			nni_iov     *aiov;
			struct iovec iov[16];

			nni_aio_get_iov(aio, &niov, &aiov);
			if (niov > NNI_NUM_ELEMENTS(iov)) {
				rv = NNG_EINVAL;
			}
			if (rv == 0) {
				struct msghdr hdr = { .msg_name = NULL };
				for (unsigned i = 0; i < niov; i++) {
					iov[i].iov_base = aiov[i].iov_buf;
					iov[i].iov_len  = aiov[i].iov_len;
				}
				hdr.msg_iov     = iov;
				hdr.msg_iovlen  = niov;
				hdr.msg_name    = &ss;
				hdr.msg_namelen = len;

				cnt = sendmsg(udp->udp_fd, &hdr, MSG_NOSIGNAL);
				if (cnt < 0) {
					if ((errno == EAGAIN) ||
					    (errno == EWOULDBLOCK)) {
						// Cannot send now, leave.
						return;
					}
					rv = nni_plat_errno(errno);
				}
			}
		}

		nni_list_remove(q, aio);
		nni_aio_finish(aio, rv, cnt);
	}
}

// This function is called by the poller on activity on the FD.
static void
nni_posix_udp_cb(nni_posix_pfd *pfd, unsigned events, void *arg)
{
	nni_plat_udp *udp = arg;
	NNI_ARG_UNUSED(pfd);

	nni_mtx_lock(&udp->udp_mtx);
	if (events & (unsigned) POLLIN) {
		nni_posix_udp_dorecv(udp);
	}
	if (events & (unsigned) POLLOUT) {
		nni_posix_udp_dosend(udp);
	}
	if (events &
	    ((unsigned) POLLHUP | (unsigned) POLLERR | (unsigned) POLLNVAL)) {
		nni_posix_udp_doclose(udp);
	} else {
		events = 0;
		if (!nni_list_empty(&udp->udp_sendq)) {
			events |= (unsigned) POLLOUT;
		}
		if (!nni_list_empty(&udp->udp_recvq)) {
			events |= (unsigned) POLLIN;
		}
		if (events) {
			int rv;
			rv = nni_posix_pfd_arm(udp->udp_pfd, events);
			if (rv != 0) {
				nni_posix_udp_doerror(udp, rv);
			}
		}
	}
	nni_mtx_unlock(&udp->udp_mtx);
}

int
nni_plat_udp_open(nni_plat_udp **upp, nni_sockaddr *bindaddr)
{
	nni_plat_udp           *udp;
	int                     salen;
	struct sockaddr_storage sa;
	int                     rv;

	if ((salen = nni_posix_nn2sockaddr(&sa, bindaddr)) < 1) {
		return (NNG_EADDRINVAL);
	}

	// UDP opens can actually run synchronously.
	if ((udp = NNI_ALLOC_STRUCT(udp)) == NULL) {
		return (NNG_ENOMEM);
	}
	nni_mtx_init(&udp->udp_mtx);

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
	if ((rv = nni_posix_pfd_init(&udp->udp_pfd, udp->udp_fd)) != 0) {
		(void) close(udp->udp_fd);
		nni_mtx_fini(&udp->udp_mtx);
		NNI_FREE_STRUCT(udp);
		return (rv);
	}
	nni_posix_pfd_set_cb(udp->udp_pfd, nni_posix_udp_cb, udp);

	nni_aio_list_init(&udp->udp_recvq);
	nni_aio_list_init(&udp->udp_sendq);

	*upp = udp;
	return (0);
}

void
nni_plat_udp_close(nni_plat_udp *udp)
{
	nni_posix_pfd_fini(udp->udp_pfd);

	nni_mtx_lock(&udp->udp_mtx);
	nni_posix_udp_doclose(udp);
	nni_mtx_unlock(&udp->udp_mtx);

	(void) close(udp->udp_fd);
	nni_mtx_fini(&udp->udp_mtx);
	NNI_FREE_STRUCT(udp);
}

void
nni_plat_udp_cancel(nni_aio *aio, void *arg, int rv)
{
	nni_plat_udp *udp = arg;

	nni_mtx_lock(&udp->udp_mtx);
	if (nni_aio_list_active(aio)) {
		nni_aio_list_remove(aio);
		nni_aio_finish_error(aio, rv);
	}
	nni_mtx_unlock(&udp->udp_mtx);
}

void
nni_plat_udp_recv(nni_plat_udp *udp, nni_aio *aio)
{
	int rv;
	if (nni_aio_begin(aio) != 0) {
		return;
	}
	nni_mtx_lock(&udp->udp_mtx);
	if ((rv = nni_aio_schedule(aio, nni_plat_udp_cancel, udp)) != 0) {
		nni_mtx_unlock(&udp->udp_mtx);
		nni_aio_finish_error(aio, rv);
		return;
	}
	nni_list_append(&udp->udp_recvq, aio);
	if (nni_list_first(&udp->udp_recvq) == aio) {
		if ((rv = nni_posix_pfd_arm(udp->udp_pfd, POLLIN)) != 0) {
			nni_aio_list_remove(aio);
			nni_aio_finish_error(aio, rv);
		}
	}
	nni_mtx_unlock(&udp->udp_mtx);
}

void
nni_plat_udp_send(nni_plat_udp *udp, nni_aio *aio)
{
	int rv;
	if (nni_aio_begin(aio) != 0) {
		return;
	}
	nni_mtx_lock(&udp->udp_mtx);
	if ((rv = nni_aio_schedule(aio, nni_plat_udp_cancel, udp)) != 0) {
		nni_mtx_unlock(&udp->udp_mtx);
		nni_aio_finish_error(aio, rv);
		return;
	}
	nni_list_append(&udp->udp_sendq, aio);
	if (nni_list_first(&udp->udp_sendq) == aio) {
		if ((rv = nni_posix_pfd_arm(udp->udp_pfd, POLLOUT)) != 0) {
			nni_aio_list_remove(aio);
			nni_aio_finish_error(aio, rv);
		}
	}
	nni_mtx_unlock(&udp->udp_mtx);
}

int
nni_plat_udp_sockname(nni_plat_udp *udp, nni_sockaddr *sa)
{
	struct sockaddr_storage ss;
	socklen_t               sz;

	sz = sizeof(ss);
	if (getsockname(udp->udp_fd, (struct sockaddr *) &ss, &sz) < 0) {
		return (nni_plat_errno(errno));
	}
	return (nni_posix_sockaddr2nn(sa, &ss, sz));
}

// Joining a multicast group is different than binding to a multicast
// group.  This allows to receive both unicast and multicast at the given
// address.
static int
ip4_multicast_member(nni_plat_udp *udp, struct sockaddr *sa, bool join)
{
	struct ip_mreq          mreq;
	struct sockaddr_in     *sin;
	struct sockaddr_storage local;
	socklen_t               sz = sizeof(local);

	if (getsockname(udp->udp_fd, (struct sockaddr *) &local, &sz) >= 0) {
		if (local.ss_family != AF_INET) {
			// address families have to match
			return (NNG_EADDRINVAL);
		}
		sin                       = (struct sockaddr_in *) &local;
		mreq.imr_interface.s_addr = sin->sin_addr.s_addr;
	} else {
		mreq.imr_interface.s_addr = INADDR_ANY;
	}

	// Determine our local interface
	sin = (struct sockaddr_in *) sa;

	mreq.imr_multiaddr.s_addr = sin->sin_addr.s_addr;
	if (setsockopt(udp->udp_fd, IPPROTO_IP,
	        join ? IP_ADD_MEMBERSHIP : IP_DROP_MEMBERSHIP, &mreq,
	        sizeof(mreq)) == 0) {
		return (0);
	}
	return (nni_plat_errno(errno));
}

#ifdef NNG_ENABLE_IPV6
static int
ip6_multicast_member(nni_plat_udp *udp, struct sockaddr *sa, bool join)
{
	struct ipv6_mreq        mreq;
	struct sockaddr_in6    *sin6;
	struct sockaddr_storage local;
	socklen_t               sz = sizeof(local);

	if (getsockname(udp->udp_fd, (struct sockaddr *) &local, &sz) >= 0) {
		if (local.ss_family != AF_INET6) {
			// address families have to match
			return (NNG_EADDRINVAL);
		}
		sin6                  = (struct sockaddr_in6 *) &local;
		mreq.ipv6mr_interface = sin6->sin6_scope_id;
	} else {
		mreq.ipv6mr_interface = 0;
	}

	// Determine our local interface
	sin6 = (struct sockaddr_in6 *) sa;

	mreq.ipv6mr_multiaddr = sin6->sin6_addr;
	if (setsockopt(udp->udp_fd, IPPROTO_IPV6,
	        join ? IPV6_JOIN_GROUP : IPV6_LEAVE_GROUP, &mreq,
	        sizeof(mreq)) == 0) {
		return (0);
	}
	return (nni_plat_errno(errno));
}
#endif

int
nni_plat_udp_multicast_membership(
    nni_plat_udp *udp, nni_sockaddr *sa, bool join)
{
	struct sockaddr_storage ss;
	socklen_t               sz;
	int                     rv;

	sz = nni_posix_nn2sockaddr(&ss, sa);
	if (sz < 1) {
		return (NNG_EADDRINVAL);
	}
	switch (ss.ss_family) {
	case AF_INET:
		rv = ip4_multicast_member(udp, (struct sockaddr *) &ss, join);
		break;
#ifdef NNG_ENABLE_IPV6
	case AF_INET6:
		rv = ip6_multicast_member(udp, (struct sockaddr *) &ss, join);
		break;
#endif
	default:
		rv = NNG_EADDRINVAL;
	}

	return (rv);
}

#endif // NNG_PLATFORM_POSIX
