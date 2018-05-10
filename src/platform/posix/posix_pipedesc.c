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
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#if defined(NNG_HAVE_GETPEERUCRED)
#include <ucred.h>
#elif defined(NNG_HAVE_LOCALPEERCRED)
#include <sys/ucred.h>
#include <sys/un.h>
#endif
#ifdef NNG_HAVE_ALLOCA
#include <alloca.h>
#endif

// nni_posix_pipedesc is a descriptor kept one per transport pipe (i.e. open
// file descriptor for TCP socket, etc.)  This contains the list of pending
// aios for that underlying socket, as well as the socket itself.
struct nni_posix_pipedesc {
	nni_posix_pfd *pfd;
	nni_list       readq;
	nni_list       writeq;
	bool           closed;
	nni_mtx        mtx;
};

static void
nni_posix_pipedesc_finish(nni_aio *aio, int rv)
{
	nni_aio_list_remove(aio);
	nni_aio_finish(aio, rv, nni_aio_count(aio));
}

static void
nni_posix_pipedesc_doclose(nni_posix_pipedesc *pd)
{
	nni_aio *aio;

	pd->closed = true;
	while ((aio = nni_list_first(&pd->readq)) != NULL) {
		nni_posix_pipedesc_finish(aio, NNG_ECLOSED);
	}
	while ((aio = nni_list_first(&pd->writeq)) != NULL) {
		nni_posix_pipedesc_finish(aio, NNG_ECLOSED);
	}
	nni_posix_pfd_close(pd->pfd);
}

static void
nni_posix_pipedesc_dowrite(nni_posix_pipedesc *pd)
{
	nni_aio *aio;
	int      fd;

	fd = nni_posix_pfd_fd(pd->pfd);
	if ((fd < 0) || (pd->closed)) {
		return;
	}

	while ((aio = nni_list_first(&pd->writeq)) != NULL) {
		unsigned      i;
		int           n;
		int           niov;
		unsigned      naiov;
		nni_iov *     aiov;
		struct msghdr hdr;
#ifdef NNG_HAVE_ALLOCA
		struct iovec *iovec;
#else
		struct iovec iovec[16];
#endif

		memset(&hdr, 0, sizeof(hdr));

		nni_aio_get_iov(aio, &naiov, &aiov);

#ifdef NNG_HAVE_ALLOCA
		if (naiov > 64) {
			nni_posix_pipedesc_finish(aio, NNG_EINVAL);
			continue;
		}
		iovec = alloca(naiov * sizeof(*iovec));
#else
		if (naiov > NNI_NUM_ELEMENTS(iovec)) {
			nni_posix_pipedesc_finish(aio, NNG_EINVAL);
			continue;
		}
#endif

		for (niov = 0, i = 0; i < naiov; i++) {
			if (aiov[i].iov_len > 0) {
				iovec[niov].iov_len  = aiov[i].iov_len;
				iovec[niov].iov_base = aiov[i].iov_buf;
				niov++;
			}
		}

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

		hdr.msg_iovlen = niov;
		hdr.msg_iov    = iovec;

		if ((n = sendmsg(fd, &hdr, MSG_NOSIGNAL)) < 0) {
			switch (errno) {
			case EINTR:
				continue;
			case EAGAIN:
#ifdef EWOULDBLOCK
#if EWOULDBLOCK != EAGAIN
			case EWOULDBLOCK:
#endif
#endif
				return;
			default:
				nni_posix_pipedesc_finish(
				    aio, nni_plat_errno(errno));
				nni_posix_pipedesc_doclose(pd);
				return;
			}
		}

		nni_aio_bump_count(aio, n);
		// We completed the entire operation on this aioq.
		// (Sendmsg never returns a partial result.)
		nni_posix_pipedesc_finish(aio, 0);

		// Go back to start of loop to see if there is another
		// aio ready for us to process.
	}
}

static void
nni_posix_pipedesc_doread(nni_posix_pipedesc *pd)
{
	nni_aio *aio;
	int      fd;

	fd = nni_posix_pfd_fd(pd->pfd);
	if ((fd < 0) || (pd->closed)) {
		return;
	}

	while ((aio = nni_list_first(&pd->readq)) != NULL) {
		unsigned i;
		int      n;
		int      niov;
		unsigned naiov;
		nni_iov *aiov;
#ifdef NNG_HAVE_ALLOCA
		struct iovec *iovec;
#else
		struct iovec iovec[16];
#endif

		nni_aio_get_iov(aio, &naiov, &aiov);
#ifdef NNG_HAVE_ALLOCA
		if (naiov > 64) {
			nni_posix_pipedesc_finish(aio, NNG_EINVAL);
			continue;
		}
		iovec = alloca(naiov * sizeof(*iovec));
#else
		if (naiov > NNI_NUM_ELEMENTS(iovec)) {
			nni_posix_pipedesc_finish(aio, NNG_EINVAL);
			continue;
		}
#endif
		for (niov = 0, i = 0; i < naiov; i++) {
			if (aiov[i].iov_len != 0) {
				iovec[niov].iov_len  = aiov[i].iov_len;
				iovec[niov].iov_base = aiov[i].iov_buf;
				niov++;
			}
		}

		if ((n = readv(fd, iovec, niov)) < 0) {
			switch (errno) {
			case EINTR:
				continue;
			case EAGAIN:
				return;
			default:
				nni_posix_pipedesc_finish(
				    aio, nni_plat_errno(errno));
				nni_posix_pipedesc_doclose(pd);
				return;
			}
		}

		if (n == 0) {
			// No bytes indicates a closed descriptor.
			nni_posix_pipedesc_finish(aio, NNG_ECLOSED);
			nni_posix_pipedesc_doclose(pd);
			return;
		}

		nni_aio_bump_count(aio, n);

		// We completed the entire operation on this aioq.
		nni_posix_pipedesc_finish(aio, 0);

		// Go back to start of loop to see if there is another
		// aio ready for us to process.
	}
}

static void
nni_posix_pipedesc_cb(nni_posix_pfd *pfd, int events, void *arg)
{
	nni_posix_pipedesc *pd = arg;

	nni_mtx_lock(&pd->mtx);
	if (events & POLLIN) {
		nni_posix_pipedesc_doread(pd);
	}
	if (events & POLLOUT) {
		nni_posix_pipedesc_dowrite(pd);
	}
	if (events & (POLLHUP | POLLERR | POLLNVAL)) {
		nni_posix_pipedesc_doclose(pd);
	} else {
		events = 0;
		if (!nni_list_empty(&pd->writeq)) {
			events |= POLLOUT;
		}
		if (!nni_list_empty(&pd->readq)) {
			events |= POLLIN;
		}
		if ((!pd->closed) && (events != 0)) {
			nni_posix_pfd_arm(pfd, events);
		}
	}
	nni_mtx_unlock(&pd->mtx);
}

void
nni_posix_pipedesc_close(nni_posix_pipedesc *pd)
{
	// NB: Events may still occur.
	nni_mtx_lock(&pd->mtx);
	nni_posix_pipedesc_doclose(pd);
	nni_mtx_unlock(&pd->mtx);
}

static void
nni_posix_pipedesc_cancel(nni_aio *aio, int rv)
{
	nni_posix_pipedesc *pd = nni_aio_get_prov_data(aio);

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

	if (nni_aio_begin(aio) != 0) {
		return;
	}
	nni_mtx_lock(&pd->mtx);

	if (pd->closed) {
		nni_mtx_unlock(&pd->mtx);
		nni_aio_finish_error(aio, NNG_ECLOSED);
		return;
	}

	if ((rv = nni_aio_schedule(aio, nni_posix_pipedesc_cancel, pd)) != 0) {
		nni_mtx_unlock(&pd->mtx);
		nni_aio_finish_error(aio, rv);
		return;
	}
	nni_aio_list_append(&pd->readq, aio);

	// If we are only job on the list, go ahead and try to do an
	// immediate transfer. This allows for faster completions in
	// many cases.  We also need not arm a list if it was already
	// armed.
	if (nni_list_first(&pd->readq) == aio) {
		nni_posix_pipedesc_doread(pd);
		// If we are still the first thing on the list, that
		// means we didn't finish the job, so arm the poller to
		// complete us.
		if (nni_list_first(&pd->readq) == aio) {
			nni_posix_pfd_arm(pd->pfd, POLLIN);
		}
	}
	nni_mtx_unlock(&pd->mtx);
}

void
nni_posix_pipedesc_send(nni_posix_pipedesc *pd, nni_aio *aio)
{
	int rv;

	if (nni_aio_begin(aio) != 0) {
		return;
	}
	nni_mtx_lock(&pd->mtx);

	if (pd->closed) {
		nni_mtx_unlock(&pd->mtx);
		nni_aio_finish_error(aio, NNG_ECLOSED);
		return;
	}

	if ((rv = nni_aio_schedule(aio, nni_posix_pipedesc_cancel, pd)) != 0) {
		nni_mtx_unlock(&pd->mtx);
		nni_aio_finish_error(aio, rv);
		return;
	}
	nni_aio_list_append(&pd->writeq, aio);

	if (nni_list_first(&pd->writeq) == aio) {
		nni_posix_pipedesc_dowrite(pd);
		// If we are still the first thing on the list, that
		// means we didn't finish the job, so arm the poller to
		// complete us.
		if (nni_list_first(&pd->writeq) == aio) {
			nni_posix_pfd_arm(pd->pfd, POLLOUT);
		}
	}
	nni_mtx_unlock(&pd->mtx);
}

int
nni_posix_pipedesc_peername(nni_posix_pipedesc *pd, nni_sockaddr *sa)
{
	struct sockaddr_storage ss;
	socklen_t               sslen = sizeof(ss);
	int                     fd    = nni_posix_pfd_fd(pd->pfd);

	if (getpeername(fd, (void *) &ss, &sslen) != 0) {
		return (nni_plat_errno(errno));
	}
	return (nni_posix_sockaddr2nn(sa, &ss));
}

int
nni_posix_pipedesc_sockname(nni_posix_pipedesc *pd, nni_sockaddr *sa)
{
	struct sockaddr_storage ss;
	socklen_t               sslen = sizeof(ss);
	int                     fd    = nni_posix_pfd_fd(pd->pfd);

	if (getsockname(fd, (void *) &ss, &sslen) != 0) {
		return (nni_plat_errno(errno));
	}
	return (nni_posix_sockaddr2nn(sa, &ss));
}

int
nni_posix_pipedesc_set_nodelay(nni_posix_pipedesc *pd, bool nodelay)
{
	int val = nodelay ? 1 : 0;
	int fd  = nni_posix_pfd_fd(pd->pfd);

	if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &val, sizeof(val)) != 0) {
		return (nni_plat_errno(errno));
	}
	return (0);
}

int
nni_posix_pipedesc_set_keepalive(nni_posix_pipedesc *pd, bool keep)
{
	int val = keep ? 1 : 0;
	int fd  = nni_posix_pfd_fd(pd->pfd);

	if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &val, sizeof(val)) != 0) {
		return (nni_plat_errno(errno));
	}
	return (0);
}

int
nni_posix_pipedesc_get_peerid(nni_posix_pipedesc *pd, uint64_t *euid,
    uint64_t *egid, uint64_t *prid, uint64_t *znid)
{
	int fd = nni_posix_pfd_fd(pd->pfd);
#if defined(NNG_HAVE_GETPEEREID)
	uid_t uid;
	gid_t gid;

	if (getpeereid(fd, &uid, &gid) != 0) {
		return (nni_plat_errno(errno));
	}
	*euid = uid;
	*egid = gid;
	*prid = (uint64_t) -1;
	*znid = (uint64_t) -1;
	return (0);
#elif defined(NNG_HAVE_GETPEERUCRED)
	ucred_t *ucp = NULL;
	if (getpeerucred(fd, &ucp) != 0) {
		return (nni_plat_errno(errno));
	}
	*euid = ucred_geteuid(ucp);
	*egid = ucred_getegid(ucp);
	*prid = ucred_getpid(ucp);
	*znid = ucred_getzoneid(ucp);
	ucred_free(ucp);
	return (0);
#elif defined(NNG_HAVE_SOPEERCRED)
	struct ucred uc;
	socklen_t    len = sizeof(uc);
	if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &uc, &len) != 0) {
		return (nni_plat_errno(errno));
	}
	*euid = uc.uid;
	*egid = uc.gid;
	*prid = uc.pid;
	*znid = (uint64_t) -1;
	return (0);
#elif defined(NNG_HAVE_LOCALPEERCRED)
	struct xucred xu;
	socklen_t     len = sizeof(xu);
	if (getsockopt(fd, SOL_LOCAL, LOCAL_PEERCRED, &xu, &len) != 0) {
		return (nni_plat_errno(errno));
	}
	*euid = xu.cr_uid;
	*egid = xu.cr_gid;
	*prid = (uint64_t) -1; // XXX: macOS has undocumented
	                       // LOCAL_PEERPID...
	*znid = (uint64_t) -1;
	return (0);
#else
	if (fd < 0) {
		return (NNG_ECLOSED);
	}
	NNI_ARG_UNUSED(euid);
	NNI_ARG_UNUSED(egid);
	NNI_ARG_UNUSED(prid);
	NNI_ARG_UNUSED(znid);
	return (NNG_ENOTSUP);
#endif
}

int
nni_posix_pipedesc_init(nni_posix_pipedesc **pdp, nni_posix_pfd *pfd)
{
	nni_posix_pipedesc *pd;

	if ((pd = NNI_ALLOC_STRUCT(pd)) == NULL) {
		return (NNG_ENOMEM);
	}

	pd->closed = false;
	pd->pfd    = pfd;

	nni_mtx_init(&pd->mtx);
	nni_aio_list_init(&pd->readq);
	nni_aio_list_init(&pd->writeq);

	nni_posix_pfd_set_cb(pfd, nni_posix_pipedesc_cb, pd);

	*pdp = pd;
	return (0);
}

void
nni_posix_pipedesc_fini(nni_posix_pipedesc *pd)
{
	nni_posix_pipedesc_close(pd);
	nni_posix_pfd_fini(pd->pfd);
	pd->pfd = NULL;
	nni_mtx_fini(&pd->mtx);

	NNI_FREE_STRUCT(pd);
}

#endif // NNG_PLATFORM_POSIX
