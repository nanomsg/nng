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

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <unistd.h>
#if defined(NNG_HAVE_GETPEERUCRED)
#include <ucred.h>
#elif defined(NNG_HAVE_LOCALPEERCRED) || defined(NNG_HAVE_SOCKPEERCRED)
#include <sys/ucred.h>
#endif

#ifdef NNG_HAVE_ALLOCA
#include <alloca.h>
#endif

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

#include "posix_ipc.h"

static void
ipc_conn_dowrite(nni_ipc_conn *c)
{
	nni_aio *aio;
	int      fd;

	if (c->closed || ((fd = nni_posix_pfd_fd(c->pfd)) < 0)) {
		return;
	}

	while ((aio = nni_list_first(&c->writeq)) != NULL) {
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
			nni_aio_list_remove(aio);
			nni_aio_finish_error(aio, NNG_EINVAL);
			continue;
		}
		iovec = alloca(naiov * sizeof(*iovec));
#else
		if (naiov > NNI_NUM_ELEMENTS(iovec)) {
			nni_aio_list_remove(aio);
			nni_aio_finish_error(aio, NNG_EINVAL);
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
				nni_aio_list_remove(aio);
				nni_aio_finish_error(
				    aio, nni_plat_errno(errno));
				return;
			}
		}

		nni_aio_bump_count(aio, n);
		// We completed the entire operation on this aio.
		// (Sendmsg never returns a partial result.)
		nni_aio_list_remove(aio);
		nni_aio_finish(aio, 0, nni_aio_count(aio));

		// Go back to start of loop to see if there is another
		// aio ready for us to process.
	}
}

static void
ipc_conn_doread(nni_ipc_conn *c)
{
	nni_aio *aio;
	int      fd;

	if (c->closed || ((fd = nni_posix_pfd_fd(c->pfd)) < 0)) {
		return;
	}

	while ((aio = nni_list_first(&c->readq)) != NULL) {
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
			nni_aio_list_remove(aio);
			nni_aio_finish_error(aio, NNG_EINVAL);
			continue;
		}
		iovec = alloca(naiov * sizeof(*iovec));
#else
		if (naiov > NNI_NUM_ELEMENTS(iovec)) {
			nni_aio_list_remove(aio);
			nni_aio_finish_error(aio, NNG_EINVAL);
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
				nni_aio_list_remove(aio);
				nni_aio_finish_error(
				    aio, nni_plat_errno(errno));
				return;
			}
		}

		if (n == 0) {
			// No bytes indicates a closed descriptor.
			// This implicitly completes this (all!) aio.
			nni_aio_list_remove(aio);
			nni_aio_finish_error(aio, NNG_ECLOSED);
			continue;
		}

		nni_aio_bump_count(aio, n);

		// We completed the entire operation on this aio.
		nni_aio_list_remove(aio);
		nni_aio_finish(aio, 0, nni_aio_count(aio));

		// Go back to start of loop to see if there is another
		// aio ready for us to process.
	}
}

void
nni_ipc_conn_close(nni_ipc_conn *c)
{
	nni_mtx_lock(&c->mtx);
	if (!c->closed) {
		nni_aio *aio;
		c->closed = true;
		while (((aio = nni_list_first(&c->readq)) != NULL) ||
		    ((aio = nni_list_first(&c->writeq)) != NULL)) {
			nni_aio_list_remove(aio);
			nni_aio_finish_error(aio, NNG_ECLOSED);
		}
		nni_posix_pfd_close(c->pfd);
	}
	nni_mtx_unlock(&c->mtx);
}

static void
ipc_conn_cb(nni_posix_pfd *pfd, int events, void *arg)
{
	nni_ipc_conn *c = arg;

	if (events & (POLLHUP | POLLERR | POLLNVAL)) {
		nni_ipc_conn_close(c);
		return;
	}
	nni_mtx_lock(&c->mtx);
	if (events & POLLIN) {
		ipc_conn_doread(c);
	}
	if (events & POLLOUT) {
		ipc_conn_dowrite(c);
	}
	events = 0;
	if (!nni_list_empty(&c->writeq)) {
		events |= POLLOUT;
	}
	if (!nni_list_empty(&c->readq)) {
		events |= POLLIN;
	}
	if ((!c->closed) && (events != 0)) {
		nni_posix_pfd_arm(pfd, events);
	}
	nni_mtx_unlock(&c->mtx);
}

static void
ipc_conn_cancel(nni_aio *aio, void *arg, int rv)
{
	nni_ipc_conn *c = arg;

	nni_mtx_lock(&c->mtx);
	if (nni_aio_list_active(aio)) {
		nni_aio_list_remove(aio);
		nni_aio_finish_error(aio, rv);
	}
	nni_mtx_unlock(&c->mtx);
}

void
nni_ipc_conn_send(nni_ipc_conn *c, nni_aio *aio)
{

	int rv;

	if (nni_aio_begin(aio) != 0) {
		return;
	}
	nni_mtx_lock(&c->mtx);

	if ((rv = nni_aio_schedule(aio, ipc_conn_cancel, c)) != 0) {
		nni_mtx_unlock(&c->mtx);
		nni_aio_finish_error(aio, rv);
		return;
	}
	nni_aio_list_append(&c->writeq, aio);

	if (nni_list_first(&c->writeq) == aio) {
		ipc_conn_dowrite(c);
		// If we are still the first thing on the list, that
		// means we didn't finish the job, so arm the poller to
		// complete us.
		if (nni_list_first(&c->writeq) == aio) {
			nni_posix_pfd_arm(c->pfd, POLLOUT);
		}
	}
	nni_mtx_unlock(&c->mtx);
}

void
nni_ipc_conn_recv(nni_ipc_conn *c, nni_aio *aio)
{
	int rv;

	if (nni_aio_begin(aio) != 0) {
		return;
	}
	nni_mtx_lock(&c->mtx);

	if ((rv = nni_aio_schedule(aio, ipc_conn_cancel, c)) != 0) {
		nni_mtx_unlock(&c->mtx);
		nni_aio_finish_error(aio, rv);
		return;
	}
	nni_aio_list_append(&c->readq, aio);

	// If we are only job on the list, go ahead and try to do an
	// immediate transfer. This allows for faster completions in
	// many cases.  We also need not arm a list if it was already
	// armed.
	if (nni_list_first(&c->readq) == aio) {
		ipc_conn_doread(c);
		// If we are still the first thing on the list, that
		// means we didn't finish the job, so arm the poller to
		// complete us.
		if (nni_list_first(&c->readq) == aio) {
			nni_posix_pfd_arm(c->pfd, POLLIN);
		}
	}
	nni_mtx_unlock(&c->mtx);
}

int
ipc_conn_peerid(nni_ipc_conn *c, uint64_t *euid, uint64_t *egid,
    uint64_t *prid, uint64_t *znid)
{
	int fd = nni_posix_pfd_fd(c->pfd);
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
#elif defined(NNG_HAVE_SOCKPEERCRED)
	struct sockpeercred uc;
	socklen_t           len = sizeof(uc);
	if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &uc, &len) != 0) {
		return (nni_plat_errno(errno));
	}
	*euid = uc.uid;
	*egid = uc.gid;
	*prid = uc.pid;
	*znid = (uint64_t) -1;
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
	*prid = (uint64_t) -1;
	*znid = (uint64_t) -1;
#if defined(LOCAL_PEERPID) // present (undocumented) on macOS
	{
		pid_t pid;
		if (getsockopt(fd, SOL_LOCAL, LOCAL_PEERPID, &pid, &len) ==
		    0) {
			*prid = (uint64_t) pid;
		}
	}
#endif                     // LOCAL_PEERPID
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
nni_ipc_conn_get_peer_uid(nni_ipc_conn *c, uint64_t *uid)
{
	int      rv;
	uint64_t ignore;

	if ((rv = ipc_conn_peerid(c, uid, &ignore, &ignore, &ignore)) != 0) {
		return (rv);
	}
	return (0);
}

int
nni_ipc_conn_get_peer_gid(nni_ipc_conn *c, uint64_t *gid)
{
	int      rv;
	uint64_t ignore;

	if ((rv = ipc_conn_peerid(c, &ignore, gid, &ignore, &ignore)) != 0) {
		return (rv);
	}
	return (0);
}

int
nni_ipc_conn_get_peer_zoneid(nni_ipc_conn *c, uint64_t *zid)
{
	int      rv;
	uint64_t ignore;
	uint64_t id;

	if ((rv = ipc_conn_peerid(c, &ignore, &ignore, &ignore, &id)) != 0) {
		return (rv);
	}
	if (id == (uint64_t) -1) {
		// NB: -1 is not a legal zone id (illumos/Solaris)
		return (NNG_ENOTSUP);
	}
	*zid = id;
	return (0);
}

int
nni_ipc_conn_get_peer_pid(nni_ipc_conn *c, uint64_t *pid)
{
	int      rv;
	uint64_t ignore;
	uint64_t id;

	if ((rv = ipc_conn_peerid(c, &ignore, &ignore, &id, &ignore)) != 0) {
		return (rv);
	}
	if (id == (uint64_t) -1) {
		// NB: -1 is not a legal process id
		return (NNG_ENOTSUP);
	}
	*pid = id;
	return (0);
}

int
nni_posix_ipc_conn_init(nni_ipc_conn **cp, nni_posix_pfd *pfd)
{
	nni_ipc_conn *c;

	if ((c = NNI_ALLOC_STRUCT(c)) == NULL) {
		return (NNG_ENOMEM);
	}

	c->closed = false;
	c->pfd    = pfd;

	nni_mtx_init(&c->mtx);
	nni_aio_list_init(&c->readq);
	nni_aio_list_init(&c->writeq);

	*cp = c;
	return (0);
}

void
nni_posix_ipc_conn_start(nni_ipc_conn *c)
{
	nni_posix_pfd_set_cb(c->pfd, ipc_conn_cb, c);
}

void
nni_ipc_conn_fini(nni_ipc_conn *c)
{
	nni_ipc_conn_close(c);
	nni_posix_pfd_fini(c->pfd);
	nni_mtx_lock(&c->mtx); // not strictly needed, but shut up TSAN
	c->pfd = NULL;
	nni_mtx_unlock(&c->mtx);
	nni_mtx_fini(&c->mtx);

	NNI_FREE_STRUCT(c);
}

#endif // NNG_PLATFORM_POSIX
