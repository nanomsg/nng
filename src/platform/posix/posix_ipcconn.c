//
// Copyright 2023 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
// Copyright 2019 Devolutions <info@devolutions.net>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "core/nng_impl.h"
#include "platform/posix/posix_peerid.h"
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdbool.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/un.h>

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

#include "posix_ipc.h"

typedef struct nni_ipc_conn ipc_conn;

static void
ipc_dowrite(ipc_conn *c)
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
		nni_iov      *aiov;
		struct msghdr hdr;
		struct iovec  iovec[16];

		memset(&hdr, 0, sizeof(hdr));
		nni_aio_get_iov(aio, &naiov, &aiov);

		if (naiov > NNI_NUM_ELEMENTS(iovec)) {
			nni_aio_list_remove(aio);
			nni_aio_finish_error(aio, NNG_EINVAL);
			continue;
		}

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
ipc_doread(ipc_conn *c)
{
	nni_aio *aio;
	int      fd;

	if (c->closed || ((fd = nni_posix_pfd_fd(c->pfd)) < 0)) {
		return;
	}

	while ((aio = nni_list_first(&c->readq)) != NULL) {
		unsigned     i;
		int          n;
		int          niov;
		unsigned     naiov;
		nni_iov     *aiov;
		struct iovec iovec[16];

		nni_aio_get_iov(aio, &naiov, &aiov);
		if (naiov > NNI_NUM_ELEMENTS(iovec)) {
			nni_aio_list_remove(aio);
			nni_aio_finish_error(aio, NNG_EINVAL);
			continue;
		}
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
			// Zero indicates a closed descriptor.
			// This implicitly completes this (all!) aio.
			nni_aio_list_remove(aio);
			nni_aio_finish_error(aio, NNG_ECONNSHUT);
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

static void
ipc_error(void *arg, int err)
{
	ipc_conn *c = arg;
	nni_aio  *aio;

	nni_mtx_lock(&c->mtx);
	while (((aio = nni_list_first(&c->readq)) != NULL) ||
	    ((aio = nni_list_first(&c->writeq)) != NULL)) {
		nni_aio_list_remove(aio);
		nni_aio_finish_error(aio, err);
	}
	nni_posix_pfd_close(c->pfd);
	nni_mtx_unlock(&c->mtx);
}

static void
ipc_close(void *arg)
{
	ipc_conn *c = arg;
	nni_mtx_lock(&c->mtx);
	if (!c->closed) {
		nni_aio *aio;
		c->closed = true;
		while (((aio = nni_list_first(&c->readq)) != NULL) ||
		    ((aio = nni_list_first(&c->writeq)) != NULL)) {
			nni_aio_list_remove(aio);
			nni_aio_finish_error(aio, NNG_ECLOSED);
		}
		if (c->pfd != NULL) {
			nni_posix_pfd_close(c->pfd);
		}
	}
	nni_mtx_unlock(&c->mtx);
}

static void
ipc_cb(nni_posix_pfd *pfd, unsigned events, void *arg)
{
	ipc_conn *c = arg;

	if (events & (NNI_POLL_HUP | NNI_POLL_ERR | NNI_POLL_INVAL)) {
		ipc_error(c, NNG_ECONNSHUT);
		return;
	}
	nni_mtx_lock(&c->mtx);
	if ((events & NNI_POLL_IN) != 0) {
		ipc_doread(c);
	}
	if ((events & NNI_POLL_OUT) != 0) {
		ipc_dowrite(c);
	}
	events = 0;
	if (!nni_list_empty(&c->writeq)) {
		events |= NNI_POLL_OUT;
	}
	if (!nni_list_empty(&c->readq)) {
		events |= NNI_POLL_IN;
	}
	if ((!c->closed) && (events != 0)) {
		nni_posix_pfd_arm(pfd, events);
	}
	nni_mtx_unlock(&c->mtx);
}

static void
ipc_cancel(nni_aio *aio, void *arg, int rv)
{
	ipc_conn *c = arg;

	nni_mtx_lock(&c->mtx);
	if (nni_aio_list_active(aio)) {
		nni_aio_list_remove(aio);
		nni_aio_finish_error(aio, rv);
	}
	nni_mtx_unlock(&c->mtx);
}

static void
ipc_send(void *arg, nni_aio *aio)
{
	ipc_conn *c = arg;
	int       rv;

	if (nni_aio_begin(aio) != 0) {
		return;
	}
	nni_mtx_lock(&c->mtx);

	if ((rv = nni_aio_schedule(aio, ipc_cancel, c)) != 0) {
		nni_mtx_unlock(&c->mtx);
		nni_aio_finish_error(aio, rv);
		return;
	}
	nni_aio_list_append(&c->writeq, aio);

	if (nni_list_first(&c->writeq) == aio) {
		ipc_dowrite(c);
		// If we are still the first thing on the list, that
		// means we didn't finish the job, so arm the poller to
		// complete us.
		if (nni_list_first(&c->writeq) == aio) {
			nni_posix_pfd_arm(c->pfd, POLLOUT);
		}
	}
	nni_mtx_unlock(&c->mtx);
}

static void
ipc_recv(void *arg, nni_aio *aio)
{
	ipc_conn *c = arg;
	int       rv;

	if (nni_aio_begin(aio) != 0) {
		return;
	}
	nni_mtx_lock(&c->mtx);

	if ((rv = nni_aio_schedule(aio, ipc_cancel, c)) != 0) {
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
		ipc_doread(c);
		// If we are still the first thing on the list, that
		// means we didn't finish the job, so arm the poller to
		// complete us.
		if (nni_list_first(&c->readq) == aio) {
			nni_posix_pfd_arm(c->pfd, POLLIN);
		}
	}
	nni_mtx_unlock(&c->mtx);
}

static int
ipc_get_peer_uid(void *arg, void *buf, size_t *szp, nni_type t)
{
	ipc_conn *c = arg;
	int       rv;
	uint64_t  ignore;
	uint64_t  id = 0;

	if ((rv = nni_posix_peerid(nni_posix_pfd_fd(c->pfd), &id, &ignore,
	         &ignore, &ignore)) != 0) {
		return (rv);
	}
	return (nni_copyout_u64(id, buf, szp, t));
}

static int
ipc_get_peer_gid(void *arg, void *buf, size_t *szp, nni_type t)
{
	ipc_conn *c = arg;
	int       rv;
	uint64_t  ignore;
	uint64_t  id = 0;

	if ((rv = nni_posix_peerid(nni_posix_pfd_fd(c->pfd), &ignore, &id,
	         &ignore, &ignore)) != 0) {
		return (rv);
	}
	return (nni_copyout_u64(id, buf, szp, t));
}

static int
ipc_get_peer_zoneid(void *arg, void *buf, size_t *szp, nni_type t)
{
	ipc_conn *c = arg;
	int       rv;
	uint64_t  ignore;
	uint64_t  id = 0;

	if ((rv = nni_posix_peerid(nni_posix_pfd_fd(c->pfd), &ignore, &ignore,
	         &ignore, &id)) != 0) {
		return (rv);
	}
	if (id == (uint64_t) -1) {
		// NB: -1 is not a legal zone id (illumos/Solaris)
		return (NNG_ENOTSUP);
	}
	return (nni_copyout_u64(id, buf, szp, t));
}

static int
ipc_get_peer_pid(void *arg, void *buf, size_t *szp, nni_type t)
{
	ipc_conn *c = arg;
	int       rv;
	uint64_t  ignore;
	uint64_t  id = 0;

	if ((rv = nni_posix_peerid(nni_posix_pfd_fd(c->pfd), &ignore, &ignore,
	         &id, &ignore)) != 0) {
		return (rv);
	}
	if (id == (uint64_t) -1) {
		// NB: -1 is not a legal process id
		return (NNG_ENOTSUP);
	}
	return (nni_copyout_u64(id, buf, szp, t));
}

static int
ipc_get_addr(void *arg, void *buf, size_t *szp, nni_type t)
{
	ipc_conn *c = arg;
	return (nni_copyout_sockaddr(&c->sa, buf, szp, t));
}

void
nni_posix_ipc_start(nni_ipc_conn *c)
{
	nni_posix_pfd_set_cb(c->pfd, ipc_cb, c);
}

static void
ipc_reap(void *arg)
{
	ipc_conn *c = arg;
	ipc_close(c);
	if (c->pfd != NULL) {
		nni_posix_pfd_fini(c->pfd);
	}
	nni_mtx_fini(&c->mtx);

	if (c->dialer != NULL) {
		nni_posix_ipc_dialer_rele(c->dialer);
	}

	NNI_FREE_STRUCT(c);
}

static nni_reap_list ipc_reap_list = {
	.rl_offset = offsetof(ipc_conn, reap),
	.rl_func   = ipc_reap,
};
static void
ipc_free(void *arg)
{
	ipc_conn *c = arg;
	nni_reap(&ipc_reap_list, c);
}

static const nni_option ipc_options[] = {
	{
	    .o_name = NNG_OPT_LOCADDR,
	    .o_get  = ipc_get_addr,
	},
	{
	    .o_name = NNG_OPT_REMADDR,
	    .o_get  = ipc_get_addr,
	},
	{
	    .o_name = NNG_OPT_IPC_PEER_PID,
	    .o_get  = ipc_get_peer_pid,
	},
	{
	    .o_name = NNG_OPT_IPC_PEER_UID,
	    .o_get  = ipc_get_peer_uid,
	},
	{
	    .o_name = NNG_OPT_IPC_PEER_GID,
	    .o_get  = ipc_get_peer_gid,
	},
	{
	    .o_name = NNG_OPT_IPC_PEER_ZONEID,
	    .o_get  = ipc_get_peer_zoneid,
	},
	{
	    .o_name = NULL,
	},
};

static int
ipc_get(void *arg, const char *name, void *val, size_t *szp, nni_type t)
{
	ipc_conn *c = arg;
	return (nni_getopt(ipc_options, name, c, val, szp, t));
}

static int
ipc_set(void *arg, const char *name, const void *val, size_t sz, nni_type t)
{
	ipc_conn *c = arg;
	return (nni_setopt(ipc_options, name, c, val, sz, t));
}

int
nni_posix_ipc_alloc(nni_ipc_conn **cp, nni_sockaddr *sa, nni_ipc_dialer *d)
{
	ipc_conn *c;

	if ((c = NNI_ALLOC_STRUCT(c)) == NULL) {
		return (NNG_ENOMEM);
	}

	c->closed         = false;
	c->dialer         = d;
	c->stream.s_free  = ipc_free;
	c->stream.s_close = ipc_close;
	c->stream.s_send  = ipc_send;
	c->stream.s_recv  = ipc_recv;
	c->stream.s_get   = ipc_get;
	c->stream.s_set   = ipc_set;
	c->sa             = *sa;

	nni_mtx_init(&c->mtx);
	nni_aio_list_init(&c->readq);
	nni_aio_list_init(&c->writeq);

	*cp = c;
	return (0);
}

void
nni_posix_ipc_init(nni_ipc_conn *c, nni_posix_pfd *pfd)
{
	c->pfd = pfd;
}
