//
// Copyright 2020 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
// Copyright 2019 Devolutions <info@devolutions.net>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "core/nng_impl.h"

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <stdbool.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/uio.h>

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

#include "posix_tcp.h"

static void
tcp_dowrite(nni_tcp_conn *c)
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
tcp_doread(nni_tcp_conn *c)
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
		nni_iov *    aiov;
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
			// No bytes indicates a closed descriptor.
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
tcp_error(void *arg, int err)
{
	nni_tcp_conn *c = arg;
	nni_aio *     aio;

	nni_mtx_lock(&c->mtx);
	while (((aio = nni_list_first(&c->readq)) != NULL) ||
	    ((aio = nni_list_first(&c->writeq)) != NULL)) {
		nni_aio_list_remove(aio);
		nni_aio_finish_error(aio, err);
	}
	if (c->pfd != NULL) {
		nni_posix_pfd_close(c->pfd);
	}
	nni_mtx_unlock(&c->mtx);
}

static void
tcp_close(void *arg)
{
	nni_tcp_conn *c = arg;
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

// tcp_fini may block briefly waiting for the pollq thread.
// To get that out of our context, we simply reap this.
static void
tcp_fini(void *arg)
{
	nni_tcp_conn *c = arg;
	tcp_close(c);
	if (c->pfd != NULL) {
		nni_posix_pfd_fini(c->pfd);
	}
	nni_mtx_fini(&c->mtx);

	if (c->dialer != NULL) {
		nni_posix_tcp_dialer_rele(c->dialer);
	}
	NNI_FREE_STRUCT(c);
}

static void
tcp_free(void *arg)
{
	nni_tcp_conn *c = arg;
	nni_reap(&c->reap, tcp_fini, arg);
}

static void
tcp_cb(nni_posix_pfd *pfd, unsigned events, void *arg)
{
	nni_tcp_conn *c = arg;

	if (events & (NNI_POLL_HUP | NNI_POLL_ERR | NNI_POLL_INVAL)) {
		tcp_error(c, NNG_ECONNSHUT);
		return;
	}
	nni_mtx_lock(&c->mtx);
	if ((events & NNI_POLL_IN) != 0) {
		tcp_doread(c);
	}
	if ((events & NNI_POLL_OUT) != 0) {
		tcp_dowrite(c);
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
tcp_cancel(nni_aio *aio, void *arg, int rv)
{
	nni_tcp_conn *c = arg;

	nni_mtx_lock(&c->mtx);
	if (nni_aio_list_active(aio)) {
		nni_aio_list_remove(aio);
		nni_aio_finish_error(aio, rv);
	}
	nni_mtx_unlock(&c->mtx);
}

static void
tcp_send(void *arg, nni_aio *aio)
{
	nni_tcp_conn *c = arg;
	int           rv;

	if (nni_aio_begin(aio) != 0) {
		return;
	}
	nni_mtx_lock(&c->mtx);

	if ((rv = nni_aio_schedule(aio, tcp_cancel, c)) != 0) {
		nni_mtx_unlock(&c->mtx);
		nni_aio_finish_error(aio, rv);
		return;
	}
	nni_aio_list_append(&c->writeq, aio);

	if (nni_list_first(&c->writeq) == aio) {
		tcp_dowrite(c);
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
tcp_recv(void *arg, nni_aio *aio)
{
	nni_tcp_conn *c = arg;
	int           rv;

	if (nni_aio_begin(aio) != 0) {
		return;
	}
	nni_mtx_lock(&c->mtx);

	if ((rv = nni_aio_schedule(aio, tcp_cancel, c)) != 0) {
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
		tcp_doread(c);
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
tcp_get_peername(void *arg, void *buf, size_t *szp, nni_type t)
{
	nni_tcp_conn *          c = arg;
	struct sockaddr_storage ss;
	socklen_t               sslen = sizeof(ss);
	int                     fd    = nni_posix_pfd_fd(c->pfd);
	int                     rv;
	nng_sockaddr            sa;

	if (getpeername(fd, (void *) &ss, &sslen) != 0) {
		return (nni_plat_errno(errno));
	}
	if ((rv = nni_posix_sockaddr2nn(&sa, &ss)) == 0) {
		rv = nni_copyout_sockaddr(&sa, buf, szp, t);
	}
	return (rv);
}

static int
tcp_get_sockname(void *arg, void *buf, size_t *szp, nni_type t)
{
	nni_tcp_conn *          c = arg;
	struct sockaddr_storage ss;
	socklen_t               sslen = sizeof(ss);
	int                     fd    = nni_posix_pfd_fd(c->pfd);
	int                     rv;
	nng_sockaddr            sa;

	if (getsockname(fd, (void *) &ss, &sslen) != 0) {
		return (nni_plat_errno(errno));
	}
	if ((rv = nni_posix_sockaddr2nn(&sa, &ss)) == 0) {
		rv = nni_copyout_sockaddr(&sa, buf, szp, t);
	}
	return (rv);
}

static int
tcp_set_nodelay(void *arg, const void *buf, size_t sz, nni_type t)
{
	nni_tcp_conn *c = arg;
	int           fd;
	bool          b;
	int           val;
	int           rv;

	if (((rv = nni_copyin_bool(&b, buf, sz, t)) != 0) || (c == NULL)) {
		return (rv);
	}
	val = b ? 1 : 0;
	fd  = nni_posix_pfd_fd(c->pfd);
	if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &val, sizeof(val)) != 0) {
		return (nni_plat_errno(errno));
	}
	return (0);
}

static int
tcp_set_keepalive(void *arg, const void *buf, size_t sz, nni_type t)
{
	nni_tcp_conn *c = arg;
	int           fd;
	bool          b;
	int           val;
	int           rv;

	if (((rv = nni_copyin_bool(&b, buf, sz, t)) != 0) || (c == NULL)) {
		return (rv);
	}
	val = b ? 1 : 0;
	fd  = nni_posix_pfd_fd(c->pfd);
	if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &val, sizeof(val)) != 0) {
		return (nni_plat_errno(errno));
	}
	return (0);
}

static int
tcp_get_nodelay(void *arg, void *buf, size_t *szp, nni_type t)
{
	nni_tcp_conn *c     = arg;
	int           fd    = nni_posix_pfd_fd(c->pfd);
	int           val   = 0;
	socklen_t     valsz = sizeof(val);

	if (getsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &val, &valsz) != 0) {
		return (nni_plat_errno(errno));
	}

	return (nni_copyout_bool(val, buf, szp, t));
}

static int
tcp_get_keepalive(void *arg, void *buf, size_t *szp, nni_type t)
{
	nni_tcp_conn *c     = arg;
	int           fd    = nni_posix_pfd_fd(c->pfd);
	int           val   = 0;
	socklen_t     valsz = sizeof(val);

	if (getsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &val, &valsz) != 0) {
		return (nni_plat_errno(errno));
	}

	return (nni_copyout_bool(val, buf, szp, t));
}

static const nni_option tcp_options[] = {
	{
	    .o_name = NNG_OPT_REMADDR,
	    .o_get  = tcp_get_peername,
	},
	{
	    .o_name = NNG_OPT_LOCADDR,
	    .o_get  = tcp_get_sockname,
	},
	{
	    .o_name = NNG_OPT_TCP_NODELAY,
	    .o_get  = tcp_get_nodelay,
	    .o_set  = tcp_set_nodelay,
	},
	{
	    .o_name = NNG_OPT_TCP_KEEPALIVE,
	    .o_get  = tcp_get_keepalive,
	    .o_set  = tcp_set_keepalive,
	},
	{
	    .o_name = NULL,
	},
};

static int
tcp_getx(void *arg, const char *name, void *buf, size_t *szp, nni_type t)
{
	nni_tcp_conn *c = arg;
	return (nni_getopt(tcp_options, name, c, buf, szp, t));
}

static int
tcp_setx(void *arg, const char *name, const void *buf, size_t sz, nni_type t)
{
	nni_tcp_conn *c = arg;
	return (nni_setopt(tcp_options, name, c, buf, sz, t));
}

int
nni_posix_tcp_alloc(nni_tcp_conn **cp, nni_tcp_dialer *d)
{
	nni_tcp_conn *c;
	if ((c = NNI_ALLOC_STRUCT(c)) == NULL) {
		return (NNG_ENOMEM);
	}

	c->closed = false;
	c->dialer = d;

	nni_mtx_init(&c->mtx);
	nni_aio_list_init(&c->readq);
	nni_aio_list_init(&c->writeq);

	c->stream.s_free  = tcp_free;
	c->stream.s_close = tcp_close;
	c->stream.s_recv  = tcp_recv;
	c->stream.s_send  = tcp_send;
	c->stream.s_getx  = tcp_getx;
	c->stream.s_setx  = tcp_setx;

	*cp = c;
	return (0);
}

void
nni_posix_tcp_init(nni_tcp_conn *c, nni_posix_pfd *pfd)
{
	c->pfd = pfd;
}

void
nni_posix_tcp_start(nni_tcp_conn *c, int nodelay, int keepalive)
{
	// Configure the initial socket options.
	(void) setsockopt(nni_posix_pfd_fd(c->pfd), IPPROTO_TCP, TCP_NODELAY,
	    &nodelay, sizeof(int));
	(void) setsockopt(nni_posix_pfd_fd(c->pfd), SOL_SOCKET, SO_KEEPALIVE,
	    &keepalive, sizeof(int));

	nni_posix_pfd_set_cb(c->pfd, tcp_cb, c);
}
