//
// Copyright 2025 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
// Copyright 2019 Devolutions <info@devolutions.net>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

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

#include "../../core/aio.h"
#include "../../core/defs.h"
#include "../../core/options.h"
#include "../../core/platform.h"

#include "posix_pollq.h"
#include "posix_tcp.h"

static void
tcp_dowrite(nni_tcp_conn *c)
{
	nni_aio *aio;
	int      fd = nni_posix_pfd_fd(&c->pfd);

	if (c->closed) {
		return;
	}

	while ((aio = nni_list_first(&c->writeq)) != NULL) {
		int      n;
		unsigned naiov;
		nni_iov *aiov;

		nni_aio_get_iov(aio, &naiov, &aiov);

		NNI_ASSERT(naiov <= NNI_AIO_MAX_IOV);

#ifdef NNG_HAVE_SENDMSG
		struct msghdr hdr = { 0 };
		struct iovec  iovec[NNI_AIO_MAX_IOV];
		int           niov;
		unsigned      i;
		for (niov = 0, i = 0; i < naiov; i++) {
			if (aiov[i].iov_len > 0) {
				iovec[niov].iov_len  = aiov[i].iov_len;
				iovec[niov].iov_base = aiov[i].iov_buf;
				niov++;
			}
		}

		hdr.msg_iovlen = niov;
		hdr.msg_iov    = iovec;

		n = sendmsg(fd, &hdr, MSG_NOSIGNAL);
#else
		// We have to send a bit at a time.
		n = send(fd, aiov[0].iov_buf, aiov[0].iov_len, MSG_NOSIGNAL);
#endif
		if (n < 0) {
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
	int      fd = nni_posix_pfd_fd(&c->pfd);

	if (c->closed) {
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
	nni_aio      *aio;

	nni_mtx_lock(&c->mtx);
	while (((aio = nni_list_first(&c->readq)) != NULL) ||
	    ((aio = nni_list_first(&c->writeq)) != NULL)) {
		nni_aio_list_remove(aio);
		nni_aio_finish_error(aio, err);
	}
	nni_posix_pfd_close(&c->pfd);
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
		nni_posix_pfd_close(&c->pfd);
	}
	nni_mtx_unlock(&c->mtx);
}

static void
tcp_stop(void *arg)
{
	nni_tcp_conn *c = arg;
	tcp_close(c);

	nni_posix_pfd_stop(&c->pfd);
}

// tcp_fini may block briefly waiting for the pollq thread.
// To get that out of our context, we simply reap this.
static void
tcp_fini(void *arg)
{
	nni_tcp_conn *c = arg;
	tcp_stop(c);
	nni_posix_pfd_fini(&c->pfd);
	nni_mtx_fini(&c->mtx);

	if (c->dialer != NULL) {
		nni_posix_tcp_dialer_rele(c->dialer);
	}
	NNI_FREE_STRUCT(c);
}

static nni_reap_list tcp_reap_list = {
	.rl_offset = offsetof(nni_tcp_conn, reap),
	.rl_func   = tcp_fini,
};

static void
tcp_free(void *arg)
{
	nni_tcp_conn *c = arg;
	nni_reap(&tcp_reap_list, c);
}

static void
tcp_cb(void *arg, unsigned events)
{
	nni_tcp_conn *c = arg;

	if (c->dial_aio != NULL) {
		nni_posix_tcp_dial_cb(c, events);
		return;
	}
	if ((events & (NNI_POLL_HUP | NNI_POLL_ERR | NNI_POLL_INVAL)) != 0) {
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
		nni_posix_pfd_arm(&c->pfd, events);
	}
	nni_mtx_unlock(&c->mtx);
}

static void
tcp_cancel(nni_aio *aio, void *arg, nng_err rv)
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

	nni_aio_reset(aio);
	nni_mtx_lock(&c->mtx);
	if (!nni_aio_start(aio, tcp_cancel, c)) {
		nni_mtx_unlock(&c->mtx);
		return;
	}
	nni_aio_list_append(&c->writeq, aio);

	if (nni_list_first(&c->writeq) == aio) {
		tcp_dowrite(c);
		// If we are still the first thing on the list, that
		// means we didn't finish the job, so arm the poller to
		// complete us.
		if (nni_list_first(&c->writeq) == aio) {
			nni_posix_pfd_arm(&c->pfd, NNI_POLL_OUT);
		}
	}
	nni_mtx_unlock(&c->mtx);
}

static void
tcp_recv(void *arg, nni_aio *aio)
{
	nni_tcp_conn *c = arg;

	nni_aio_reset(aio);
	nni_mtx_lock(&c->mtx);
	if (!nni_aio_start(aio, tcp_cancel, c)) {
		nni_mtx_unlock(&c->mtx);
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
			nni_posix_pfd_arm(&c->pfd, NNI_POLL_IN);
		}
	}
	nni_mtx_unlock(&c->mtx);
}

static const nng_sockaddr *
tcp_get_peer_addr(void *arg)
{
	nni_tcp_conn *c = arg;
	return (&c->peer);
}

static const nng_sockaddr *
tcp_get_self_addr(void *arg)
{
	nni_tcp_conn *c = arg;
	return (&c->self);
}

static nng_err
tcp_get_nodelay(void *arg, void *buf, size_t *szp, nni_type t)
{
	nni_tcp_conn *c     = arg;
	int           fd    = nni_posix_pfd_fd(&c->pfd);
	int           val   = 0;
	socklen_t     valsz = sizeof(val);

	if (getsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &val, &valsz) != 0) {
		return (nni_plat_errno(errno));
	}

	return (nni_copyout_bool(val, buf, szp, t));
}

static nng_err
tcp_get_keepalive(void *arg, void *buf, size_t *szp, nni_type t)
{
	nni_tcp_conn *c     = arg;
	int           fd    = nni_posix_pfd_fd(&c->pfd);
	int           val   = 0;
	socklen_t     valsz = sizeof(val);

	if (getsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &val, &valsz) != 0) {
		return (nni_plat_errno(errno));
	}

	return (nni_copyout_bool(val, buf, szp, t));
}

static const nni_option tcp_options[] = {
	{
	    .o_name = NNG_OPT_TCP_NODELAY,
	    .o_get  = tcp_get_nodelay,
	},
	{
	    .o_name = NNG_OPT_TCP_KEEPALIVE,
	    .o_get  = tcp_get_keepalive,
	},
	{
	    .o_name = NULL,
	},
};

static nng_err
tcp_get(void *arg, const char *name, void *buf, size_t *szp, nni_type t)
{
	nni_tcp_conn *c = arg;
	return (nni_getopt(tcp_options, name, c, buf, szp, t));
}

static nng_err
tcp_set(void *arg, const char *name, const void *buf, size_t sz, nni_type t)
{
	nni_tcp_conn *c = arg;
	return (nni_setopt(tcp_options, name, c, buf, sz, t));
}

int
nni_posix_tcp_alloc(nni_tcp_conn **cp, nni_tcp_dialer *d, int fd)
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
	nni_posix_pfd_init(&c->pfd, fd, tcp_cb, c);

	c->stream.s_free      = tcp_free;
	c->stream.s_stop      = tcp_stop;
	c->stream.s_close     = tcp_close;
	c->stream.s_recv      = tcp_recv;
	c->stream.s_send      = tcp_send;
	c->stream.s_get       = tcp_get;
	c->stream.s_set       = tcp_set;
	c->stream.s_peer_addr = tcp_get_peer_addr;
	c->stream.s_self_addr = tcp_get_self_addr;

	*cp = c;
	return (0);
}

void
nni_posix_tcp_start(nni_tcp_conn *c, int nodelay, int keepalive)
{
	int fd = nni_posix_pfd_fd(&c->pfd);
	// Configure the initial socket options.
	(void) setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof(int));
	(void) setsockopt(
	    fd, SOL_SOCKET, SO_KEEPALIVE, &keepalive, sizeof(int));

	struct sockaddr_storage ss;
	socklen_t               len = sizeof(ss);

	// Get this info now so we can avoid system calls later.
	(void) getpeername(fd, (void *) &ss, &len);
	nni_posix_sockaddr2nn(&c->peer, &ss, len);

	(void) getsockname(fd, (void *) &ss, &len);
	nni_posix_sockaddr2nn(&c->self, &ss, len);
}
