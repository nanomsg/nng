//
// Copyright 2020 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
// Copyright 2018 Devolutions <info@devolutions.net>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "core/nng_impl.h"

#include <errno.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#ifndef SOCK_CLOEXEC
#define SOCK_CLOEXEC 0
#endif

#include "posix_tcp.h"

// Dialer stuff.
int
nni_tcp_dialer_init(nni_tcp_dialer **dp)
{
	nni_tcp_dialer *d;

	if ((d = NNI_ALLOC_STRUCT(d)) == NULL) {
		return (NNG_ENOMEM);
	}
	nni_mtx_init(&d->mtx);
	d->closed = false;
	nni_aio_list_init(&d->connq);
	nni_atomic_init_bool(&d->fini);
	nni_atomic_init64(&d->ref);
	nni_atomic_inc64(&d->ref);
	*dp = d;
	return (0);
}

void
nni_tcp_dialer_close(nni_tcp_dialer *d)
{
	nni_mtx_lock(&d->mtx);
	if (!d->closed) {
		nni_aio *aio;
		d->closed = true;
		while ((aio = nni_list_first(&d->connq)) != NULL) {
			nni_tcp_conn *c;
			nni_list_remove(&d->connq, aio);
			if ((c = nni_aio_get_prov_extra(aio, 0)) != NULL) {
				c->dial_aio = NULL;
				nni_aio_set_prov_extra(aio, 0, NULL);
				nng_stream_close(&c->stream);
				nng_stream_free(&c->stream);
			}
			nni_aio_finish_error(aio, NNG_ECLOSED);
		}
	}
	nni_mtx_unlock(&d->mtx);
}

static void
tcp_dialer_fini(nni_tcp_dialer *d)
{
	nni_mtx_fini(&d->mtx);
	NNI_FREE_STRUCT(d);
}

void
nni_tcp_dialer_fini(nni_tcp_dialer *d)
{
	nni_tcp_dialer_close(d);
	nni_atomic_set_bool(&d->fini, true);
	nni_posix_tcp_dialer_rele(d);
}

void
nni_posix_tcp_dialer_rele(nni_tcp_dialer *d)
{
	if (((nni_atomic_dec64_nv(&d->ref) != 0)) ||
	    (!nni_atomic_get_bool(&d->fini))) {
		return;
	}
	tcp_dialer_fini(d);
}

static void
tcp_dialer_cancel(nni_aio *aio, void *arg, int rv)
{
	nni_tcp_dialer *d = arg;
	nni_tcp_conn *  c;

	nni_mtx_lock(&d->mtx);
	if ((!nni_aio_list_active(aio)) ||
	    ((c = nni_aio_get_prov_extra(aio, 0)) == NULL)) {
		nni_mtx_unlock(&d->mtx);
		return;
	}
	nni_aio_list_remove(aio);
	c->dial_aio = NULL;
	nni_aio_set_prov_extra(aio, 0, NULL);
	nni_mtx_unlock(&d->mtx);

	nni_aio_finish_error(aio, rv);
	nng_stream_free(&c->stream);
}

static void
tcp_dialer_cb(nni_posix_pfd *pfd, unsigned ev, void *arg)
{
	nni_tcp_conn *  c = arg;
	nni_tcp_dialer *d = c->dialer;
	nni_aio *       aio;
	int             rv;
	int             ka;
	int             nd;

	nni_mtx_lock(&d->mtx);
	aio = c->dial_aio;
	if ((aio == NULL) || (!nni_aio_list_active(aio))) {
		nni_mtx_unlock(&d->mtx);
		return;
	}

	if ((ev & NNI_POLL_INVAL) != 0) {
		rv = EBADF;

	} else {
		socklen_t sz = sizeof(int);
		int       fd = nni_posix_pfd_fd(pfd);
		if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &rv, &sz) < 0) {
			rv = errno;
		}
		if (rv == EINPROGRESS) {
			// Connection still in progress, come back
			// later.
			nni_mtx_unlock(&d->mtx);
			return;
		} else if (rv != 0) {
			rv = nni_plat_errno(rv);
		}
	}

	c->dial_aio = NULL;
	nni_aio_list_remove(aio);
	nni_aio_set_prov_extra(aio, 0, NULL);
	nd = d->nodelay ? 1 : 0;
	ka = d->keepalive ? 1 : 0;

	nni_mtx_unlock(&d->mtx);

	if (rv != 0) {
		nng_stream_close(&c->stream);
		nng_stream_free(&c->stream);
		nni_aio_finish_error(aio, rv);
		return;
	}

	nni_posix_tcp_start(c, nd, ka);
	nni_aio_set_output(aio, 0, c);
	nni_aio_finish(aio, 0, 0);
}

// We don't give local address binding support.  Outbound dialers always
// get an ephemeral port.
void
nni_tcp_dial(nni_tcp_dialer *d, nni_aio *aio)
{
	nni_tcp_conn *          c;
	nni_posix_pfd *         pfd = NULL;
	struct sockaddr_storage ss;
	size_t                  sslen;
	int                     fd;
	int                     rv;
	int                     ka;
	int                     nd;
	nng_sockaddr            sa;

	if (nni_aio_begin(aio) != 0) {
		return;
	}

	nni_aio_get_sockaddr(aio, &sa);
	if (((sslen = nni_posix_nn2sockaddr(&ss, &sa)) == 0) ||
	    ((ss.ss_family != AF_INET) && (ss.ss_family != AF_INET6))) {
		nni_aio_finish_error(aio, NNG_EADDRINVAL);
		return;
	}

	if ((fd = socket(ss.ss_family, SOCK_STREAM | SOCK_CLOEXEC, 0)) < 0) {
		nni_aio_finish_error(aio, nni_plat_errno(errno));
		return;
	}

	nni_atomic_inc64(&d->ref);

	if ((rv = nni_posix_tcp_alloc(&c, d)) != 0) {
		nni_aio_finish_error(aio, rv);
		nni_posix_tcp_dialer_rele(d);
		return;
	}

	// This arranges for the fd to be in non-blocking mode, and adds the
	// poll fd to the list.
	if ((rv = nni_posix_pfd_init(&pfd, fd)) != 0) {
		(void) close(fd);
		goto error;
	}

	nni_posix_tcp_init(c, pfd);
	nni_posix_pfd_set_cb(pfd, tcp_dialer_cb, c);

	nni_mtx_lock(&d->mtx);
	if (d->closed) {
		rv = NNG_ECLOSED;
		goto error;
	}
	if (d->srclen != 0) {
		if (bind(fd, (void *) &d->src, d->srclen) != 0) {
			rv = nni_plat_errno(errno);
			goto error;
		}
	}
	if ((rv = nni_aio_schedule(aio, tcp_dialer_cancel, d)) != 0) {
		goto error;
	}
	if (connect(fd, (void *) &ss, sslen) != 0) {
		if (errno != EINPROGRESS) {
			rv = nni_plat_errno(errno);
			goto error;
		}
		// Asynchronous connect.
		if ((rv = nni_posix_pfd_arm(pfd, NNI_POLL_OUT)) != 0) {
			goto error;
		}
		c->dial_aio = aio;
		nni_aio_set_prov_extra(aio, 0, c);
		nni_list_append(&d->connq, aio);
		nni_mtx_unlock(&d->mtx);
		return;
	}
	// Immediate connect, cool!  This probably only happens
	// on loopback, and probably not on every platform.
	nni_aio_set_prov_extra(aio, 0, NULL);
	nd = d->nodelay ? 1 : 0;
	ka = d->keepalive ? 1 : 0;
	nni_mtx_unlock(&d->mtx);
	nni_posix_tcp_start(c, nd, ka);
	nni_aio_set_output(aio, 0, c);
	nni_aio_finish(aio, 0, 0);
	return;

error:
	nni_aio_set_prov_extra(aio, 0, NULL);
	nni_mtx_unlock(&d->mtx);
	nng_stream_free(&c->stream);
	nni_aio_finish_error(aio, rv);
}

static int
tcp_dialer_set_nodelay(void *arg, const void *buf, size_t sz, nni_type t)
{
	nni_tcp_dialer *d = arg;
	int             rv;
	bool            b;

	if (((rv = nni_copyin_bool(&b, buf, sz, t)) != 0) || (d == NULL)) {
		return (rv);
	}
	nni_mtx_lock(&d->mtx);
	d->nodelay = b;
	nni_mtx_unlock(&d->mtx);
	return (0);
}

static int
tcp_dialer_get_nodelay(void *arg, void *buf, size_t *szp, nni_type t)
{
	bool            b;
	nni_tcp_dialer *d = arg;
	nni_mtx_lock(&d->mtx);
	b = d->nodelay;
	nni_mtx_unlock(&d->mtx);
	return (nni_copyout_bool(b, buf, szp, t));
}

static int
tcp_dialer_set_keepalive(void *arg, const void *buf, size_t sz, nni_type t)
{
	nni_tcp_dialer *d = arg;
	int             rv;
	bool            b;

	if (((rv = nni_copyin_bool(&b, buf, sz, t)) != 0) || (d == NULL)) {
		return (rv);
	}
	nni_mtx_lock(&d->mtx);
	d->keepalive = b;
	nni_mtx_unlock(&d->mtx);
	return (0);
}

static int
tcp_dialer_get_keepalive(void *arg, void *buf, size_t *szp, nni_type t)
{
	bool            b;
	nni_tcp_dialer *d = arg;
	nni_mtx_lock(&d->mtx);
	b = d->keepalive;
	nni_mtx_unlock(&d->mtx);
	return (nni_copyout_bool(b, buf, szp, t));
}

static int
tcp_dialer_get_locaddr(void *arg, void *buf, size_t *szp, nni_type t)
{
	nni_tcp_dialer *d = arg;
	nng_sockaddr    sa;

	nni_mtx_lock(&d->mtx);
	if (nni_posix_sockaddr2nn(&sa, &d->src) != 0) {
		sa.s_family = NNG_AF_UNSPEC;
	}
	nni_mtx_unlock(&d->mtx);
	return (nni_copyout_sockaddr(&sa, buf, szp, t));
}

static int
tcp_dialer_set_locaddr(void *arg, const void *buf, size_t sz, nni_type t)
{
	nni_tcp_dialer *        d = arg;
	nng_sockaddr            sa;
	struct sockaddr_storage ss;
	struct sockaddr_in *    sin;
	struct sockaddr_in6 *   sin6;
	size_t                  sslen;
	int                     rv;

	if ((rv = nni_copyin_sockaddr(&sa, buf, sz, t)) != 0) {
		return (rv);
	}
	if ((sslen = nni_posix_nn2sockaddr(&ss, &sa)) == 0) {
		return (NNG_EADDRINVAL);
	}
	// Ensure we are either IPv4 or IPv6, and port is not set.  (We
	// do not allow binding to a specific port.)
	switch (ss.ss_family) {
	case AF_INET:
		sin = (void *) &ss;
		if (sin->sin_port != 0) {
			return (NNG_EADDRINVAL);
		}
		break;
	case AF_INET6:
		sin6 = (void *) &ss;
		if (sin6->sin6_port != 0) {
			return (NNG_EADDRINVAL);
		}
		break;
	default:
		return (NNG_EADDRINVAL);
	}
	if (d != NULL) {
		nni_mtx_lock(&d->mtx);
		if (d->closed) {
			nni_mtx_unlock(&d->mtx);
			return (NNG_ECLOSED);
		}
		d->src    = ss;
		d->srclen = sslen;
		nni_mtx_unlock(&d->mtx);
	}
	return (0);
}

static const nni_option tcp_dialer_options[] = {
	{
	    .o_name = NNG_OPT_LOCADDR,
	    .o_get  = tcp_dialer_get_locaddr,
	    .o_set  = tcp_dialer_set_locaddr,
	},
	{
	    .o_name = NNG_OPT_TCP_NODELAY,
	    .o_get  = tcp_dialer_get_nodelay,
	    .o_set  = tcp_dialer_set_nodelay,
	},
	{
	    .o_name = NNG_OPT_TCP_KEEPALIVE,
	    .o_get  = tcp_dialer_get_keepalive,
	    .o_set  = tcp_dialer_set_keepalive,
	},
	{
	    .o_name = NULL,
	},
};

int
nni_tcp_dialer_getopt(
    nni_tcp_dialer *d, const char *name, void *buf, size_t *szp, nni_type t)
{
	return (nni_getopt(tcp_dialer_options, name, d, buf, szp, t));
}

int
nni_tcp_dialer_setopt(nni_tcp_dialer *d, const char *name, const void *buf,
    size_t sz, nni_type t)
{
	return (nni_setopt(tcp_dialer_options, name, d, buf, sz, t));
}
