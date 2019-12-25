//
// Copyright 2019 Staysail Systems, Inc. <info@staysail.tech>
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
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#ifndef SOCK_CLOEXEC
#define SOCK_CLOEXEC 0
#endif

#include "posix_ipc.h"

typedef struct nni_ipc_dialer ipc_dialer;

// Dialer stuff.
static void
ipc_dialer_close(void *arg)
{
	ipc_dialer *d = arg;
	nni_mtx_lock(&d->mtx);
	if (!d->closed) {
		nni_aio *aio;
		d->closed = true;
		while ((aio = nni_list_first(&d->connq)) != NULL) {
			nni_ipc_conn *c;
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
ipc_dialer_free(void *arg)
{
	ipc_dialer *d = arg;
	ipc_dialer_close(d);
	nni_mtx_fini(&d->mtx);
	NNI_FREE_STRUCT(d);
}

static void
ipc_dialer_cancel(nni_aio *aio, void *arg, int rv)
{
	nni_ipc_dialer *d = arg;
	nni_ipc_conn *  c;

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
ipc_dialer_cb(nni_posix_pfd *pfd, unsigned ev, void *arg)
{
	nni_ipc_conn *  c = arg;
	nni_ipc_dialer *d = c->dialer;
	nni_aio *       aio;
	int             rv;

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
	nni_mtx_unlock(&d->mtx);

	if (rv != 0) {
		nng_stream_close(&c->stream);
		nng_stream_free(&c->stream);
		nni_aio_finish_error(aio, rv);
		return;
	}

	nni_posix_ipc_start(c);
	nni_aio_set_output(aio, 0, c);
	nni_aio_finish(aio, 0, 0);
}

// We don't give local address binding support.  Outbound dialers always
// get an ephemeral port.
void
ipc_dialer_dial(void *arg, nni_aio *aio)
{
	ipc_dialer *            d = arg;
	nni_ipc_conn *          c;
	nni_posix_pfd *         pfd = NULL;
	struct sockaddr_storage ss;
	size_t                  sslen;
	int                     fd;
	int                     rv;

	if (nni_aio_begin(aio) != 0) {
		return;
	}

	if (((sslen = nni_posix_nn2sockaddr(&ss, &d->sa)) == 0) ||
	    (ss.ss_family != AF_UNIX)) {
		nni_aio_finish_error(aio, NNG_EADDRINVAL);
		return;
	}

	if ((fd = socket(ss.ss_family, SOCK_STREAM | SOCK_CLOEXEC, 0)) < 0) {
		nni_aio_finish_error(aio, nni_plat_errno(errno));
		return;
	}

	// This arranges for the fd to be in nonblocking mode, and adds the
	// pollfd to the list.
	if ((rv = nni_posix_pfd_init(&pfd, fd)) != 0) {
		(void) close(fd);
		nni_aio_finish_error(aio, rv);
		return;
	}
	if ((rv = nni_posix_ipc_init(&c, pfd)) != 0) {
		nni_posix_pfd_fini(pfd);
		nni_aio_finish_error(aio, rv);
		return;
	}
	c->dialer = d;
	nni_posix_pfd_set_cb(pfd, ipc_dialer_cb, c);

	nni_mtx_lock(&d->mtx);
	if (d->closed) {
		rv = NNG_ECLOSED;
		goto error;
	}
	if ((rv = nni_aio_schedule(aio, ipc_dialer_cancel, d)) != 0) {
		goto error;
	}
	if (connect(fd, (void *) &ss, sslen) != 0) {
		if (errno != EINPROGRESS) {
			if (errno == ENOENT) {
				// No socket present means nobody listening.
				rv = NNG_ECONNREFUSED;
			} else {
				rv = nni_plat_errno(errno);
			}
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
	nni_mtx_unlock(&d->mtx);
	nni_posix_ipc_start(c);
	nni_aio_set_output(aio, 0, c);
	nni_aio_finish(aio, 0, 0);
	return;

error:
	nni_aio_set_prov_extra(aio, 0, NULL);
	nni_mtx_unlock(&d->mtx);
	nng_stream_free(&c->stream);
	nni_aio_finish_error(aio, rv);
}

static const nni_option ipc_dialer_options[] = {
	{
	    .o_name = NULL,
	},
};

int
ipc_dialer_getx(void *arg, const char *nm, void *buf, size_t *szp, nni_type t)
{
	ipc_dialer *d = arg;
	return (nni_getopt(ipc_dialer_options, nm, d, buf, szp, t));
}

int
ipc_dialer_setx(
    void *arg, const char *nm, const void *buf, size_t sz, nni_type t)
{
	ipc_dialer *d = arg;
	return (nni_setopt(ipc_dialer_options, nm, d, buf, sz, t));
}

int
nni_ipc_dialer_alloc(nng_stream_dialer **dp, const nng_url *url)
{
	ipc_dialer *d;

	if ((strcmp(url->u_scheme, "ipc") != 0) || (url->u_path == NULL) ||
	    (strlen(url->u_path) == 0) ||
	    (strlen(url->u_path) >= NNG_MAXADDRLEN)) {
		return (NNG_EADDRINVAL);
	}
	if ((d = NNI_ALLOC_STRUCT(d)) == NULL) {
		return (NNG_ENOMEM);
	}
	nni_mtx_init(&d->mtx);
	nni_aio_list_init(&d->connq);
	d->closed             = false;
	d->sa.s_ipc.sa_family = NNG_AF_IPC;
	strcpy(d->sa.s_ipc.sa_path, url->u_path);
	d->sd.sd_free  = ipc_dialer_free;
	d->sd.sd_close = ipc_dialer_close;
	d->sd.sd_dial  = ipc_dialer_dial;
	d->sd.sd_getx  = ipc_dialer_getx;
	d->sd.sd_setx  = ipc_dialer_setx;

	*dp = (void *) d;
	return (0);
}
