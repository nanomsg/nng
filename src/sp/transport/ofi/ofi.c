// Copyright 2026 - OFI/libfabric transport for NNG (EXPERIMENTAL)
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).

#include "../../../core/nng_impl.h"

#include <rdma/fabric.h>
#include <rdma/fi_cm.h>
#include <rdma/fi_domain.h>
#include <rdma/fi_endpoint.h>
#include <rdma/fi_errno.h>
#include <string.h>

// OFI/libfabric transport for NNG.
// Uses FI_EP_MSG (reliable connected) endpoints over the configured
// libfabric provider.  Local testing uses the "tcp" provider;
// production use targets HPE Slingshot (cxi provider).

typedef struct ofi_pipe     ofi_pipe;
typedef struct ofi_listener ofi_listener;
typedef struct ofi_dialer   ofi_dialer;

// OFI_BOUNCE_SZ: size of the per-pipe TX/RX bounce buffers.
// Large enough for the 8-byte SP header + a modest payload.
// Tasks 3-5 will make this dynamic.
#define OFI_BOUNCE_SZ (64 * 1024)

// ofi_pipe represents one connected FI_EP_MSG endpoint.
struct ofi_pipe {
	struct fid_ep     *ep;      // active endpoint
	struct fid_eq     *eq;      // event queue (CM: CONNECTED, SHUTDOWN)
	struct fid_cq     *tx_cq;   // TX completion queue
	struct fid_cq     *rx_cq;   // RX completion queue
	struct fid_mr     *mr;      // memory region for bounce buffers
	struct fid_domain *domain;  // borrowed, not owned
	struct fi_info    *fi;      // owned; the info used to create ep
	uint8_t           *tx_buf;  // TX bounce buffer (OFI_BOUNCE_SZ)
	uint8_t           *rx_buf;  // RX bounce buffer (OFI_BOUNCE_SZ)
	uint16_t           proto;   // local SP protocol ID
	uint16_t           peer;    // peer SP protocol ID
	nni_pipe          *npipe;
	nni_list_node      node;    // for ofi_listener.waitpipes
	nni_list           sendq;
	nni_list           recvq;
	nni_mtx            mtx;
	nni_thr            cq_thr;
	nni_cv             cv;
	bool               closed;
};

// ofi_listener represents a passive endpoint that accepts inbound connections.
struct ofi_listener {
	struct fid_fabric *fabric;
	struct fid_domain *domain;
	struct fid_pep    *pep;       // passive endpoint
	struct fid_eq     *eq;        // EQ for CM events on the pep
	struct fi_info    *fi;        // owned
	uint16_t           proto;
	nni_listener      *nlistener;
	nni_aio           *useraio;   // pending l_accept AIO
	nni_list           waitpipes; // fully-negotiated pipes awaiting accept
	nni_mtx            mtx;
	nni_thr            eq_thr;
	nni_cv             cv;
	bool               closed;
	bool               started;
	bool               fini;
};

// ofi_dialer represents the dialer side of a connection.
struct ofi_dialer {
	struct fid_fabric *fabric;
	struct fid_domain *domain;
	struct fi_info    *fi;
	uint16_t           proto;
	nni_dialer        *ndialer;
	nni_aio           *useraio;
	nni_mtx            mtx;
	nni_cv             cv;
	bool               closed;
	bool               fini;
};

// ofi_err maps a libfabric negative-errno return value to an NNG error.
static nng_err
ofi_err(ssize_t rv)
{
	if (rv == 0) {
		return (NNG_OK);
	}
	// libfabric returns negative errno on failure
	switch ((int) -rv) {
	case ENOTSUP:
		return (NNG_ENOTSUP);
	case EADDRINUSE:
		return (NNG_EADDRINUSE);
	case ECONNREFUSED:
		return (NNG_ECONNREFUSED);
	case ETIMEDOUT:
		return (NNG_ETIMEDOUT);
	case EACCES:
		return (NNG_EPERM);
	case ENOMEM:
		return (NNG_ENOMEM);
	case EINVAL:
		return (NNG_EINVAL);
	case EMSGSIZE:
		return (NNG_EMSGSIZE);
	case EINTR:
		return (NNG_EINTR);
	case EBADF:
		return (NNG_ECLOSED);
	case ENOENT:
		return (NNG_ENOENT);
	default:
		return (NNG_ETRANERR);
	}
}

// ─── Pipe ops ──────────────────────────────────────────────────────────────

static size_t
ofi_pipe_size(void)
{
	return (sizeof(ofi_pipe));
}

static int
ofi_pipe_init(void *arg, nni_pipe *npipe)
{
	ofi_pipe *p = arg;
	p->npipe    = npipe;
	nni_mtx_init(&p->mtx);
	nni_cv_init(&p->cv, &p->mtx);
	nni_aio_list_init(&p->sendq);
	nni_aio_list_init(&p->recvq);
	return (0);
}

static void
ofi_pipe_fini(void *arg)
{
	ofi_pipe *p = arg;
	// ep, cqs, mr, buffers and fi are freed in Tasks 3-5.
	nni_cv_fini(&p->cv);
	nni_mtx_fini(&p->mtx);
}

static void
ofi_pipe_stop(void *arg)
{
	ofi_pipe *p = arg;
	nni_mtx_lock(&p->mtx);
	p->closed = true;
	nni_cv_wake(&p->cv);
	nni_mtx_unlock(&p->mtx);
}

static void
ofi_pipe_close(void *arg)
{
	ofi_pipe *p = arg;
	nni_mtx_lock(&p->mtx);
	p->closed = true;
	nni_cv_wake(&p->cv);
	nni_mtx_unlock(&p->mtx);
}

static void
ofi_pipe_send(void *arg, nni_aio *aio)
{
	// Implemented in Task 5.
	NNI_ARG_UNUSED(arg);
	nni_aio_finish_error(aio, NNG_ENOTSUP);
}

static void
ofi_pipe_recv(void *arg, nni_aio *aio)
{
	// Implemented in Task 5.
	NNI_ARG_UNUSED(arg);
	nni_aio_finish_error(aio, NNG_ENOTSUP);
}

static uint16_t
ofi_pipe_peer(void *arg)
{
	ofi_pipe *p = arg;
	return (p->peer);
}

static nni_sp_pipe_ops ofi_pipe_ops = {
	.p_size  = ofi_pipe_size,
	.p_init  = ofi_pipe_init,
	.p_fini  = ofi_pipe_fini,
	.p_stop  = ofi_pipe_stop,
	.p_close = ofi_pipe_close,
	.p_send  = ofi_pipe_send,
	.p_recv  = ofi_pipe_recv,
	.p_peer  = ofi_pipe_peer,
};

// ─── Listener ops ──────────────────────────────────────────────────────────

static nng_err
ofi_listener_init(void *arg, nng_url *url, nni_listener *nlistener)
{
	ofi_listener *l = arg;
	NNI_ARG_UNUSED(url);

	l->nlistener = nlistener;
	l->proto =
	    nni_sock_proto_id(nni_listener_sock(nlistener));
	nni_mtx_init(&l->mtx);
	nni_cv_init(&l->cv, &l->mtx);
	NNI_LIST_INIT(&l->waitpipes, ofi_pipe, node);
	// fabric/domain/pep init happens in l_bind (Task 3).
	return (NNG_OK);
}

static void
ofi_listener_fini(void *arg)
{
	ofi_listener *l = arg;
	if (l->fi != NULL) {
		fi_freeinfo(l->fi);
	}
	nni_cv_fini(&l->cv);
	nni_mtx_fini(&l->mtx);
}

static nng_err
ofi_listener_bind(void *arg, nng_url *url)
{
	// Implemented in Task 3.
	NNI_ARG_UNUSED(arg);
	NNI_ARG_UNUSED(url);
	return (NNG_ENOTSUP);
}

static void
ofi_listener_accept(void *arg, nni_aio *aio)
{
	// Implemented in Task 3.
	NNI_ARG_UNUSED(arg);
	nni_aio_finish_error(aio, NNG_ENOTSUP);
}

static void
ofi_listener_close(void *arg)
{
	ofi_listener *l = arg;
	nni_mtx_lock(&l->mtx);
	l->closed = true;
	nni_cv_wake(&l->cv);
	nni_mtx_unlock(&l->mtx);
}

static void
ofi_listener_stop(void *arg)
{
	ofi_listener *l = arg;
	nni_mtx_lock(&l->mtx);
	l->fini = true;
	l->closed = true;
	nni_cv_wake(&l->cv);
	nni_mtx_unlock(&l->mtx);
}

static nng_err
ofi_listener_getopt(
    void *arg, const char *name, void *buf, size_t *szp, nni_type t)
{
	NNI_ARG_UNUSED(arg);
	NNI_ARG_UNUSED(name);
	NNI_ARG_UNUSED(buf);
	NNI_ARG_UNUSED(szp);
	NNI_ARG_UNUSED(t);
	return (NNG_ENOTSUP);
}

static nng_err
ofi_listener_setopt(
    void *arg, const char *name, const void *buf, size_t sz, nni_type t)
{
	NNI_ARG_UNUSED(arg);
	NNI_ARG_UNUSED(name);
	NNI_ARG_UNUSED(buf);
	NNI_ARG_UNUSED(sz);
	NNI_ARG_UNUSED(t);
	return (NNG_ENOTSUP);
}

static nni_sp_listener_ops ofi_listener_ops = {
	.l_size   = sizeof(ofi_listener),
	.l_init   = ofi_listener_init,
	.l_fini   = ofi_listener_fini,
	.l_bind   = ofi_listener_bind,
	.l_accept = ofi_listener_accept,
	.l_close  = ofi_listener_close,
	.l_stop   = ofi_listener_stop,
	.l_getopt = ofi_listener_getopt,
	.l_setopt = ofi_listener_setopt,
};

// ─── Dialer ops ────────────────────────────────────────────────────────────

static nng_err
ofi_dialer_init(void *arg, nng_url *url, nni_dialer *ndialer)
{
	ofi_dialer *d = arg;
	NNI_ARG_UNUSED(url);

	d->ndialer = ndialer;
	d->proto   = nni_sock_proto_id(nni_dialer_sock(ndialer));
	nni_mtx_init(&d->mtx);
	nni_cv_init(&d->cv, &d->mtx);
	// fabric/domain init happens in d_connect (Task 4).
	return (NNG_OK);
}

static void
ofi_dialer_fini(void *arg)
{
	ofi_dialer *d = arg;
	if (d->fi != NULL) {
		fi_freeinfo(d->fi);
	}
	nni_cv_fini(&d->cv);
	nni_mtx_fini(&d->mtx);
}

static void
ofi_dialer_connect(void *arg, nni_aio *aio)
{
	// Implemented in Task 4.
	NNI_ARG_UNUSED(arg);
	nni_aio_finish_error(aio, NNG_ENOTSUP);
}

static void
ofi_dialer_close(void *arg)
{
	ofi_dialer *d = arg;
	nni_mtx_lock(&d->mtx);
	d->closed = true;
	nni_cv_wake(&d->cv);
	nni_mtx_unlock(&d->mtx);
}

static void
ofi_dialer_stop(void *arg)
{
	ofi_dialer *d = arg;
	nni_mtx_lock(&d->mtx);
	d->fini   = true;
	d->closed = true;
	nni_cv_wake(&d->cv);
	nni_mtx_unlock(&d->mtx);
}

static nng_err
ofi_dialer_getopt(
    void *arg, const char *name, void *buf, size_t *szp, nni_type t)
{
	NNI_ARG_UNUSED(arg);
	NNI_ARG_UNUSED(name);
	NNI_ARG_UNUSED(buf);
	NNI_ARG_UNUSED(szp);
	NNI_ARG_UNUSED(t);
	return (NNG_ENOTSUP);
}

static nng_err
ofi_dialer_setopt(
    void *arg, const char *name, const void *buf, size_t sz, nni_type t)
{
	NNI_ARG_UNUSED(arg);
	NNI_ARG_UNUSED(name);
	NNI_ARG_UNUSED(buf);
	NNI_ARG_UNUSED(sz);
	NNI_ARG_UNUSED(t);
	return (NNG_ENOTSUP);
}

static nni_sp_dialer_ops ofi_dialer_ops = {
	.d_size    = sizeof(ofi_dialer),
	.d_init    = ofi_dialer_init,
	.d_fini    = ofi_dialer_fini,
	.d_connect = ofi_dialer_connect,
	.d_close   = ofi_dialer_close,
	.d_stop    = ofi_dialer_stop,
	.d_getopt  = ofi_dialer_getopt,
	.d_setopt  = ofi_dialer_setopt,
};

// ─── Transport registration ────────────────────────────────────────────────

static void
ofi_tran_init(void)
{
}

static void
ofi_tran_fini(void)
{
}

static nni_sp_tran ofi_tran = {
	.tran_scheme   = "ofi",
	.tran_dialer   = &ofi_dialer_ops,
	.tran_listener = &ofi_listener_ops,
	.tran_pipe     = &ofi_pipe_ops,
	.tran_init     = ofi_tran_init,
	.tran_fini     = ofi_tran_fini,
};

void
nni_sp_ofi_register(void)
{
	nni_sp_tran_register(&ofi_tran);
}
