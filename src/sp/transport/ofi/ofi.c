// Copyright 2026 - OFI/libfabric transport for NNG (EXPERIMENTAL)
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).

#include "../../../core/nng_impl.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <netinet/in.h>
#include <rdma/fabric.h>
#include <rdma/fi_cm.h>
#include <rdma/fi_domain.h>
#include <rdma/fi_endpoint.h>
#include <rdma/fi_errno.h>
#include "platform/posix/posix_pollq.h"

// OFI/libfabric transport for NNG.
// Uses FI_EP_MSG (reliable connected) endpoints over the configured
// libfabric provider.  Local testing uses the "sockets" provider;
// production use targets HPE Slingshot (cxi provider).

typedef struct ofi_pipe ofi_pipe;
typedef struct ofi_ep   ofi_ep;

// Per-pipe TX/RX bounce buffer size.
// Must be >= the NNG socket option NNG_OPT_RECVMAXSZ (default 1 MB).
// Framing adds 8 bytes for the length prefix.
#define OFI_BOUNCE_SZ (1024 * 1024)

// Wire size of the SP negotiation header (same format as TCP transport).
#define OFI_NEGO_SZ 8

// ── Global libfabric state (one fabric + domain per process) ─────────────

static struct fid_fabric *ofi_fabric;
static struct fid_domain *ofi_domain;
static struct fi_info    *ofi_base_info;
static nni_mtx            ofi_global_mtx;

// ── Per-endpoint (dialer or listener) ────────────────────────────────────

struct ofi_ep {
	// Listener-only
	struct fid_pep *pep; // passive endpoint

	// Shared
	struct fid_eq *eq;    // CM event queue
	bool           is_dialer;
	uint16_t       proto; // local SP protocol ID
	bool           closed;
	bool           eq_thr_started;
	nni_aio       *useraio;   // pending accept / connect AIO
	nni_list       waitpipes; // nego-complete pipes pending delivery
	nni_listener  *nlistener;
	nni_dialer    *ndialer;
	nni_mtx        mtx;
	nni_thr        eq_thr;

	// Dialer in-progress connection state
	// (created in d_connect, transferred to pipe on FI_CONNECTED)
	struct fid_ep *dial_ep;
	struct fid_cq *dial_tx_cq;
	struct fid_cq *dial_rx_cq;
	void          *dest_addr;
	size_t         dest_addrlen;
};

// ── Per-pipe (one FI_EP_MSG active endpoint + CQs + bounce buffers) ───────

struct ofi_pipe {
	ofi_ep       *oep;
	nni_pipe     *npipe;
	uint16_t      peer;  // peer SP protocol ID (extracted from nego header)
	uint16_t      proto; // local SP protocol ID
	bool          closed;
	nni_posix_pfd cq_pfd;
	nni_list_node node; // link in oep->waitpipes

	struct fid_ep *ep;    // active endpoint (owned)
	struct fid_cq *tx_cq; // TX completion queue (owned)
	struct fid_cq *rx_cq; // RX completion queue (owned)
	struct fid_mr *tx_mr; // TX memory region
	struct fid_mr *rx_mr; // RX memory region
	void          *tx_buf; // registered TX bounce buffer
	void          *rx_buf; // registered RX bounce buffer

	uint8_t tx_nego[OFI_NEGO_SZ]; // outgoing SP header bytes
	uint8_t rx_nego[OFI_NEGO_SZ]; // received SP header bytes

	nni_msg *rx_msg_cache; // cached RX message

	nni_list sendq; // pending send AIOs (Task 5)
	nni_list recvq; // pending recv AIOs (Task 5)
	nni_mtx  mtx;
};

// ── Error mapping ─────────────────────────────────────────────────────────

static nng_err
ofi_err(ssize_t rv)
{
	if (rv == 0) {
		return (NNG_OK);
	}
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
	default:
		return (NNG_ETRANERR);
	}
}

// ── Forward declarations ──────────────────────────────────────────────────

static void ofi_ep_eq_thread(void *);
static void ofi_cq_pfd_cb(void *, unsigned);
static void ofi_pipe_nego_start(ofi_pipe *);
static void ofi_pipe_nego_complete(ofi_pipe *, bool);
static nng_err ofi_pipe_alloc(
    ofi_ep *, struct fid_ep *, struct fid_cq *, struct fid_cq *, bool);

// ── Pipe ops ──────────────────────────────────────────────────────────────

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
	p->rx_msg_cache = NULL;
	nni_mtx_init(&p->mtx);
	nni_aio_list_init(&p->sendq);
	nni_aio_list_init(&p->recvq);
	return (0);
}

static void
ofi_pipe_fini(void *arg)
{
	ofi_pipe *p = arg;
	// ofi_pipe_stop has already joined cq_thr; safe to free resources.
	if (p->rx_msg_cache != NULL) {
		nni_msg_free(p->rx_msg_cache);
		p->rx_msg_cache = NULL;
	}
	if (p->ep != NULL) {
		fi_close(&p->ep->fid);
		p->ep = NULL;
	}
	if (p->tx_mr != NULL) {
		fi_close(&p->tx_mr->fid);
		p->tx_mr = NULL;
	}
	if (p->rx_mr != NULL) {
		fi_close(&p->rx_mr->fid);
		p->rx_mr = NULL;
	}
	if (p->tx_cq != NULL) {
		fi_close(&p->tx_cq->fid);
		p->tx_cq = NULL;
	}
	if (p->rx_cq != NULL) {
		fi_close(&p->rx_cq->fid);
		p->rx_cq = NULL;
	}
	if (p->tx_buf != NULL) {
		nni_free(p->tx_buf, OFI_BOUNCE_SZ);
		p->tx_buf = NULL;
	}
	if (p->rx_buf != NULL) {
		nni_free(p->rx_buf, OFI_BOUNCE_SZ);
		p->rx_buf = NULL;
	}
	nni_mtx_fini(&p->mtx);
	nni_posix_pfd_fini(&p->cq_pfd);
}

static void
ofi_pipe_stop(void *arg)
{
	ofi_pipe *p = arg;
	nni_mtx_lock(&p->mtx);
	p->closed     = true;
	nni_mtx_unlock(&p->mtx);
	nni_posix_pfd_stop(&p->cq_pfd);
}

static void
ofi_pipe_close(void *arg)
{
	ofi_pipe *p = arg;
	nni_aio  *aio;

	nni_mtx_lock(&p->mtx);
	p->closed     = true;
	nni_mtx_unlock(&p->mtx);

	// Cancel any recv AIOs queued by the SP protocol layer.  Without
	// this the SP recv loop hangs indefinitely waiting for messages that
	// will never arrive, blocking pipe teardown and socket shutdown.
	for (;;) {
		nni_mtx_lock(&p->mtx);
		aio = nni_list_first(&p->recvq);
		if (aio != NULL) {
			nni_aio_list_remove(aio);
		}
		nni_mtx_unlock(&p->mtx);
		if (aio == NULL) {
			break;
		}
		nni_aio_finish_error(aio, NNG_ECLOSED);
	}

	// Cancel any send AIOs that are outstanding.
	for (;;) {
		nni_mtx_lock(&p->mtx);
		aio = nni_list_first(&p->sendq);
		if (aio != NULL) {
			nni_aio_list_remove(aio);
		}
		nni_mtx_unlock(&p->mtx);
		if (aio == NULL) {
			break;
		}
		nni_aio_finish_error(aio, NNG_ECLOSED);
	}
}

static void
ofi_pipe_send_cancel(nni_aio *aio, void *arg, nng_err rv)
{
	ofi_pipe *p = arg;
	nni_mtx_lock(&p->mtx);
	if (nni_aio_list_active(aio)) {
		nni_aio_list_remove(aio);
		nni_mtx_unlock(&p->mtx);
		nni_aio_finish_error(aio, rv);
		return;
	}
	nni_mtx_unlock(&p->mtx);
}

static void
ofi_pipe_do_send(ofi_pipe *p)
{
	nni_aio      *aio;
	nni_msg      *msg;
	size_t        hlen, blen, total;
	struct iovec  tx_iov;
	struct fi_msg tx_msg;
	int           rv;

	aio = nni_list_first(&p->sendq);
	if (aio == NULL) {
		return;
	}
	msg   = nni_aio_get_msg(aio);
	hlen  = nni_msg_header_len(msg);
	blen  = nni_msg_len(msg);
	total = hlen + blen;

	NNI_PUT64((uint8_t *) p->tx_buf, (uint64_t) total);
	memcpy((uint8_t *) p->tx_buf + 8, nni_msg_header(msg), hlen);
	memcpy((uint8_t *) p->tx_buf + 8 + hlen, nni_msg_body(msg), blen);

	tx_iov.iov_base = p->tx_buf;
	tx_iov.iov_len  = total + 8;
	memset(&tx_msg, 0, sizeof(tx_msg));
	tx_msg.msg_iov   = &tx_iov;
	tx_msg.desc      = fi_mr_desc(p->tx_mr);
	tx_msg.iov_count = 1;
	tx_msg.addr      = FI_ADDR_UNSPEC;
	tx_msg.context   = aio;
	rv               = fi_sendmsg(p->ep, &tx_msg, 0);
	if (rv != 0) {
		nni_aio_list_remove(aio);
		nni_mtx_unlock(&p->mtx);
		nni_aio_finish_error(aio, ofi_err(rv));
		nni_mtx_lock(&p->mtx);
	}
}

static void
ofi_pipe_send(void *arg, nni_aio *aio)
{
	ofi_pipe     *p = arg;
	nni_msg      *msg;
	size_t        hlen, blen, total;

	nni_aio_reset(aio);
	nni_mtx_lock(&p->mtx);
	if (p->closed) {
		nni_mtx_unlock(&p->mtx);
		nni_aio_finish_error(aio, NNG_ECLOSED);
		return;
	}
	if (!nni_aio_start(aio, ofi_pipe_send_cancel, p)) {
		nni_mtx_unlock(&p->mtx);
		return;
	}
	msg   = nni_aio_get_msg(aio);
	hlen  = nni_msg_header_len(msg);
	blen  = nni_msg_len(msg);
	total = hlen + blen;
	if (total + 8 > OFI_BOUNCE_SZ) {
		nni_mtx_unlock(&p->mtx);
		nni_aio_finish_error(aio, NNG_EMSGSIZE);
		return;
	}

	nni_list_append(&p->sendq, aio);
	if (nni_list_first(&p->sendq) == aio) {
		ofi_pipe_do_send(p);
	}
	nni_mtx_unlock(&p->mtx);
}

static void
ofi_pipe_recv_cancel(nni_aio *aio, void *arg, nng_err rv)
{
	ofi_pipe *p = arg;
	nni_mtx_lock(&p->mtx);
	if (nni_aio_list_active(aio)) {
		nni_aio_list_remove(aio);
		nni_mtx_unlock(&p->mtx);
		nni_aio_finish_error(aio, rv);
		return;
	}
	nni_mtx_unlock(&p->mtx);
}

static void
ofi_pipe_recv(void *arg, nni_aio *aio)
{
	ofi_pipe *p = arg;

	nni_aio_reset(aio);
	nni_mtx_lock(&p->mtx);
	if (p->closed) {
		nni_mtx_unlock(&p->mtx);
		nni_aio_finish_error(aio, NNG_ECLOSED);
		return;
	}
	if (!nni_aio_start(aio, ofi_pipe_recv_cancel, p)) {
		nni_mtx_unlock(&p->mtx);
		return;
	}
	if (p->rx_msg_cache != NULL) {
		nni_msg *msg = p->rx_msg_cache;
		p->rx_msg_cache = NULL;
		nni_pipe_bump_rx(p->npipe, nni_msg_len(msg));
		nni_aio_set_msg(aio, msg);
		
		struct iovec  rx_iov;
		struct fi_msg rx_msg;
		rx_iov.iov_base = p->rx_buf;
		rx_iov.iov_len  = OFI_BOUNCE_SZ;
		memset(&rx_msg, 0, sizeof(rx_msg));
		rx_msg.msg_iov   = &rx_iov;
		rx_msg.desc      = fi_mr_desc(p->rx_mr);
		rx_msg.iov_count = 1;
		rx_msg.addr      = FI_ADDR_UNSPEC;
		fi_recvmsg(p->ep, &rx_msg, 0);
		
		nni_mtx_unlock(&p->mtx);
		nni_aio_finish_sync(aio, 0, nni_msg_len(msg));
		return;
	}
	nni_list_append(&p->recvq, aio);
	nni_mtx_unlock(&p->mtx);
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

// ── Negotiation helpers ────────────────────────────────────────────────────

// Send the 8-byte SP protocol header over the connected endpoint.
// Wire format (same as TCP transport): 0x00 'S' 'P' 0x00 <proto_id BE16>
// 0x00 0x00
static void
ofi_pipe_nego_start(ofi_pipe *p)
{
	struct iovec  iov;
	struct fi_msg msg;
	int           rv;

	p->tx_nego[0] = 0x00;
	p->tx_nego[1] = 'S';
	p->tx_nego[2] = 'P';
	p->tx_nego[3] = 0x00;
	NNI_PUT16(&p->tx_nego[4], p->proto);
	p->tx_nego[6] = 0x00;
	p->tx_nego[7] = 0x00;

	// TX buffer is registered; copy header there before fi_sendmsg.
	memcpy(p->tx_buf, p->tx_nego, OFI_NEGO_SZ);

	iov.iov_base = p->tx_buf;
	iov.iov_len  = OFI_NEGO_SZ;

	memset(&msg, 0, sizeof(msg));
	msg.msg_iov   = &iov;
	msg.desc      = fi_mr_desc(p->tx_mr);
	msg.iov_count = 1;
	msg.addr      = FI_ADDR_UNSPEC;

	rv = fi_sendmsg(p->ep, &msg, 0);
	if (rv != 0) {
		nng_log_warn("NNG-OFI", "nego send failed: %s",
		    fi_strerror(-rv));
		nni_pipe_close(p->npipe);
	}
}

// Called from the CQ thread when TX + RX of the SP header are both done.
static void
ofi_pipe_nego_complete(ofi_pipe *p, bool success)
{
	ofi_ep  *ep;
	nni_aio *aio;

	if (!success) {
		nni_pipe_close(p->npipe);
		return;
	}

	// Validate received SP header.
	if (p->rx_nego[0] != 0x00 || p->rx_nego[1] != 'S' ||
	    p->rx_nego[2] != 'P' || p->rx_nego[3] != 0x00 ||
	    p->rx_nego[6] != 0x00 || p->rx_nego[7] != 0x00) {
		nng_log_warn("NNG-OFI", "bad SP header from peer");
		nni_pipe_close(p->npipe);
		return;
	}
	NNI_GET16(&p->rx_nego[4], p->peer);

	// Deliver the pipe to the socket via the pending accept/connect AIO.
	ep = p->oep;
	nni_mtx_lock(&ep->mtx);
	aio = ep->useraio;
	if (aio != NULL) {
		ep->useraio = NULL;
		nni_aio_set_output(aio, 0, p->npipe);
		nni_mtx_unlock(&ep->mtx);
		nni_aio_finish(aio, 0, 0);
	} else {
		nni_list_append(&ep->waitpipes, p);
		nni_mtx_unlock(&ep->mtx);
	}
}

// ── CQ polling thread ─────────────────────────────────────────────────────
//
// A single ofi_pipe_drain_cqs call handles both phases:
//   - TX completions: absorb nego TX (sendq empty) or finish data send AIOs.
//   - RX completions: detect nego vs data by p->peer == 0; call
//     ofi_pipe_nego_complete on nego, unpack framed message and deliver to
//     a queued recv AIO on data.
// TX is always drained before RX so that when nego_complete delivers the
// pipe (asynchronously via nni_aio_finish → task queue), no data send AIO
// can be in sendq yet when the pending nego TX completion is processed.

static void
ofi_pipe_drain_cqs(ofi_pipe *p)
{
	struct fi_cq_msg_entry cqe[16];
	struct fi_cq_err_entry cq_err;
	ssize_t                n;
	int                    wait_fd = nni_posix_pfd_fd(&p->cq_pfd);
	bool                   found;


	// The FI_WAIT_FD mechanism uses a Unix pipe: the provider writes one
	// byte per completion, but fi_cq_read() does NOT drain those bytes.
	// If we only call fi_cq_read(), the pipe stays readable and kqueue
	// fires again on every re-arm, creating a busy spin loop with zero
	// actual completions.
	//
	// Fix: loop until both CQs return EAGAIN AND the pipe is empty.
	// If new completions arrive in the race window between "last EAGAIN"
	// and "pipe drained", their pipe bytes are consumed here; their CQ
	// entries are found in the next inner CQ pass so no data is lost.
	do {
		found = false;

		// --- TX completions ---
		while ((n = fi_cq_read(p->tx_cq, cqe, 16)) > 0) {
			found = true;
			for (ssize_t i = 0; i < n; i++) {
				nni_mtx_lock(&p->mtx);
				nni_aio *aio = nni_list_first(&p->sendq);
				if (aio == NULL) {
					// Nego TX completion — absorb.
					nni_mtx_unlock(&p->mtx);
					continue;
				}
				nni_aio_list_remove(aio);
				nni_mtx_unlock(&p->mtx);

				nni_msg *msg = nni_aio_get_msg(aio);
				size_t   len = nni_msg_len(msg);
				nni_aio_set_msg(aio, NULL);
				nni_msg_free(msg);
				nni_pipe_bump_tx(p->npipe, len);
				nni_aio_finish_sync(aio, 0, len);

				nni_mtx_lock(&p->mtx);
				ofi_pipe_do_send(p);
				nni_mtx_unlock(&p->mtx);
			}
		}
		if (n == -FI_EAVAIL) {
			fi_cq_readerr(p->tx_cq, &cq_err, 0);
			nng_log_warn("NNG-OFI",
			    "TX CQ error: prov_errno=%d err=%d",
			    cq_err.prov_errno, cq_err.err);
			nni_pipe_close(p->npipe);
			return;
		}
		if (n < 0 && n != -FI_EAGAIN) {
			nni_pipe_close(p->npipe);
			return;
		}

		// --- RX completions ---
		while ((n = fi_cq_read(p->rx_cq, cqe, 16)) > 0) {
			found = true;
			for (ssize_t i = 0; i < n; i++) {
				nni_mtx_lock(&p->mtx);
				bool nego_done = (p->peer != 0);
				nni_mtx_unlock(&p->mtx);

				if (!nego_done) {
					// Negotiation RX.
					struct iovec  rx_iov;
					struct fi_msg rx_msg;
					memcpy(p->rx_nego, p->rx_buf,
					    OFI_NEGO_SZ);
					ofi_pipe_nego_complete(p, true);
					// Re-post RX for data phase.
					rx_iov.iov_base = p->rx_buf;
					rx_iov.iov_len  = OFI_BOUNCE_SZ;
					memset(&rx_msg, 0, sizeof(rx_msg));
					rx_msg.msg_iov   = &rx_iov;
					rx_msg.desc      = fi_mr_desc(p->rx_mr);
					rx_msg.iov_count = 1;
					rx_msg.addr      = FI_ADDR_UNSPEC;
					fi_recvmsg(p->ep, &rx_msg, 0);
					continue;
				}

				// Data message framing: [uint64 len][payload].
				uint64_t msglen;
				NNI_GET64((uint8_t *) p->rx_buf, msglen);
				if (msglen > (uint64_t)(OFI_BOUNCE_SZ - 8)) {
					nni_pipe_close(p->npipe);
					continue;
				}

				nni_msg *msg;
				if (nni_msg_alloc(&msg, (size_t) msglen) != 0) {
					nni_pipe_close(p->npipe);
					continue;
				}
				memcpy(nni_msg_body(msg),
				    (uint8_t *) p->rx_buf + 8,
				    (size_t) msglen);

				nni_mtx_lock(&p->mtx);
				nni_aio *aio = nni_list_first(&p->recvq);
				if (aio != NULL) {
					nni_aio_list_remove(aio);
				}
				nni_mtx_unlock(&p->mtx);

				if (aio != NULL) {
					nni_pipe_bump_rx(p->npipe,
					    (size_t) msglen);
					nni_aio_set_msg(aio, msg);
					nni_aio_finish_sync(aio, 0,
					    (size_t) msglen);

					// Re-post RX buffer.
					struct iovec  rx_iov;
					struct fi_msg rx_msg;
					rx_iov.iov_base = p->rx_buf;
					rx_iov.iov_len  = OFI_BOUNCE_SZ;
					memset(&rx_msg, 0, sizeof(rx_msg));
					rx_msg.msg_iov   = &rx_iov;
					rx_msg.desc      = fi_mr_desc(p->rx_mr);
					rx_msg.iov_count = 1;
					rx_msg.addr      = FI_ADDR_UNSPEC;
					fi_recvmsg(p->ep, &rx_msg, 0);
				} else {
					nni_mtx_lock(&p->mtx);
					p->rx_msg_cache = msg;
					nni_mtx_unlock(&p->mtx);
				}
			}
		}
		if (n == -FI_EAVAIL) {
			fi_cq_readerr(p->rx_cq, &cq_err, 0);
			nng_log_warn("NNG-OFI",
			    "RX CQ error: prov_errno=%d err=%d",
			    cq_err.prov_errno, cq_err.err);
			nni_pipe_close(p->npipe);
			return;
		} else if (n < 0 && n != -FI_EAGAIN) {
			nni_pipe_close(p->npipe);
			return;
		}

		// --- Drain the notification pipe ---
		// The XNET provider writes one byte per completion; fi_cq_read()
		// leaves those bytes in the pipe.  Read them out so kqueue won't
		// re-fire spuriously on the next arm().  If the read returns data,
		// completions may have raced in — loop to catch them.
		{
			char    buf[64];
			ssize_t r;
			while ((r = read(wait_fd, buf, sizeof(buf))) > 0) {
				found = true;
			}
			if (r < 0 && errno != EAGAIN) {
				nng_log_warn("NNG-OFI", "read error: %s (fd=%d)\n", strerror(errno), wait_fd);
			}
			(void) r; // EAGAIN / EWOULDBLOCK means empty
		}

	} while (found);
}

static void
ofi_cq_pfd_cb(void *arg, unsigned events)
{
	(void) events;
	ofi_pipe *p = arg;
	ofi_pipe_drain_cqs(p);
	nni_posix_pfd_arm(&p->cq_pfd, POLLIN);
}

// ── Pipe allocation helper ────────────────────────────────────────────────
//
// Called from the EQ thread when a connection is established.
// Takes ownership of fid_ep, tx_cq, rx_cq (already bound and enabled).
// Allocates the NNG pipe, registers bounce buffers, pre-posts an RX,
// starts the CQ thread, and sends our SP negotiation header.

static nng_err
ofi_pipe_alloc(ofi_ep *ep, struct fid_ep *fid_ep, struct fid_cq *tx_cq,
    struct fid_cq *rx_cq, bool is_dialer)
{
	void     *p_data;
	ofi_pipe *p;
	int       rv;

	// Allocate NNG pipe — calls p_init, giving us p_data = ofi_pipe*.
	if (is_dialer) {
		rv = nni_pipe_alloc_dialer(&p_data, ep->ndialer);
	} else {
		rv = nni_pipe_alloc_listener(&p_data, ep->nlistener);
	}
	if (rv != 0) {
		fi_close(&fid_ep->fid);
		fi_close(&tx_cq->fid);
		fi_close(&rx_cq->fid);
		return (rv);
	}

	p         = p_data;
	p->oep    = ep;
	p->ep     = fid_ep;
	p->tx_cq  = tx_cq;
	p->rx_cq  = rx_cq;
	p->proto  = ep->proto;

	// Allocate bounce buffers.
	p->tx_buf = nni_alloc(OFI_BOUNCE_SZ);
	p->rx_buf = nni_alloc(OFI_BOUNCE_SZ);
	if (p->tx_buf == NULL || p->rx_buf == NULL) {
		goto fail_nomem;
	}

	// Register TX buffer for SEND access.
	rv = fi_mr_reg(ofi_domain, p->tx_buf, OFI_BOUNCE_SZ, FI_SEND, 0, 0,
	    0, &p->tx_mr, NULL);
	if (rv != 0) {
		goto fail;
	}

	// Register RX buffer for RECV access.
	rv = fi_mr_reg(ofi_domain, p->rx_buf, OFI_BOUNCE_SZ, FI_RECV, 0, 0,
	    0, &p->rx_mr, NULL);
	if (rv != 0) {
		goto fail;
	}


	// Pre-post the RX buffer so the peer's nego header can arrive.
	{
		struct iovec  iov;
		struct fi_msg msg;
		iov.iov_base = p->rx_buf;
		iov.iov_len  = OFI_BOUNCE_SZ;
		memset(&msg, 0, sizeof(msg));
		msg.msg_iov   = &iov;
		msg.desc      = fi_mr_desc(p->rx_mr);
		msg.iov_count = 1;
		msg.addr      = FI_ADDR_UNSPEC;
		fi_recvmsg(fid_ep, &msg, 0);
	}

	// Start the CQ polling thread (drives nego, then data in Task 5).
	int wait_fd = -1;
	fi_control(&p->rx_cq->fid, FI_GETWAIT, &wait_fd);
	nni_posix_pfd_init(&p->cq_pfd, wait_fd, ofi_cq_pfd_cb, p);
	nni_posix_pfd_arm(&p->cq_pfd, POLLIN);

	// Send our SP negotiation header (queued on the EP until connected).
	ofi_pipe_nego_start(p);
	return (NNG_OK);

fail_nomem:
	rv = NNG_ENOMEM;
fail:
	// p_fini will be called by NNG; it frees what's non-NULL.
	nni_pipe_close(p->npipe);
	return (rv);
}

// ── Unified EQ thread ─────────────────────────────────────────────────────
//
// For a listener: polls pep EQ for FI_CONNREQ events.
// For a dialer:   polls active-ep EQ for FI_CONNECTED event.
// Both use the same code path for simplicity.

static void
ofi_ep_eq_thread(void *arg)
{
	ofi_ep               *ep = arg;
	struct fi_eq_cm_entry entry;
	struct fi_eq_err_entry err_entry;
	uint32_t               event;
	ssize_t                n;
	int                    rv;
	int                    iteration = 0;


	for (;;) {
		nni_mtx_lock(&ep->mtx);
		if (ep->closed) {
			nni_mtx_unlock(&ep->mtx);
			return;
		}
		nni_mtx_unlock(&ep->mtx);

		// Block up to 10 ms so shutdown latency is bounded.
		n = fi_eq_sread(ep->eq, &event, &entry, sizeof(entry), 10, 0);
		iteration++;
		if (iteration <= 5 || (iteration % 50) == 0) {
		}

		if (n == -FI_EAGAIN || n == -FI_ETIMEDOUT || n == 0) {
			continue;
		}
		if (n == -FI_EAVAIL) {
			fi_eq_readerr(ep->eq, &err_entry, 0);
			nng_log_warn("NNG-OFI", "EQ error: prov_errno=%d",
			    err_entry.prov_errno);
			nni_mtx_lock(&ep->mtx);
			nni_aio *aio = ep->useraio;
			ep->useraio  = NULL;
			nni_mtx_unlock(&ep->mtx);
			if (aio != NULL) {
				nni_aio_finish_error(aio, ofi_err(-err_entry.err));
			}
			continue;
		}
		if (n < 0) {
			// Unrecoverable (e.g., fabric closed).
			nni_mtx_lock(&ep->mtx);
			nni_aio *aio = ep->useraio;
			ep->useraio  = NULL;
			nni_mtx_unlock(&ep->mtx);
			if (aio != NULL) {
				nni_aio_finish_error(aio, ofi_err(n));
			}
			return;
		}


		if (event == FI_CONNREQ) {
			// ── Listener: accept incoming connection ──────────
			struct fi_info *req_info = entry.info;
			struct fid_ep  *new_ep   = NULL;
			struct fid_cq  *tx_cq    = NULL;
			struct fid_cq  *rx_cq    = NULL;
			struct fi_cq_attr cq_attr = {
				.size     = 64,
				.format   = FI_CQ_FORMAT_MSG,
				.wait_obj = FI_WAIT_FD,			};

			rv = fi_endpoint(
			    ofi_domain, req_info, &new_ep, NULL);
			if (rv != 0) {
				nng_log_warn("NNG-OFI",
				    "fi_endpoint failed: %s",
				    fi_strerror(-rv));
				fi_reject(ep->pep, req_info->handle, NULL, 0);
				fi_freeinfo(req_info);
				continue;
			}

			// Bind the same EQ so FI_CONNECTED/SHUTDOWN arrives.
			fi_ep_bind(new_ep, &ep->eq->fid, 0);

			// Create and bind TX/RX CQs.
			if ((rv = fi_cq_open(
			         ofi_domain, &cq_attr, &tx_cq, NULL)) != 0 ||
			    (rv = fi_cq_open(
			         ofi_domain, &cq_attr, &rx_cq, NULL)) != 0 ||
			    (rv = fi_ep_bind(
			         new_ep, &tx_cq->fid, FI_TRANSMIT)) != 0 ||
			    (rv = fi_ep_bind(
			         new_ep, &rx_cq->fid, FI_RECV)) != 0 ||
			    (rv = fi_enable(new_ep)) != 0) {
				nng_log_warn("NNG-OFI",
				    "listener EP setup failed: %s",
				    fi_strerror(-rv));
				if (tx_cq != NULL)
					fi_close(&tx_cq->fid);
				if (rx_cq != NULL)
					fi_close(&rx_cq->fid);
				fi_close(&new_ep->fid);
				fi_reject(ep->pep, req_info->handle, NULL, 0);
				fi_freeinfo(req_info);
				continue;
			}

			// Accept the connection (triggers FI_CONNECTED on EQ).
			fi_accept(new_ep, NULL, 0);
			fi_freeinfo(req_info);

			// Allocate the NNG pipe and start nego.
			// Sends/recvs posted now will complete after CONNECTED.
			ofi_pipe_alloc(ep, new_ep, tx_cq, rx_cq, false);

		} else if (event == FI_CONNECTED && ep->is_dialer) {
			// ── Dialer: connection established ────────────────
			struct fid_ep *fid_ep;
			struct fid_cq *tx_cq;
			struct fid_cq *rx_cq;

			nni_mtx_lock(&ep->mtx);
			fid_ep         = ep->dial_ep;
			tx_cq          = ep->dial_tx_cq;
			rx_cq          = ep->dial_rx_cq;
			ep->dial_ep    = NULL;
			ep->dial_tx_cq = NULL;
			ep->dial_rx_cq = NULL;
			nni_mtx_unlock(&ep->mtx);

			if (fid_ep != NULL) {
				ofi_pipe_alloc(ep, fid_ep, tx_cq, rx_cq, true);
			}

		} else if (event == FI_SHUTDOWN) {
			// Remote disconnected; pipe teardown handled by CQ
			// thread (Task 5).
		}
		// FI_CONNECTED events for listener-accepted EPs are benign;
		// we do nothing — the pipe is already being set up via alloc.
	}
}

// ── Listener ops ──────────────────────────────────────────────────────────

static nng_err
ofi_listener_init(void *arg, nng_url *url, nni_listener *nlistener)
{
	ofi_ep         *ep = arg;
	struct fi_info *hints;
	struct fi_info *info = NULL;
	char            svcbuf[8];
	int             rv;
	struct fi_eq_attr eq_attr = {
		.size     = 256,
		.wait_obj = FI_WAIT_UNSPEC,
	};

	memset(ep, 0, sizeof(*ep));
	nni_mtx_init(&ep->mtx);
	NNI_LIST_INIT(&ep->waitpipes, ofi_pipe, node);
	ep->nlistener = nlistener;
	ep->is_dialer = false;
	ep->proto     = nni_sock_proto_id(nni_listener_sock(nlistener));

	if (ofi_fabric == NULL) {
		// Global init failed (no provider available).
		return (NNG_ENOTSUP);
	}

	(void) snprintf(svcbuf, sizeof(svcbuf), "%u", url->u_port);

	// Use fresh hints (not fi_dupinfo) to avoid provider-filled fields
	// like src_addr/dest_addr in ofi_base_info polluting the request.
	hints = fi_allocinfo();
	if (hints == NULL) {
		return (NNG_ENOMEM);
	}
	hints->ep_attr->type = FI_EP_MSG;
	hints->caps          = FI_MSG;
	hints->mode          = 0;
	if (ofi_base_info->fabric_attr->prov_name != NULL) {
		hints->fabric_attr->prov_name =
		    strdup(ofi_base_info->fabric_attr->prov_name);
	}

	rv = fi_getinfo(FI_VERSION(1, 11),
	    (strlen(url->u_hostname) > 0) ? url->u_hostname : NULL, svcbuf,
	    FI_SOURCE, hints, &info);
	fi_freeinfo(hints);
	if (rv != 0) {
		return (ofi_err(rv));
	}

	rv = fi_passive_ep(ofi_fabric, info, &ep->pep, NULL);
	fi_freeinfo(info);
	if (rv != 0) {
		return (ofi_err(rv));
	}

	rv = fi_eq_open(ofi_fabric, &eq_attr, &ep->eq, NULL);
	if (rv != 0) {
		fi_close(&ep->pep->fid);
		ep->pep = NULL;
		return (ofi_err(rv));
	}

	rv = fi_pep_bind(ep->pep, &ep->eq->fid, 0);
	if (rv != 0) {
		fi_close(&ep->eq->fid);
		fi_close(&ep->pep->fid);
		ep->eq  = NULL;
		ep->pep = NULL;
		return (ofi_err(rv));
	}

	return (NNG_OK);
}

static void
ofi_listener_fini(void *arg)
{
	ofi_ep *ep = arg;
	if (ep->pep != NULL) {
		fi_close(&ep->pep->fid);
		ep->pep = NULL;
	}
	if (ep->eq != NULL) {
		fi_close(&ep->eq->fid);
		ep->eq = NULL;
	}
	nni_mtx_fini(&ep->mtx);
}

static nng_err
ofi_listener_bind(void *arg, nng_url *url)
{
	ofi_ep *ep = arg;
	int     rv;

	rv = fi_listen(ep->pep);
	if (rv != 0) {
		return (ofi_err(rv));
	}

	// After fi_listen the OS assigns an ephemeral port if url->u_port
	// was 0.  Retrieve the actual bound address so that callers of
	// nng_listener_get_url() see the real port number.
	if (url->u_port == 0) {
		struct sockaddr_storage ss;
		size_t                  addrlen = sizeof(ss);
		if (fi_getname(&ep->pep->fid, &ss, &addrlen) == 0) {
			if (ss.ss_family == AF_INET) {
				url->u_port = ntohs(
				    ((struct sockaddr_in *) &ss)->sin_port);
			} else if (ss.ss_family == AF_INET6) {
				url->u_port = ntohs(
				    ((struct sockaddr_in6 *) &ss)->sin6_port);
			}
		}
	}

	rv = nni_thr_init(&ep->eq_thr, ofi_ep_eq_thread, ep);
	if (rv != 0) {
		return (rv);
	}
	ep->eq_thr_started = true;
	nni_thr_run(&ep->eq_thr);
	return (NNG_OK);
}

static void
ofi_listener_accept_cancel(nni_aio *aio, void *arg, nng_err rv)
{
	ofi_ep *ep = arg;
	nni_mtx_lock(&ep->mtx);
	if (ep->useraio == aio) {
		ep->useraio = NULL;
		nni_mtx_unlock(&ep->mtx);
		nni_aio_finish_error(aio, rv);
		return;
	}
	nni_mtx_unlock(&ep->mtx);
}

static void
ofi_listener_accept(void *arg, nni_aio *aio)
{
	ofi_ep   *ep = arg;
	ofi_pipe *p;

	nni_aio_reset(aio);
	nni_mtx_lock(&ep->mtx);
	if (ep->closed) {
		nni_mtx_unlock(&ep->mtx);
		nni_aio_finish_error(aio, NNG_ECLOSED);
		return;
	}
	if (!nni_aio_start(aio, ofi_listener_accept_cancel, ep)) {
		nni_mtx_unlock(&ep->mtx);
		return;
	}
	if (ep->useraio != NULL) {
		nni_mtx_unlock(&ep->mtx);
		nni_aio_finish_error(aio, NNG_EBUSY);
		return;
	}
	if ((p = nni_list_first(&ep->waitpipes)) != NULL) {
		nni_list_remove(&ep->waitpipes, p);
		nni_mtx_unlock(&ep->mtx);
		nni_aio_set_output(aio, 0, p->npipe);
		nni_aio_finish(aio, 0, 0);
		return;
	}
	// No pipe ready yet — save AIO for when one arrives.
	ep->useraio = aio;
	nni_mtx_unlock(&ep->mtx);
}

static void
ofi_listener_close(void *arg)
{
	ofi_ep  *ep = arg;
	nni_aio *aio;

	nni_mtx_lock(&ep->mtx);
	ep->closed  = true;
	aio         = ep->useraio;
	ep->useraio = NULL;
	nni_mtx_unlock(&ep->mtx);

	if (aio != NULL) {
		nni_aio_finish_error(aio, NNG_ECLOSED);
	}
}

static void
ofi_listener_stop(void *arg)
{
	ofi_ep *ep = arg;
	ofi_listener_close(ep);
	if (ep->eq_thr_started) {
		nni_thr_fini(&ep->eq_thr);
		ep->eq_thr_started = false;
	}
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
	.l_size   = sizeof(ofi_ep),
	.l_init   = ofi_listener_init,
	.l_fini   = ofi_listener_fini,
	.l_bind   = ofi_listener_bind,
	.l_accept = ofi_listener_accept,
	.l_close  = ofi_listener_close,
	.l_stop   = ofi_listener_stop,
	.l_getopt = ofi_listener_getopt,
	.l_setopt = ofi_listener_setopt,
};

// ── Dialer ops ────────────────────────────────────────────────────────────

static nng_err
ofi_dialer_init(void *arg, nng_url *url, nni_dialer *ndialer)
{
	ofi_ep         *ep = arg;
	struct fi_info *hints;
	struct fi_info *info = NULL;
	char            svcbuf[8];
	int             rv;
	struct fi_eq_attr eq_attr = {
		.size     = 64,
		.wait_obj = FI_WAIT_UNSPEC,
	};

	memset(ep, 0, sizeof(*ep));
	nni_mtx_init(&ep->mtx);
	NNI_LIST_INIT(&ep->waitpipes, ofi_pipe, node);
	ep->ndialer   = ndialer;
	ep->is_dialer = true;
	ep->proto     = nni_sock_proto_id(nni_dialer_sock(ndialer));

	if (ofi_fabric == NULL) {
		return (NNG_ENOTSUP);
	}

	(void) snprintf(svcbuf, sizeof(svcbuf), "%u", url->u_port);

	hints = fi_allocinfo();
	if (hints == NULL) {
		return (NNG_ENOMEM);
	}
	hints->ep_attr->type = FI_EP_MSG;
	hints->caps          = FI_MSG;
	hints->mode          = 0;
	if (ofi_base_info->fabric_attr->prov_name != NULL) {
		hints->fabric_attr->prov_name =
		    strdup(ofi_base_info->fabric_attr->prov_name);
	}

	// Resolve destination address (client-side, no FI_SOURCE).
	rv = fi_getinfo(FI_VERSION(1, 11),
	    url->u_hostname, svcbuf, 0, hints, &info);
	fi_freeinfo(hints);
	if (rv != 0) {
		return (ofi_err(rv));
	}

	// Save destination address for use in fi_connect.
	ep->dest_addr    = nni_alloc(info->dest_addrlen);
	ep->dest_addrlen = info->dest_addrlen;
	if (ep->dest_addr == NULL) {
		fi_freeinfo(info);
		return (NNG_ENOMEM);
	}
	memcpy(ep->dest_addr, info->dest_addr, info->dest_addrlen);
	fi_freeinfo(info);

	// Create the CM event queue (for FI_CONNECTED / FI_SHUTDOWN).
	rv = fi_eq_open(ofi_fabric, &eq_attr, &ep->eq, NULL);
	if (rv != 0) {
		nni_free(ep->dest_addr, ep->dest_addrlen);
		ep->dest_addr = NULL;
		return (ofi_err(rv));
	}

	return (NNG_OK);
}

static void
ofi_dialer_fini(void *arg)
{
	ofi_ep *ep = arg;
	if (ep->dial_ep != NULL) {
		fi_close(&ep->dial_ep->fid);
		ep->dial_ep = NULL;
	}
	if (ep->dial_tx_cq != NULL) {
		fi_close(&ep->dial_tx_cq->fid);
		ep->dial_tx_cq = NULL;
	}
	if (ep->dial_rx_cq != NULL) {
		fi_close(&ep->dial_rx_cq->fid);
		ep->dial_rx_cq = NULL;
	}
	if (ep->eq != NULL) {
		fi_close(&ep->eq->fid);
		ep->eq = NULL;
	}
	if (ep->dest_addr != NULL) {
		nni_free(ep->dest_addr, ep->dest_addrlen);
		ep->dest_addr    = NULL;
		ep->dest_addrlen = 0;
	}
	nni_mtx_fini(&ep->mtx);
}

static void
ofi_dialer_connect_cancel(nni_aio *aio, void *arg, nng_err rv)
{
	ofi_ep *ep = arg;
	nni_mtx_lock(&ep->mtx);
	if (ep->useraio == aio) {
		ep->useraio = NULL;
		nni_mtx_unlock(&ep->mtx);
		nni_aio_finish_error(aio, rv);
		return;
	}
	nni_mtx_unlock(&ep->mtx);
}

static void
ofi_dialer_connect(void *arg, nni_aio *aio)
{
	ofi_ep           *ep = arg;
	struct fid_ep    *fid_ep   = NULL;
	struct fid_cq    *tx_cq    = NULL;
	struct fid_cq    *rx_cq    = NULL;
	struct fi_cq_attr cq_attr  = {
		.size     = 64,
		.format   = FI_CQ_FORMAT_MSG,
		.wait_obj = FI_WAIT_FD,	};
	int rv;

	nni_aio_reset(aio);
	nni_mtx_lock(&ep->mtx);
	if (ep->closed) {
		nni_mtx_unlock(&ep->mtx);
		nni_aio_finish_error(aio, NNG_ECLOSED);
		return;
	}
	if (!nni_aio_start(aio, ofi_dialer_connect_cancel, ep)) {
		nni_mtx_unlock(&ep->mtx);
		return;
	}
	if (ep->useraio != NULL) {
		nni_mtx_unlock(&ep->mtx);
		nni_aio_finish_error(aio, NNG_EBUSY);
		return;
	}
	ep->useraio = aio;
	nni_mtx_unlock(&ep->mtx);

	// Create active endpoint.
	rv = fi_endpoint(ofi_domain, ofi_base_info, &fid_ep, NULL);
	if (rv != 0) {
		goto fail;
	}

	// Bind EQ for CM events (FI_CONNECTED, FI_SHUTDOWN).
	rv = fi_ep_bind(fid_ep, &ep->eq->fid, 0);
	if (rv != 0) {
		goto fail;
	}

	// Create and bind TX/RX CQs before fi_enable.
	if ((rv = fi_cq_open(ofi_domain, &cq_attr, &tx_cq, NULL)) != 0 ||
	    (rv = fi_cq_open(ofi_domain, &cq_attr, &rx_cq, NULL)) != 0 ||
	    (rv = fi_ep_bind(fid_ep, &tx_cq->fid, FI_TRANSMIT)) != 0 ||
	    (rv = fi_ep_bind(fid_ep, &rx_cq->fid, FI_RECV)) != 0) {
		goto fail;
	}

	// Enable and initiate the connection.
	if ((rv = fi_enable(fid_ep)) != 0 ||
	    (rv = fi_connect(fid_ep, ep->dest_addr, NULL, 0)) != 0) {
		goto fail;
	}

	// Store in-progress connection state; EQ thread takes over on
	// FI_CONNECTED.
	nni_mtx_lock(&ep->mtx);
	ep->dial_ep    = fid_ep;
	ep->dial_tx_cq = tx_cq;
	ep->dial_rx_cq = rx_cq;
	nni_mtx_unlock(&ep->mtx);

	// Start the EQ thread to wait for FI_CONNECTED.
	if (!ep->eq_thr_started) {
		rv = nni_thr_init(&ep->eq_thr, ofi_ep_eq_thread, ep);
		if (rv != 0) {
			nni_mtx_lock(&ep->mtx);
			ep->dial_ep    = NULL;
			ep->dial_tx_cq = NULL;
			ep->dial_rx_cq = NULL;
			nni_mtx_unlock(&ep->mtx);
			goto fail;
		}
		ep->eq_thr_started = true;
		nni_thr_run(&ep->eq_thr);
	}
	return;

fail:
	if (tx_cq != NULL) {
		fi_close(&tx_cq->fid);
	}
	if (rx_cq != NULL) {
		fi_close(&rx_cq->fid);
	}
	if (fid_ep != NULL) {
		fi_close(&fid_ep->fid);
	}
	nni_mtx_lock(&ep->mtx);
	ep->useraio = NULL;
	nni_mtx_unlock(&ep->mtx);
	nni_aio_finish_error(aio, ofi_err(rv));
}

static void
ofi_dialer_close(void *arg)
{
	ofi_ep  *ep = arg;
	nni_aio *aio;

	nni_mtx_lock(&ep->mtx);
	ep->closed  = true;
	aio         = ep->useraio;
	ep->useraio = NULL;
	nni_mtx_unlock(&ep->mtx);

	if (aio != NULL) {
		nni_aio_finish_error(aio, NNG_ECLOSED);
	}
}

static void
ofi_dialer_stop(void *arg)
{
	ofi_ep *ep = arg;
	ofi_dialer_close(ep);
	if (ep->eq_thr_started) {
		nni_thr_fini(&ep->eq_thr);
		ep->eq_thr_started = false;
	}
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
	.d_size    = sizeof(ofi_ep),
	.d_init    = ofi_dialer_init,
	.d_fini    = ofi_dialer_fini,
	.d_connect = ofi_dialer_connect,
	.d_close   = ofi_dialer_close,
	.d_stop    = ofi_dialer_stop,
	.d_getopt  = ofi_dialer_getopt,
	.d_setopt  = ofi_dialer_setopt,
};

// ── Transport registration ────────────────────────────────────────────────

static void
ofi_tran_init(void)
{
	struct fi_info *hints;
	int             rv;
	const char     *prov;

	nni_mtx_init(&ofi_global_mtx);

	hints = fi_allocinfo();
	if (hints == NULL) {
		nng_log_warn("NNG-OFI", "fi_allocinfo failed");
		return;
	}
	hints->ep_attr->type = FI_EP_MSG;
	hints->caps          = FI_MSG;
	hints->mode          = 0;

	// Provider selection: env var > compile-time default > auto-detect.
	prov = getenv("NNG_OFI_PROVIDER");
#ifdef NNG_OFI_DEFAULT_PROVIDER
	if (prov == NULL) {
		prov = NNG_OFI_DEFAULT_PROVIDER;
	}
#endif
	if (prov != NULL && prov[0] != '\0') {
		hints->fabric_attr->prov_name = strdup(prov);
	}

	rv = fi_getinfo(FI_VERSION(FI_MAJOR_VERSION, FI_MINOR_VERSION), NULL,
	    NULL, 0, hints, &ofi_base_info);
	fi_freeinfo(hints);
	if (rv != 0) {
		nng_log_warn(
		    "NNG-OFI", "fi_getinfo failed: %s", fi_strerror(-rv));
		return;
	}

	rv = fi_fabric2(ofi_base_info, &ofi_fabric, 0, NULL);
	if (rv != 0) {
		nng_log_warn(
		    "NNG-OFI", "fi_fabric2 failed: %s", fi_strerror(-rv));
		fi_freeinfo(ofi_base_info);
		ofi_base_info = NULL;
		return;
	}

	rv = fi_domain(ofi_fabric, ofi_base_info, &ofi_domain, NULL);
	if (rv != 0) {
		nng_log_warn(
		    "NNG-OFI", "fi_domain failed: %s", fi_strerror(-rv));
		fi_close(&ofi_fabric->fid);
		fi_freeinfo(ofi_base_info);
		ofi_fabric    = NULL;
		ofi_base_info = NULL;
		return;
	}

	nng_log_info("NNG-OFI", "Initialized provider: %s",
	    ofi_base_info->fabric_attr->prov_name);
}

static void
ofi_tran_fini(void)
{
	if (ofi_domain != NULL) {
		fi_close(&ofi_domain->fid);
		ofi_domain = NULL;
	}
	if (ofi_fabric != NULL) {
		fi_close(&ofi_fabric->fid);
		ofi_fabric = NULL;
	}
	if (ofi_base_info != NULL) {
		fi_freeinfo(ofi_base_info);
		ofi_base_info = NULL;
	}
	nni_mtx_fini(&ofi_global_mtx);
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
