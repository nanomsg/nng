// Copyright 2026 - OFI/libfabric transport for NNG (EXPERIMENTAL)
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).

#include "../../../core/nng_impl.h"
#include "../../transport.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <netinet/in.h>
#include <rdma/fabric.h>
#include <rdma/fi_cm.h>
#include <rdma/fi_domain.h>
#include <rdma/fi_endpoint.h>
#include <rdma/fi_errno.h>
#include "platform/posix/posix_pollq.h"

#ifndef NNG_OFI_DEFAULT_PROVIDER
#define NNG_OFI_DEFAULT_PROVIDER "tcp"
#endif

typedef struct ofi_pipe ofi_pipe;
typedef struct ofi_ep   ofi_ep;

#define OFI_BOUNCE_SZ (1024 * 1024)
#define OFI_NEGO_SZ 8

static struct fid_fabric *ofi_fabric;
static struct fid_domain *ofi_domain;
static struct fi_info    *ofi_base_info;
static enum fi_ep_type    ofi_ep_type;
static nni_mtx            ofi_global_mtx;
static bool               ofi_mtx_inited = false;

struct ofi_ep {
	struct fid_pep *pep;
	struct fid_ep  *ep;
	struct fid_av  *av;
	struct fid_eq  *eq;
	bool           is_dialer;
	uint16_t       proto;
	bool           closed;
	bool           eq_thr_started;
	nni_aio       *useraio;
	nni_list       waitpipes;
	nni_listener  *nlistener;
	nni_dialer    *ndialer;
	nni_mtx        mtx;
	nni_thr        eq_thr;
	struct fid_ep *dial_ep;
	struct fid_cq *dial_tx_cq;
	struct fid_cq *dial_rx_cq;
	void          *dest_addr;
	size_t         dest_addrlen;
};

struct ofi_pipe {
	ofi_ep       *oep;
	nni_pipe     *npipe;
	uint16_t      peer;
	uint16_t      proto;
	bool          closed;
	nni_posix_pfd cq_pfd;
	nni_list_node node;
	fi_addr_t     addr;
	struct fid_ep *ep;
	struct fid_cq *tx_cq;
	struct fid_cq *rx_cq;
	struct fid_mr *tx_mr;
	struct fid_mr *rx_mr;
	void          *tx_buf;
	void          *rx_buf;
	uint8_t tx_nego[OFI_NEGO_SZ];
	uint8_t rx_nego[OFI_NEGO_SZ];
	nni_msg *rx_msg_cache;
	nni_list sendq;
	nni_list recvq;
	nni_mtx  mtx;
};

static nng_err
ofi_err(ssize_t rv)
{
	if (rv == 0) return (NNG_OK);
	switch ((int) -rv) {
	case ENOTSUP: return (NNG_ENOTSUP);
	case EADDRINUSE: return (NNG_EADDRINUSE);
	case ECONNREFUSED: return (NNG_ECONNREFUSED);
	case ETIMEDOUT: return (NNG_ETIMEDOUT);
	case EACCES: return (NNG_EPERM);
	case ENOMEM: return (NNG_ENOMEM);
	case EINVAL: return (NNG_EINVAL);
	case EMSGSIZE: return (NNG_EMSGSIZE);
	case EINTR: return (NNG_EINTR);
	case EBADF: return (NNG_ECLOSED);
	default: return (NNG_ETRANERR);
	}
}

static void ofi_pipe_drain_cqs(ofi_pipe *);
static void ofi_cq_pfd_cb(void *arg, unsigned events) {
	(void) events;
	ofi_pipe_drain_cqs(arg);
	nni_posix_pfd_arm(&((ofi_pipe*)arg)->cq_pfd, POLLIN);
}

static void ofi_pipe_nego_complete(ofi_pipe *p, bool success) {
	ofi_ep *ep = p->oep;
	nni_aio *aio;
	if (!success) {
		nni_pipe_close(p->npipe);
		return;
	}
	p->peer = NNI_GET16(&p->rx_nego[4], p->peer);
	nni_mtx_lock(&ep->mtx);
	aio = ep->useraio;
	if (aio != NULL) {
		ep->useraio = NULL;
		nni_mtx_unlock(&ep->mtx);
		nni_aio_set_output(aio, 0, p->npipe);
		nni_aio_finish(aio, 0, 0);
	} else {
		nni_list_append(&ep->waitpipes, p);
		nni_mtx_unlock(&ep->mtx);
	}
}

static void ofi_pipe_do_send(ofi_pipe *p) {
	nni_aio *aio = nni_list_first(&p->sendq);
	if (!aio) return;
	nni_msg *msg = nni_aio_get_msg(aio);
	size_t hlen = nni_msg_header_len(msg);
	size_t blen = nni_msg_len(msg);
	size_t total = hlen + blen;
	NNI_PUT64((uint8_t *) p->tx_buf, (uint64_t) total);
	memcpy((uint8_t *) p->tx_buf + 8, nni_msg_header(msg), hlen);
	memcpy((uint8_t *) p->tx_buf + 8 + hlen, nni_msg_body(msg), blen);
	struct iovec iov = { .iov_base = p->tx_buf, .iov_len = total + 8 };
	struct fi_msg fmsg = {
		.msg_iov = &iov, .iov_count = 1, .desc = fi_mr_desc(p->tx_mr),
		.addr = (ofi_ep_type == FI_EP_RDM) ? p->addr : FI_ADDR_UNSPEC,
		.context = aio
	};
	int rv = fi_sendmsg(p->ep, &fmsg, 0);
	if (rv != 0) {
		nni_aio_list_remove(aio);
		nni_mtx_unlock(&p->mtx);
		nni_aio_finish_error(aio, ofi_err(rv));
		nni_mtx_lock(&p->mtx);
	}
}

static void ofi_pipe_nego_start(ofi_pipe *p) {
	NNI_PUT32(p->tx_nego, 0x00535000);
	NNI_PUT16(&p->tx_nego[4], p->proto);
	NNI_PUT16(&p->tx_nego[6], 0);
	struct iovec iov = { .iov_base = p->tx_nego, .iov_len = OFI_NEGO_SZ };
	struct fi_msg fmsg = {
		.msg_iov = &iov, .iov_count = 1, .desc = fi_mr_desc(p->tx_mr),
		.addr = (ofi_ep_type == FI_EP_RDM) ? p->addr : FI_ADDR_UNSPEC
	};
	fi_sendmsg(p->ep, &fmsg, 0);
}

static void ofi_pipe_drain_cqs(ofi_pipe *p) {
	struct fi_cq_msg_entry cqe[16];
	ssize_t n;
	int wait_fd = nni_posix_pfd_fd(&p->cq_pfd);
	bool found;
	do {
		found = false;
		while ((n = fi_cq_read(p->tx_cq, cqe, 16)) > 0) {
			found = true;
			for (ssize_t i = 0; i < n; i++) {
				nni_aio *aio = cqe[i].op_context;
				if (!aio) continue;
				nni_mtx_lock(&p->mtx);
				nni_aio_list_remove(aio);
				nni_mtx_unlock(&p->mtx);
				nni_msg *msg = nni_aio_get_msg(aio);
				size_t len = nni_msg_len(msg);
				nni_aio_set_msg(aio, NULL);
				nni_msg_free(msg);
				nni_pipe_bump_tx(p->npipe, len);
				nni_aio_finish_sync(aio, 0, len);
				nni_mtx_lock(&p->mtx);
				ofi_pipe_do_send(p);
				nni_mtx_unlock(&p->mtx);
			}
		}
		while ((n = fi_cq_read(p->rx_cq, cqe, 16)) > 0) {
			found = true;
			for (ssize_t i = 0; i < n; i++) {
				nni_mtx_lock(&p->mtx);
				bool nego_done = (p->peer != 0);
				nni_mtx_unlock(&p->mtx);
				if (!nego_done) {
					memcpy(p->rx_nego, p->rx_buf, OFI_NEGO_SZ);
					ofi_pipe_nego_complete(p, true);
					struct iovec iov = { .iov_base = p->rx_buf, .iov_len = OFI_BOUNCE_SZ };
					struct fi_msg fmsg = {
						.msg_iov = &iov, .iov_count = 1, .desc = fi_mr_desc(p->rx_mr),
						.addr = (ofi_ep_type == FI_EP_RDM) ? p->addr : FI_ADDR_UNSPEC
					};
					fi_recvmsg(p->ep, &fmsg, 0);
					continue;
				}
				uint64_t msglen;
				NNI_GET64(p->rx_buf, msglen);
				nni_msg *msg;
				nni_msg_alloc(&msg, (size_t)msglen);
				memcpy(nni_msg_body(msg), (uint8_t*)p->rx_buf + 8, (size_t)msglen);
				nni_mtx_lock(&p->mtx);
				nni_aio *aio = nni_list_first(&p->recvq);
				if (aio) nni_aio_list_remove(aio);
				nni_mtx_unlock(&p->mtx);
				if (aio) {
					nni_pipe_bump_rx(p->npipe, (size_t)msglen);
					nni_aio_set_msg(aio, msg);
					nni_aio_finish_sync(aio, 0, (size_t)msglen);
					struct iovec iov = { .iov_base = p->rx_buf, .iov_len = OFI_BOUNCE_SZ };
					struct fi_msg fmsg = {
						.msg_iov = &iov, .iov_count = 1, .desc = fi_mr_desc(p->rx_mr),
						.addr = (ofi_ep_type == FI_EP_RDM) ? p->addr : FI_ADDR_UNSPEC
					};
					fi_recvmsg(p->ep, &fmsg, 0);
				} else {
					nni_mtx_lock(&p->mtx);
					p->rx_msg_cache = msg;
					nni_mtx_unlock(&p->mtx);
				}
			}
		}
		char buf[64];
		while (read(wait_fd, buf, sizeof(buf)) > 0) found = true;
	} while (found);
}

static nng_err ofi_pipe_alloc(ofi_ep *ep, struct fid_ep *fid_ep, struct fid_cq *tx_cq, struct fid_cq *rx_cq, bool is_dialer, fi_addr_t addr) {
	void *p_data;
	int rv = is_dialer ? nni_pipe_alloc_dialer(&p_data, ep->ndialer) : nni_pipe_alloc_listener(&p_data, ep->nlistener);
	if (rv != 0) return ofi_err(rv);
	ofi_pipe *p = p_data;
	p->oep = ep; p->ep = fid_ep; p->tx_cq = tx_cq; p->rx_cq = rx_cq; p->proto = ep->proto; p->addr = addr;
	p->tx_buf = nni_alloc(OFI_BOUNCE_SZ); p->rx_buf = nni_alloc(OFI_BOUNCE_SZ);
	fi_mr_reg(ofi_domain, p->tx_buf, OFI_BOUNCE_SZ, FI_SEND, 0, 0, 0, &p->tx_mr, NULL);
	fi_mr_reg(ofi_domain, p->rx_buf, OFI_BOUNCE_SZ, FI_RECV, 0, 0, 0, &p->rx_mr, NULL);
	struct iovec iov = { .iov_base = p->rx_buf, .iov_len = OFI_BOUNCE_SZ };
	struct fi_msg fmsg = { .msg_iov = &iov, .iov_count = 1, .desc = fi_mr_desc(p->rx_mr), .addr = (ofi_ep_type == FI_EP_RDM) ? p->addr : FI_ADDR_UNSPEC };
	fi_recvmsg(fid_ep, &fmsg, 0);
	int wait_fd = -1;
	fi_control(&p->rx_cq->fid, FI_GETWAIT, &wait_fd);
	nni_posix_pfd_init(&p->cq_pfd, wait_fd, ofi_cq_pfd_cb, p);
	nni_posix_pfd_arm(&p->cq_pfd, POLLIN);
	ofi_pipe_nego_start(p);
	return 0;
}

static void ofi_ep_eq_thread(void *arg) {
	ofi_ep *ep = arg;
	struct fi_eq_cm_entry entry;
	uint32_t event;
	while (!ep->closed) {
		ssize_t n = fi_eq_sread(ep->eq, &event, &entry, sizeof(entry), 10, 0);
		if (n <= 0) continue;
		if (event == FI_CONNREQ) {
			struct fi_info *req = entry.info;
			struct fid_ep *nep; struct fid_cq *tcq, *rcq;
			struct fi_cq_attr cattr = { .size = 64, .format = FI_CQ_FORMAT_MSG, .wait_obj = FI_WAIT_FD };
			fi_endpoint(ofi_domain, req, &nep, NULL);
			fi_ep_bind(nep, &ep->eq->fid, 0);
			fi_cq_open(ofi_domain, &cattr, &tcq, NULL);
			fi_cq_open(ofi_domain, &cattr, &rcq, NULL);
			fi_ep_bind(nep, &tcq->fid, FI_TRANSMIT);
			fi_ep_bind(nep, &rcq->fid, FI_RECV);
			fi_enable(nep);
			fi_accept(nep, NULL, 0);
			ofi_pipe_alloc(ep, nep, tcq, rcq, false, FI_ADDR_UNSPEC);
			fi_freeinfo(req);
		} else if (event == FI_CONNECTED && ep->is_dialer) {
			nni_mtx_lock(&ep->mtx);
			struct fid_ep *nep = ep->dial_ep; struct fid_cq *tcq = ep->dial_tx_cq, *rcq = ep->dial_rx_cq;
			ep->dial_ep = NULL; ep->dial_tx_cq = NULL; ep->dial_rx_cq = NULL;
			nni_mtx_unlock(&ep->mtx);
			if (nep) ofi_pipe_alloc(ep, nep, tcq, rcq, true, FI_ADDR_UNSPEC);
		}
	}
}

static int ofi_pipe_init(void *arg, nni_pipe *npipe) {
	ofi_pipe *p = arg; p->npipe = npipe; nni_mtx_init(&p->mtx);
	nni_aio_list_init(&p->sendq); nni_aio_list_init(&p->recvq); return 0;
}
static void ofi_pipe_fini(void *arg) {
	ofi_pipe *p = arg; if (p->tx_mr) fi_close(&p->tx_mr->fid); if (p->rx_mr) fi_close(&p->rx_mr->fid);
	if (p->ep) fi_close(&p->ep->fid); if (p->tx_cq) fi_close(&p->tx_cq->fid); if (p->rx_cq) fi_close(&p->rx_cq->fid);
	nni_free(p->tx_buf, OFI_BOUNCE_SZ); nni_free(p->rx_buf, OFI_BOUNCE_SZ); nni_mtx_fini(&p->mtx);
}
static void ofi_pipe_stop(void *arg) { ofi_pipe *p = arg; nni_posix_pfd_fini(&p->cq_pfd); }
static void ofi_pipe_close(void *arg) { ofi_pipe *p = arg; nni_mtx_lock(&p->mtx); p->closed = true; nni_mtx_unlock(&p->mtx); }
static void ofi_pipe_send(void *arg, nni_aio *aio) {
	ofi_pipe *p = arg; nni_aio_reset(aio); nni_mtx_lock(&p->mtx);
	nni_list_append(&p->sendq, aio); if (nni_list_first(&p->sendq) == aio) ofi_pipe_do_send(p);
	nni_mtx_unlock(&p->mtx);
}
static void ofi_pipe_recv(void *arg, nni_aio *aio) {
	ofi_pipe *p = arg; nni_aio_reset(aio); nni_mtx_lock(&p->mtx);
	if (p->rx_msg_cache) {
		nni_msg *m = p->rx_msg_cache; p->rx_msg_cache = NULL;
		nni_aio_set_msg(aio, m); nni_mtx_unlock(&p->mtx); nni_aio_finish(aio, 0, nni_msg_len(m)); return;
	}
	nni_list_append(&p->recvq, aio); nni_mtx_unlock(&p->mtx);
}
static size_t ofi_pipe_size(void) { return sizeof(ofi_pipe); }
static uint16_t ofi_pipe_peer(void *arg) { return ((ofi_pipe*)arg)->peer; }

static nni_sp_pipe_ops ofi_pipe_ops = {
	.p_size = ofi_pipe_size, .p_init = ofi_pipe_init, .p_fini = ofi_pipe_fini,
	.p_stop = ofi_pipe_stop, .p_close = ofi_pipe_close, .p_send = ofi_pipe_send, .p_recv = ofi_pipe_recv,
	.p_peer = ofi_pipe_peer
};

static void ofi_tran_init(void) {
	// NNG framework guarantees that this is called in a thread-safe manner
	// via the global transport initialization lock.
	if (!ofi_mtx_inited) {
		nni_mtx_init(&ofi_global_mtx);
		ofi_mtx_inited = true;
	}
	nni_mtx_lock(&ofi_global_mtx);
	if (ofi_fabric != NULL) {
		nni_mtx_unlock(&ofi_global_mtx);
		return;
	}
	struct fi_info *hints = fi_allocinfo();
	hints->ep_attr->type = getenv("NNG_OFI_FORCE_RDM") ? FI_EP_RDM : FI_EP_MSG;
	hints->caps = FI_MSG; hints->mode = FI_CONTEXT;
	hints->domain_attr->resource_mgmt = FI_RM_ENABLED; hints->domain_attr->threading = FI_THREAD_SAFE;
	if (!getenv("FI_PROVIDER")) hints->fabric_attr->prov_name = nni_strdup(NNG_OFI_DEFAULT_PROVIDER);
	int rv = fi_getinfo(FI_VERSION(1, 10), NULL, NULL, 0, hints, &ofi_base_info);
	if (rv != 0 && hints->ep_attr->type == FI_EP_MSG) {
		hints->ep_attr->type = FI_EP_RDM;
		rv = fi_getinfo(FI_VERSION(1, 10), NULL, NULL, 0, hints, &ofi_base_info);
	}
	fi_freeinfo(hints);
	if (rv == 0) {
		ofi_ep_type = ofi_base_info->ep_attr->type;
		fi_fabric(ofi_base_info->fabric_attr, &ofi_fabric, NULL);
		fi_domain(ofi_fabric, ofi_base_info, &ofi_domain, NULL);
	}
	nni_mtx_unlock(&ofi_global_mtx);
}
static void ofi_tran_fini(void) {}

static nng_err ofi_listener_init(void *arg, nng_url *url, nni_listener *nl) {
	ofi_ep *ep = arg; memset(ep, 0, sizeof(*ep)); nni_mtx_init(&ep->mtx);
	NNI_LIST_INIT(&ep->waitpipes, ofi_pipe, node); ep->nlistener = nl; ep->proto = nni_sock_proto_id(nni_listener_sock(nl));
	char svc[8]; sprintf(svc, "%u", url->u_port);
	struct fi_info *hints = fi_allocinfo(); hints->ep_attr->type = ofi_ep_type; hints->caps = FI_MSG;
	if (ofi_ep_type == FI_EP_RDM) hints->caps |= FI_SOURCE;
	struct fi_info *info = NULL; fi_getinfo(FI_VERSION(1, 11), (url->u_hostname[0]?url->u_hostname:NULL), svc, FI_SOURCE, hints, &info);
	if (ofi_ep_type == FI_EP_MSG) {
		fi_passive_ep(ofi_fabric, info, &ep->pep, NULL);
		struct fi_eq_attr eattr = { .size = 256, .wait_obj = FI_WAIT_UNSPEC };
		fi_eq_open(ofi_fabric, &eattr, &ep->eq, NULL);
		fi_pep_bind(ep->pep, &ep->eq->fid, 0);
	} else if (info != NULL) {
		struct fi_av_attr aattr = { .type = FI_AV_MAP, .count = 128 };
		fi_endpoint(ofi_domain, info, &ep->ep, NULL);
		fi_av_open(ofi_domain, &aattr, &ep->av, NULL);
		fi_ep_bind(ep->ep, &ep->av->fid, 0);
	}
	if (info) fi_freeinfo(info); fi_freeinfo(hints); return 0;
}
static nng_err ofi_listener_bind(void *arg, nng_url *url) {
	ofi_ep *ep = arg;
	if (ofi_ep_type == FI_EP_MSG) {
		fi_listen(ep->pep); nni_thr_init(&ep->eq_thr, ofi_ep_eq_thread, ep); nni_thr_run(&ep->eq_thr);
		if (url->u_port == 0) {
			struct sockaddr_storage ss; size_t al = sizeof(ss);
			if (fi_getname(&ep->pep->fid, &ss, &al) == 0) {
				if (ss.ss_family == AF_INET) url->u_port = ntohs(((struct sockaddr_in *)&ss)->sin_port);
			}
		}
	} else if (ep->ep != NULL) {
		struct fi_cq_attr cattr = { .size = 64, .format = FI_CQ_FORMAT_MSG, .wait_obj = FI_WAIT_FD };
		struct fid_cq *tcq, *rcq; fi_cq_open(ofi_domain, &cattr, &tcq, NULL); fi_cq_open(ofi_domain, &cattr, &rcq, NULL);
		fi_ep_bind(ep->ep, &tcq->fid, FI_TRANSMIT); fi_ep_bind(ep->ep, &rcq->fid, FI_RECV);
		fi_enable(ep->ep); ofi_pipe_alloc(ep, ep->ep, tcq, rcq, false, FI_ADDR_UNSPEC);
	}
	return 0;
}
static void ofi_listener_accept(void *arg, nni_aio *aio) {
	ofi_ep *ep = arg; nni_mtx_lock(&ep->mtx);
	ofi_pipe *p = nni_list_first(&ep->waitpipes);
	if (p) { nni_list_remove(&ep->waitpipes, p); nni_mtx_unlock(&ep->mtx); nni_aio_set_output(aio, 0, p->npipe); nni_aio_finish(aio, 0, 0); }
	else { ep->useraio = aio; nni_mtx_unlock(&ep->mtx); }
}
static void ofi_listener_close(void *arg) { ofi_ep *ep = arg; nni_mtx_lock(&ep->mtx); ep->closed = true; nni_mtx_unlock(&ep->mtx); }
static void ofi_listener_stop(void *arg) { ofi_ep *ep = arg; if (ep->eq_thr_started) nni_thr_fini(&ep->eq_thr); }
static nng_err ofi_listener_getopt(void *a, const char *n, void *v, size_t *s, nni_type t) { return NNG_ENOTSUP; }
static nng_err ofi_listener_setopt(void *a, const char *n, const void *v, size_t s, nni_type t) { return NNG_ENOTSUP; }

static nni_sp_listener_ops ofi_listener_ops = {
	.l_size = sizeof(ofi_ep), .l_init = ofi_listener_init, .l_fini = (void*)ofi_listener_close,
	.l_bind = ofi_listener_bind, .l_accept = ofi_listener_accept, .l_close = ofi_listener_close, .l_stop = ofi_listener_stop,
	.l_getopt = ofi_listener_getopt, .l_setopt = ofi_listener_setopt
};

static nng_err ofi_dialer_init(void *arg, nng_url *url, nni_dialer *nd) {
	ofi_ep *ep = arg; memset(ep, 0, sizeof(*ep)); nni_mtx_init(&ep->mtx); ep->ndialer = nd; ep->is_dialer = true;
	ep->proto = nni_sock_proto_id(nni_dialer_sock(nd)); char svc[8]; sprintf(svc, "%u", url->u_port);
	struct fi_info *hints = fi_allocinfo(); hints->ep_attr->type = ofi_ep_type; hints->caps = FI_MSG;
	struct fi_info *info = NULL; fi_getinfo(FI_VERSION(1, 11), url->u_hostname, svc, 0, hints, &info);
	if (info != NULL) {
		ep->dest_addr = nni_alloc(info->dest_addrlen); ep->dest_addrlen = info->dest_addrlen; memcpy(ep->dest_addr, info->dest_addr, info->dest_addrlen);
		if (ofi_ep_type == FI_EP_MSG) {
			struct fi_eq_attr eattr = { .size = 64, .wait_obj = FI_WAIT_UNSPEC }; fi_eq_open(ofi_fabric, &eattr, &ep->eq, NULL);
		} else {
			struct fi_av_attr aattr = { .type = FI_AV_MAP, .count = 128 }; fi_av_open(ofi_domain, &aattr, &ep->av, NULL);
		}
		fi_freeinfo(info);
	}
	fi_freeinfo(hints); return 0;
}
static void ofi_dialer_connect(void *arg, nni_aio *aio) {
	ofi_ep *ep = arg; struct fid_ep *nep; struct fid_cq *tcq, *rcq;
	struct fi_cq_attr cattr = { .size = 64, .format = FI_CQ_FORMAT_MSG, .wait_obj = FI_WAIT_FD };
	fi_endpoint(ofi_domain, ofi_base_info, &nep, NULL);
	if (ofi_ep_type == FI_EP_MSG) {
		fi_ep_bind(nep, &ep->eq->fid, 0); fi_cq_open(ofi_domain, &cattr, &tcq, NULL); fi_cq_open(ofi_domain, &cattr, &rcq, NULL);
		fi_ep_bind(nep, &tcq->fid, FI_TRANSMIT); fi_ep_bind(nep, &rcq->fid, FI_RECV);
		fi_enable(nep); fi_connect(nep, ep->dest_addr, NULL, 0);
		ep->dial_ep = nep; ep->dial_tx_cq = tcq; ep->dial_rx_cq = rcq; ep->useraio = aio;
		if (!ep->eq_thr_started) { nni_thr_init(&ep->eq_thr, ofi_ep_eq_thread, ep); nni_thr_run(&ep->eq_thr); ep->eq_thr_started = true; }
	} else {
		fi_ep_bind(nep, &ep->av->fid, 0); fi_cq_open(ofi_domain, &cattr, &tcq, NULL); fi_cq_open(ofi_domain, &cattr, &rcq, NULL);
		fi_ep_bind(nep, &tcq->fid, FI_TRANSMIT); fi_ep_bind(nep, &rcq->fid, FI_RECV);
		fi_addr_t pa; fi_av_insert(ep->av, ep->dest_addr, 1, &pa, 0, NULL);
		fi_enable(nep); ep->useraio = aio; ofi_pipe_alloc(ep, nep, tcq, rcq, true, pa);
	}
}
static void ofi_dialer_close(void *arg) { ofi_ep *ep = arg; nni_mtx_lock(&ep->mtx); ep->closed = true; nni_mtx_unlock(&ep->mtx); }
static nng_err ofi_dialer_getopt(void *a, const char *n, void *v, size_t *s, nni_type t) { return NNG_ENOTSUP; }
static nng_err ofi_dialer_setopt(void *a, const char *n, const void *v, size_t s, nni_type t) { return NNG_ENOTSUP; }

static nni_sp_dialer_ops ofi_dialer_ops = {
	.d_size = sizeof(ofi_ep), .d_init = ofi_dialer_init, .d_fini = (void*)ofi_dialer_close,
	.d_connect = ofi_dialer_connect, .d_close = ofi_dialer_close, .d_stop = ofi_dialer_close,
	.d_getopt = ofi_dialer_getopt, .d_setopt = ofi_dialer_setopt
};

static nni_sp_tran ofi_tran = {
	.tran_scheme = "ofi", .tran_dialer = &ofi_dialer_ops, .tran_listener = &ofi_listener_ops, .tran_pipe = &ofi_pipe_ops,
	.tran_init = ofi_tran_init, .tran_fini = ofi_tran_fini
};
int nni_sp_ofi_register(void) { nni_sp_tran_register(&ofi_tran); return 0; }
