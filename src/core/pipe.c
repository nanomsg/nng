//
// Copyright 2024 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
// Copyright 2018 Devolutions <info@devolutions.net>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "core/nng_impl.h"
#include "nng/nng.h"
#include "sockimpl.h"

#include <stdio.h>

// This file contains functions related to pipe objects.
//
// Operations on pipes (to the transport) are generally blocking operations,
// performed in the context of the protocol.

static nni_id_map pipes =
    NNI_ID_MAP_INITIALIZER(1, 0x7fffffff, NNI_ID_FLAG_RANDOM);
static nni_mtx pipes_lk = NNI_MTX_INITIALIZER;

static void pipe_destroy(void *);

static nni_reap_list pipe_reap_list = {
	.rl_offset = offsetof(nni_pipe, p_reap),
	.rl_func   = pipe_destroy,
};

static void
pipe_destroy(void *arg)
{
	nni_pipe *p = arg;
	if (p == NULL) {
		return;
	}

	nni_pipe_run_cb(p, NNG_PIPE_EV_REM_POST);

	// Make sure any unlocked holders are done with this.
	// This happens during initialization for example.
	nni_mtx_lock(&pipes_lk);
	if (p->p_id != 0) {
		nni_id_remove(&pipes, p->p_id);
	}
	// This wait guarantees that all callers are done with us.
	while (p->p_ref != 0) {
		nni_cv_wait(&p->p_cv);
	}
	nni_mtx_unlock(&pipes_lk);

	if (p->p_proto_data != NULL) {
		p->p_proto_ops.pipe_stop(p->p_proto_data);
	}
	if ((p->p_tran_data != NULL) && (p->p_tran_ops.p_stop != NULL)) {
		p->p_tran_ops.p_stop(p->p_tran_data);
	}

#ifdef NNG_ENABLE_STATS
	nni_stat_unregister(&p->st_root);
#endif
	nni_pipe_remove(p);

	if (p->p_proto_data != NULL) {
		p->p_proto_ops.pipe_fini(p->p_proto_data);
	}
	if (p->p_tran_data != NULL) {
		p->p_tran_ops.p_fini(p->p_tran_data);
	}
	nni_cv_fini(&p->p_cv);
	nni_free(p, p->p_size);
}

int
nni_pipe_find(nni_pipe **pp, uint32_t id)
{
	nni_pipe *p;

	// We don't care if the pipe is "closed".  End users only have
	// access to the pipe in order to obtain properties (which may
	// be retried during the post-close notification callback) or to
	// close the pipe.
	nni_mtx_lock(&pipes_lk);
	if ((p = nni_id_get(&pipes, id)) != NULL) {
		p->p_ref++;
		*pp = p;
	}
	nni_mtx_unlock(&pipes_lk);
	return (p == NULL ? NNG_ENOENT : 0);
}

void
nni_pipe_rele(nni_pipe *p)
{
	nni_mtx_lock(&pipes_lk);
	p->p_ref--;
	if (p->p_ref == 0) {
		nni_cv_wake(&p->p_cv);
	}
	nni_mtx_unlock(&pipes_lk);
}

// nni_pipe_id returns the 32-bit pipe id, which can be used in backtraces.
uint32_t
nni_pipe_id(nni_pipe *p)
{
	return (p->p_id);
}

void
nni_pipe_recv(nni_pipe *p, nni_aio *aio)
{
	p->p_tran_ops.p_recv(p->p_tran_data, aio);
}

void
nni_pipe_send(nni_pipe *p, nni_aio *aio)
{
	p->p_tran_ops.p_send(p->p_tran_data, aio);
}

// nni_pipe_close closes the underlying connection.  It is expected that
// subsequent attempts to receive or send (including any waiting receive) will
// simply return NNG_ECLOSED.
void
nni_pipe_close(nni_pipe *p)
{
	if (nni_atomic_swap_bool(&p->p_closed, true)) {
		return; // We already did a close.
	}

	if (p->p_proto_data != NULL) {
		p->p_proto_ops.pipe_close(p->p_proto_data);
	}

	// Close the underlying transport.
	if (p->p_tran_data != NULL) {
		p->p_tran_ops.p_close(p->p_tran_data);
	}

	nni_reap(&pipe_reap_list, p);
}

bool
nni_pipe_is_closed(nni_pipe *p)
{
	return (nni_atomic_get_bool(&p->p_closed));
}

uint16_t
nni_pipe_peer(nni_pipe *p)
{
	return (p->p_tran_ops.p_peer(p->p_tran_data));
}

#ifdef NNG_ENABLE_STATS
static void
pipe_stat_init(nni_pipe *p, nni_stat_item *item, const nni_stat_info *info)
{
	nni_stat_init(item, info);
	nni_stat_add(&p->st_root, item);
}

static void
pipe_stats_init(nni_pipe *p)
{
	static const nni_stat_info root_info = {
		.si_name = "pipe",
		.si_desc = "pipe statistics",
		.si_type = NNG_STAT_SCOPE,
	};
	static const nni_stat_info id_info = {
		.si_name = "id",
		.si_desc = "pipe id",
		.si_type = NNG_STAT_ID,
	};
	static const nni_stat_info socket_info = {
		.si_name = "socket",
		.si_desc = "socket for pipe",
		.si_type = NNG_STAT_ID,
	};
	static const nni_stat_info rx_msgs_info = {
		.si_name   = "rx_msgs",
		.si_desc   = "messages received",
		.si_type   = NNG_STAT_COUNTER,
		.si_unit   = NNG_UNIT_MESSAGES,
		.si_atomic = true,
	};
	static const nni_stat_info tx_msgs_info = {
		.si_name   = "tx_msgs",
		.si_desc   = "messages sent",
		.si_type   = NNG_STAT_COUNTER,
		.si_unit   = NNG_UNIT_MESSAGES,
		.si_atomic = true,
	};
	static const nni_stat_info rx_bytes_info = {
		.si_name   = "rx_bytes",
		.si_desc   = "bytes received",
		.si_type   = NNG_STAT_COUNTER,
		.si_unit   = NNG_UNIT_BYTES,
		.si_atomic = true,
	};
	static const nni_stat_info tx_bytes_info = {
		.si_name   = "tx_bytes",
		.si_desc   = "bytes sent",
		.si_type   = NNG_STAT_COUNTER,
		.si_unit   = NNG_UNIT_BYTES,
		.si_atomic = true,
	};

	nni_stat_init(&p->st_root, &root_info);
	pipe_stat_init(p, &p->st_id, &id_info);
	pipe_stat_init(p, &p->st_sock_id, &socket_info);
	pipe_stat_init(p, &p->st_rx_msgs, &rx_msgs_info);
	pipe_stat_init(p, &p->st_tx_msgs, &tx_msgs_info);
	pipe_stat_init(p, &p->st_rx_bytes, &rx_bytes_info);
	pipe_stat_init(p, &p->st_tx_bytes, &tx_bytes_info);

	nni_stat_set_id(&p->st_root, (int) p->p_id);
	nni_stat_set_id(&p->st_id, (int) p->p_id);
	nni_stat_set_id(&p->st_sock_id, (int) nni_sock_id(p->p_sock));
}
#endif // NNG_ENABLE_STATS

static int
pipe_create(nni_pipe **pp, nni_sock *sock, nni_sp_tran *tran, void *tran_data)
{
	nni_pipe           *p;
	int                 rv;
	void               *sock_data = nni_sock_proto_data(sock);
	nni_proto_pipe_ops *pops      = nni_sock_proto_pipe_ops(sock);
	size_t              sz;

	sz = NNI_ALIGN_UP(sizeof(*p)) + pops->pipe_size;

	if ((p = nni_zalloc(sz)) == NULL) {
		// In this case we just toss the pipe...
		tran->tran_pipe->p_fini(tran_data);
		return (NNG_ENOMEM);
	}

	p->p_size       = sz;
	p->p_proto_data = p + 1;
	p->p_tran_ops   = *tran->tran_pipe;
	p->p_tran_data  = tran_data;
	p->p_proto_ops  = *pops;
	p->p_sock       = sock;
	p->p_cbs        = false;
	p->p_ref        = 1;

	nni_atomic_init_bool(&p->p_closed);
	nni_atomic_flag_reset(&p->p_stop);
	NNI_LIST_NODE_INIT(&p->p_sock_node);
	NNI_LIST_NODE_INIT(&p->p_ep_node);

	nni_cv_init(&p->p_cv, &pipes_lk);

	nni_mtx_lock(&pipes_lk);
	rv = nni_id_alloc32(&pipes, &p->p_id, p);
	nni_mtx_unlock(&pipes_lk);

#ifdef NNG_ENABLE_STATS
	pipe_stats_init(p);
#endif

	if ((rv != 0) || ((rv = p->p_tran_ops.p_init(tran_data, p)) != 0) ||
	    ((rv = pops->pipe_init(p->p_proto_data, p, sock_data)) != 0)) {
		nni_pipe_close(p);
		nni_pipe_rele(p);
		return (rv);
	}

	*pp = p;
	return (0);
}

int
nni_pipe_create_dialer(nni_pipe **pp, nni_dialer *d, void *tran_data)
{
	int          rv;
	nni_sp_tran *tran = d->d_tran;
	nni_pipe    *p;

	if ((rv = pipe_create(&p, d->d_sock, tran, tran_data)) != 0) {
		return (rv);
	}
	p->p_dialer = d;
#ifdef NNG_ENABLE_STATS
	static const nni_stat_info dialer_info = {
		.si_name = "dialer",
		.si_desc = "dialer for pipe",
		.si_type = NNG_STAT_ID,
	};
	pipe_stat_init(p, &p->st_ep_id, &dialer_info);
	nni_stat_set_id(&p->st_ep_id, (int) nni_dialer_id(d));
#endif
	*pp = p;
	return (0);
}

int
nni_pipe_create_listener(nni_pipe **pp, nni_listener *l, void *tran_data)
{
	int          rv;
	nni_sp_tran *tran = l->l_tran;
	nni_pipe    *p;

	if ((rv = pipe_create(&p, l->l_sock, tran, tran_data)) != 0) {
		return (rv);
	}
	p->p_listener = l;
#ifdef NNG_ENABLE_STATS
	static const nni_stat_info listener_info = {
		.si_name = "listener",
		.si_desc = "listener for pipe",
		.si_type = NNG_STAT_ID,
	};
	pipe_stat_init(p, &p->st_ep_id, &listener_info);
	nni_stat_set_id(&p->st_ep_id, (int) nni_listener_id(l));
#endif
	*pp = p;
	return (0);
}

int
nni_pipe_getopt(
    nni_pipe *p, const char *name, void *val, size_t *szp, nni_opt_type t)
{
	int rv;

	rv = p->p_tran_ops.p_getopt(p->p_tran_data, name, val, szp, t);
	if (rv != NNG_ENOTSUP) {
		return (rv);
	}

	// Maybe the endpoint knows? The guarantees on pipes ensure that the
	// pipe will not outlive its creating endpoint.
	if (p->p_dialer != NULL) {
		return (nni_dialer_getopt(p->p_dialer, name, val, szp, t));
	}
	if (p->p_listener != NULL) {
		return (nni_listener_getopt(p->p_listener, name, val, szp, t));
	}
	return (NNG_ENOTSUP);
}

uint32_t
nni_pipe_sock_id(nni_pipe *p)
{
	return (nni_sock_id(p->p_sock));
}

uint32_t
nni_pipe_listener_id(nni_pipe *p)
{
	return (p->p_listener ? nni_listener_id(p->p_listener) : 0);
}

uint32_t
nni_pipe_dialer_id(nni_pipe *p)
{
	return (p->p_dialer ? nni_dialer_id(p->p_dialer) : 0);
}

void
nni_pipe_add_stat(nni_pipe *p, nni_stat_item *item)
{
#ifdef NNG_ENABLE_STATS
	nni_stat_add(&p->st_root, item);
#else
	NNI_ARG_UNUSED(p);
	NNI_ARG_UNUSED(item);
#endif
}

void
nni_pipe_bump_rx(nni_pipe *p, size_t bytes)
{
#ifdef NNG_ENABLE_STATS
	nni_stat_inc(&p->st_rx_bytes, bytes);
	nni_stat_inc(&p->st_rx_msgs, 1);
#else
	NNI_ARG_UNUSED(p);
	NNI_ARG_UNUSED(bytes);
#endif
}

void
nni_pipe_bump_tx(nni_pipe *p, size_t bytes)
{
#ifdef NNG_ENABLE_STATS
	nni_stat_inc(&p->st_tx_bytes, bytes);
	nni_stat_inc(&p->st_tx_msgs, 1);
#else
	NNI_ARG_UNUSED(p);
	NNI_ARG_UNUSED(bytes);
#endif
}

void
nni_pipe_bump_error(nni_pipe *p, int err)
{
	if (p->p_dialer != NULL) {
		nni_dialer_bump_error(p->p_dialer, err);
	} else {
		nni_listener_bump_error(p->p_listener, err);
	}
}

char *
nni_pipe_peer_addr(nni_pipe *p, char buf[NNG_MAXADDRSTRLEN])
{
	nng_sockaddr sa;
	size_t       sz = sizeof(sa);
	sa.s_family     = AF_UNSPEC;
	nni_pipe_getopt(p, NNG_OPT_REMADDR, &sa, &sz, NNI_TYPE_SOCKADDR);
	nng_str_sockaddr(&sa, buf, NNG_MAXADDRSTRLEN);
	return (buf);
}
