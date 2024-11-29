//
// Copyright 2023 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#ifndef CORE_SOCKIMPL_H
#define CORE_SOCKIMPL_H

// This file contains stuff shared within the core between sockets, endpoints,
// and pipes.  This must not be exposed to other subsystems -- these internals
// are subject to change at any time.

struct nni_dialer {
	nni_sp_dialer_ops d_ops;  // transport ops
	nni_sp_tran      *d_tran; // transport pointer
	void             *d_data; // transport private
	uint32_t          d_id;   // endpoint id
	nni_list_node     d_node; // per socket list
	nni_sock         *d_sock;
	nni_pipe         *d_pipe; // active pipe (for re-dialer)
	int               d_ref;
	bool              d_closed; // full shutdown
	nni_atomic_flag   d_closing;
	nni_atomic_flag   d_started;
	nni_mtx           d_mtx;
	nni_list          d_pipes;
	nni_aio          *d_user_aio;
	nni_aio           d_con_aio;
	nni_aio           d_tmo_aio;  // backoff timer
	nni_duration      d_maxrtime; // maximum time for reconnect
	nni_duration      d_currtime; // current time for reconnect
	nni_duration      d_inirtime; // initial time for reconnect
	nni_reap_node     d_reap;
	nng_url           d_url;

#ifdef NNG_ENABLE_STATS
	nni_stat_item st_root;
	nni_stat_item st_id;
	nni_stat_item st_sock;
	nni_stat_item st_pipes;
	nni_stat_item st_connect;
	nni_stat_item st_refused;
	nni_stat_item st_disconnect; // aborted remotely
	nni_stat_item st_canceled;
	nni_stat_item st_other;
	nni_stat_item st_timeout;
	nni_stat_item st_proto; // protocol error
	nni_stat_item st_auth;
	nni_stat_item st_oom;
	nni_stat_item st_reject;
#endif
};

struct nni_listener {
	nni_sp_listener_ops l_ops;  // transport ops
	nni_sp_tran        *l_tran; // transport pointer
	void               *l_data; // transport private
	uint32_t            l_id;   // endpoint id
	nni_list_node       l_node; // per socket list
	nni_sock           *l_sock;
	int                 l_ref;
	bool                l_closed;  // full shutdown
	nni_atomic_flag     l_closing; // close started (shutdown)
	nni_atomic_flag     l_started;
	nni_list            l_pipes;
	nni_aio             l_acc_aio;
	nni_aio             l_tmo_aio;
	nni_reap_node       l_reap;
	nng_url             l_url;

#ifdef NNG_ENABLE_STATS
	nni_stat_item st_root;
	nni_stat_item st_id;
	nni_stat_item st_sock;
	nni_stat_item st_pipes;
	nni_stat_item st_accept;
	nni_stat_item st_disconnect; // aborted remotely
	nni_stat_item st_canceled;
	nni_stat_item st_other;
	nni_stat_item st_timeout;
	nni_stat_item st_proto; // protocol error
	nni_stat_item st_auth;
	nni_stat_item st_oom;
	nni_stat_item st_reject;
#endif
};

struct nni_pipe {
	uint32_t           p_id;
	nni_sp_pipe_ops    p_tran_ops;
	nni_proto_pipe_ops p_proto_ops;
	size_t             p_size;
	void              *p_tran_data;
	void              *p_proto_data;
	nni_list_node      p_sock_node;
	nni_list_node      p_ep_node;
	nni_sock          *p_sock;
	nni_dialer        *p_dialer;
	nni_listener      *p_listener;
	nni_atomic_bool    p_closed;
	nni_atomic_flag    p_stop;
	bool               p_cbs;
	nni_reap_node      p_reap;
	nni_refcnt         p_refcnt;

#ifdef NNG_ENABLE_STATS
	nni_stat_item st_root;
	nni_stat_item st_id;
	nni_stat_item st_ep_id;
	nni_stat_item st_sock_id;
	nni_stat_item st_rx_msgs;
	nni_stat_item st_tx_msgs;
	nni_stat_item st_rx_bytes;
	nni_stat_item st_tx_bytes;
#endif
};

extern int  nni_sock_add_dialer(nni_sock *, nni_dialer *);
extern int  nni_sock_add_listener(nni_sock *, nni_listener *);
extern void nni_sock_remove_listener(nni_listener *);
extern void nni_sock_remove_dialer(nni_dialer *);

extern void nni_dialer_add_pipe(nni_dialer *, void *);
extern void nni_dialer_shutdown(nni_dialer *);
extern void nni_dialer_reap(nni_dialer *);
extern void nni_dialer_destroy(nni_dialer *);
extern void nni_dialer_timer_start(nni_dialer *);
extern void nni_dialer_stop(nni_dialer *);

extern void nni_listener_add_pipe(nni_listener *, void *);
extern void nni_listener_shutdown(nni_listener *);
extern void nni_listener_reap(nni_listener *);
extern void nni_listener_destroy(nni_listener *);
extern void nni_listener_stop(nni_listener *);

extern void nni_pipe_remove(nni_pipe *);
extern bool nni_pipe_is_closed(nni_pipe *);
extern void nni_pipe_run_cb(nni_pipe *, nng_pipe_ev);
extern int  nni_pipe_create_dialer(nni_pipe **, nni_dialer *, void *);
extern int  nni_pipe_create_listener(nni_pipe **, nni_listener *, void *);

extern void nni_pipe_start(nni_pipe *);

#endif // CORE_SOCKIMPL_H
