//
// Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
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
	nni_tran_dialer_ops d_ops;  // transport ops
	nni_tran *          d_tran; // transport pointer
	void *              d_data; // transport private
	uint32_t            d_id;   // endpoint id
	nni_list_node       d_node; // per socket list
	nni_sock *          d_sock;
	nni_url *           d_url;
	nni_pipe *          d_pipe; // active pipe (for redialer)
	int                 d_refcnt;
	bool                d_closed; // full shutdown
	bool                d_closing;
	nni_atomic_flag     d_started;
	nni_mtx             d_mtx;
	nni_list            d_pipes;
	nni_aio *           d_user_aio;
	nni_aio *           d_con_aio;
	nni_aio *           d_tmo_aio;  // backoff timer
	nni_duration        d_maxrtime; // maximum time for reconnect
	nni_duration        d_currtime; // current time for reconnect
	nni_duration        d_inirtime; // initial time for reconnect
	nni_time            d_conntime; // time of last good connect
	nni_reap_item       d_reap;
};

struct nni_listener {
	nni_tran_listener_ops l_ops;  // transport ops
	nni_tran *            l_tran; // transport pointer
	void *                l_data; // transport private
	uint32_t              l_id;   // endpoint id
	nni_list_node         l_node; // per socket list
	nni_sock *            l_sock;
	nni_url *             l_url;
	int                   l_refcnt;
	bool                  l_closed;  // full shutdown
	bool                  l_closing; // close started (shutdown)
	nni_atomic_flag       l_started;
	nni_list              l_pipes;
	nni_aio *             l_acc_aio;
	nni_aio *             l_tmo_aio;
	nni_reap_item         l_reap;
};

struct nni_pipe {
	uint32_t           p_id;
	nni_tran_pipe_ops  p_tran_ops;
	nni_proto_pipe_ops p_proto_ops;
	void *             p_tran_data;
	void *             p_proto_data;
	nni_list_node      p_sock_node;
	nni_list_node      p_ep_node;
	nni_sock *         p_sock;
	nni_dialer *       p_dialer;
	nni_listener *     p_listener;
	bool               p_closed;
	nni_atomic_flag    p_stop;
	bool               p_cbs;
	int                p_refcnt;
	nni_mtx            p_mtx;
	nni_cv             p_cv;
	nni_reap_item      p_reap;
};

extern int  nni_sock_add_dialer(nni_sock *, nni_dialer *);
extern void nni_sock_remove_dialer(nni_sock *, nni_dialer *);

extern int  nni_sock_add_listener(nni_sock *, nni_listener *);
extern void nni_sock_remove_listener(nni_sock *, nni_listener *);

extern void nni_dialer_add_pipe(nni_dialer *, void *);
extern void nni_dialer_shutdown(nni_dialer *);
extern void nni_dialer_reap(nni_dialer *);
extern void nni_dialer_destroy(nni_dialer *);
extern void nni_dialer_timer_start(nni_dialer *);
extern void nni_dialer_close_rele(nni_dialer *);

extern void nni_listener_add_pipe(nni_listener *, void *);
extern void nni_listener_shutdown(nni_listener *);
extern void nni_listener_reap(nni_listener *);
extern void nni_listener_destroy(nni_listener *);
extern void nni_listener_close_rele(nni_listener *);

extern void nni_pipe_remove(nni_pipe *);
extern void nni_pipe_run_cb(nni_pipe *, nng_pipe_ev);
extern int  nni_pipe_create(nni_pipe **, nni_sock *, nni_tran *, void *);
extern void nni_pipe_start(nni_pipe *);

#endif // CORE_SOCKIMPL_H
