//
// Copyright 2016 Garrett D'Amore <garrett@damore.org>
// Copyright 2017 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#ifndef CORE_ENDPT_H
#define CORE_ENDPT_H

#include "core/defs.h"
#include "core/list.h"
#include "core/thread.h"
#include "core/transport.h"

// NB: This structure is supplied here for use by the CORE. Use of this
// OUSIDE of the core is STRICTLY VERBOTEN.  NO DIRECT ACCESS BY PROTOCOLS
// OR TRANSPORTS.
struct nni_ep {
	nni_tran_ep   ep_ops;  // transport ops
	nni_tran *    ep_tran; // transport pointer
	void *        ep_data; // transport private
	uint32_t      ep_id;   // endpoint id
	nni_list_node ep_node; // per socket list
	nni_sock *    ep_sock;
	char          ep_addr[NNG_MAXADDRLEN];
	int           ep_mode;
	int           ep_started;
	int           ep_stop;
	int           ep_closed; // full shutdown
	int           ep_bound;  // true if we bound locally
	int           ep_refcnt;
	nni_mtx       ep_mtx;
	nni_cv        ep_cv;
	nni_list      ep_pipes;
	nni_aio       ep_acc_aio;
	nni_aio       ep_con_aio;
	nni_aio       ep_con_syn;  // used for sync connect
	nni_aio       ep_backoff;  // backoff timer
	nni_duration  ep_maxrtime; // maximum time for reconnect
	nni_duration  ep_currtime; // current time for reconnect
	nni_duration  ep_inirtime; // initial time for reconnect
	nni_time      ep_conntime; // time of last good connect
	nni_taskq_ent ep_reap_tqe;
};

enum nni_ep_mode {
	NNI_EP_MODE_DIAL   = 1,
	NNI_EP_MODE_LISTEN = 2,
};

extern int      nni_ep_sys_init(void);
extern void     nni_ep_sys_fini(void);
extern int      nni_ep_find(nni_ep **, uint32_t);
extern uint32_t nni_ep_id(nni_ep *);
extern int      nni_ep_create(nni_ep **, nni_sock *, const char *, int);
extern void     nni_ep_stop(nni_ep *);
extern void     nni_ep_close(nni_ep *);
extern int      nni_ep_dial(nni_ep *, int);
extern int      nni_ep_listen(nni_ep *, int);
extern void     nni_ep_list_init(nni_list *);
extern int nni_ep_pipe_add(nni_ep *ep, nni_pipe *);
extern void nni_ep_pipe_remove(nni_ep *, nni_pipe *);

#endif // CORE_ENDPT_H
