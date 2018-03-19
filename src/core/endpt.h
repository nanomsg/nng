//
// Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#ifndef CORE_ENDPT_H
#define CORE_ENDPT_H

extern int       nni_ep_sys_init(void);
extern void      nni_ep_sys_fini(void);
extern nni_tran *nni_ep_tran(nni_ep *);
extern nni_sock *nni_ep_sock(nni_ep *);
extern int       nni_ep_find(nni_ep **, uint32_t);
extern int       nni_ep_hold(nni_ep *);
extern void      nni_ep_rele(nni_ep *);
extern uint32_t  nni_ep_id(nni_ep *);
extern int       nni_ep_create_dialer(nni_ep **, nni_sock *, const char *);
extern int       nni_ep_create_listener(nni_ep **, nni_sock *, const char *);
extern void      nni_ep_stop(nni_ep *);
extern int       nni_ep_shutdown(nni_ep *);
extern void      nni_ep_close(nni_ep *);
extern int       nni_ep_dial(nni_ep *, int);
extern int       nni_ep_listen(nni_ep *, int);
extern void      nni_ep_list_init(nni_list *);
extern int  nni_ep_setopt(nni_ep *, const char *, const void *, size_t, int);
extern int  nni_ep_getopt(nni_ep *, const char *, void *, size_t *, int);
extern int  nni_ep_opttype(nni_ep *, const char *, int *);
extern int  nni_ep_pipe_add(nni_ep *ep, nni_pipe *);
extern void nni_ep_pipe_remove(nni_ep *, nni_pipe *);
extern int  nni_ep_mode(nni_ep *);

// Endpoint modes.  Currently used by transports.  Remove this when we make
// transport dialers and listeners explicit.
enum nni_ep_mode {
	NNI_EP_MODE_DIAL   = 1,
	NNI_EP_MODE_LISTEN = 2,
};

#endif // CORE_ENDPT_H
