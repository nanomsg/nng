//
// Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#ifndef CORE_DIALER_H
#define CORE_DIALER_H

extern int      nni_dialer_sys_init(void);
extern void     nni_dialer_sys_fini(void);
extern int      nni_dialer_find(nni_dialer **, uint32_t);
extern int      nni_dialer_hold(nni_dialer *);
extern void     nni_dialer_rele(nni_dialer *);
extern uint32_t nni_dialer_id(nni_dialer *);
extern int      nni_dialer_create(nni_dialer **, nni_sock *, const char *);
extern int      nni_dialer_shutdown(nni_dialer *);
extern void     nni_dialer_close(nni_dialer *);
extern int      nni_dialer_start(nni_dialer *, int);
extern void     nni_dialer_list_init(nni_list *);
extern void     nni_dialer_remove_pipe(nni_dialer *, nni_pipe *);

extern int nni_dialer_setopt(
    nni_dialer *, const char *, const void *, size_t, nni_opt_type);
extern int nni_dialer_getopt(
    nni_dialer *, const char *, void *, size_t *, nni_opt_type);

#endif // CORE_DIALER_H
