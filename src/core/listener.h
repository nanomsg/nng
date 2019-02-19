//
// Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
// Copyright 2018 Devolutions <info@devolutions.net>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#ifndef CORE_LISTENER_H
#define CORE_LISTENER_H

extern int      nni_listener_sys_init(void);
extern void     nni_listener_sys_fini(void);
extern int      nni_listener_find(nni_listener **, uint32_t);
extern int      nni_listener_hold(nni_listener *);
extern void     nni_listener_rele(nni_listener *);
extern uint32_t nni_listener_id(nni_listener *);
extern int      nni_listener_create(nni_listener **, nni_sock *, const char *);
extern void     nni_listener_close(nni_listener *);
extern int      nni_listener_start(nni_listener *, int);
extern nni_sock *nni_listener_sock(nni_listener *);

extern int nni_listener_setopt(
    nni_listener *, const char *, const void *, size_t, nni_type);
extern int nni_listener_getopt(
    nni_listener *, const char *, void *, size_t *, nni_type);
extern void nni_listener_add_stat(nni_listener *, nni_stat_item *);
extern void nni_listener_bump_error(nni_listener *, int);

#endif // CORE_LISTENER_H
