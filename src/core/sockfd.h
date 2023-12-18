//
// Copyright 2023 Staysail Systems, Inc. <info@staysail.tech>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#ifndef CORE_FDC_H
#define CORE_FDC_H

#include "core/nng_impl.h"

// the nni_sfd_conn struct is provided by platform code to wrap
// an arbitrary byte stream file descriptor (UNIX) or handle (Windows)
// with a nng_stream.
typedef struct nni_sfd_conn nni_sfd_conn;
extern int nni_sfd_conn_alloc(nni_sfd_conn **cp, int fd);
extern int nni_sfd_dialer_alloc(nng_stream_dialer **, const nng_url *);
extern int nni_sfd_listener_alloc(nng_stream_listener **, const nng_url *);

// this is used to close a file descriptor, in case we cannot
// create a connection (or if the listener is closed before the
// connection is accepted.)
extern void nni_sfd_close_fd(int fd);

#endif // CORE_FDC_H
