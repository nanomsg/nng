//
// Copyright 2017 Garrett D'Amore <garrett@damore.org>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#ifndef PLATFORM_POSIX_SOCKET_H
#define PLATFORM_POSIX_SOCKET_H

// This file provides declarations for comment socket handling functions on
// POSIX platforms.  We assume that TCP and Unix domain socket (IPC) all
// work using mostly comment socket handling routines.

#include "core/nng_impl.h"

#include "platform/posix/posix_aio.h"

#include <sys/types.h>
#include <sys/socket.h>

typedef struct nni_posix_sock   nni_posix_sock;

extern int nni_posix_to_sockaddr(struct sockaddr_storage *,
    const nni_sockaddr *);
extern int nni_posix_from_sockaddr(nni_sockaddr *, const struct sockaddr *);
extern void nni_posix_sock_aio_send(nni_posix_sock *, nni_aio *);
extern void nni_posix_sock_aio_recv(nni_posix_sock *, nni_aio *);
extern int nni_posix_sock_init(nni_posix_sock **);
extern void nni_posix_sock_fini(nni_posix_sock *);
extern void nni_posix_sock_shutdown(nni_posix_sock *);
extern int nni_posix_sock_listen(nni_posix_sock *, const nni_sockaddr *);

// These functions will need to be removed in the future.  They are
// transition functions for now.

extern int nni_posix_sock_send_sync(nni_posix_sock *, nni_iov *, int);
extern int nni_posix_sock_recv_sync(nni_posix_sock *, nni_iov *, int);
extern int nni_posix_sock_accept_sync(nni_posix_sock *, nni_posix_sock *);
extern int nni_posix_sock_connect_sync(nni_posix_sock *,
    const nni_sockaddr *, const nni_sockaddr *);

#endif // PLATFORM_POSIX_SOCKET_H
