//
// Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#ifndef PLATFORM_POSIX_AIO_H
#define PLATFORM_POSIX_AIO_H

// This file defines structures we will use for emulating asynchronous I/O
// on POSIX.  POSIX lacks the support for callback based asynchronous I/O
// that we have on Windows, although it has a non-widely support aio layer
// that is not very performant on many systems.   So we emulate this using
// one of several possible different backends.

#include "core/nng_impl.h"
#include "posix_pollq.h"

#include <sys/stat.h>  // needed for musl build
#include <sys/types.h> // needed for mode_t

typedef struct nni_posix_pipedesc nni_posix_pipedesc;
typedef struct nni_posix_epdesc   nni_posix_epdesc;

extern int  nni_posix_pipedesc_init(nni_posix_pipedesc **, nni_posix_pfd *);
extern void nni_posix_pipedesc_fini(nni_posix_pipedesc *);
extern void nni_posix_pipedesc_recv(nni_posix_pipedesc *, nni_aio *);
extern void nni_posix_pipedesc_send(nni_posix_pipedesc *, nni_aio *);
extern void nni_posix_pipedesc_close(nni_posix_pipedesc *);
extern int  nni_posix_pipedesc_peername(nni_posix_pipedesc *, nni_sockaddr *);
extern int  nni_posix_pipedesc_sockname(nni_posix_pipedesc *, nni_sockaddr *);
extern int  nni_posix_pipedesc_set_nodelay(nni_posix_pipedesc *, bool);
extern int  nni_posix_pipedesc_set_keepalive(nni_posix_pipedesc *, bool);
extern int  nni_posix_pipedesc_get_peerid(
     nni_posix_pipedesc *, uint64_t *, uint64_t *, uint64_t *, uint64_t *);

extern int  nni_posix_epdesc_init(nni_posix_epdesc **, int);
extern void nni_posix_epdesc_set_local(nni_posix_epdesc *, void *, size_t);
extern void nni_posix_epdesc_set_remote(nni_posix_epdesc *, void *, size_t);
extern void nni_posix_epdesc_fini(nni_posix_epdesc *);
extern void nni_posix_epdesc_close(nni_posix_epdesc *);
extern void nni_posix_epdesc_connect(nni_posix_epdesc *, nni_aio *);
extern int  nni_posix_epdesc_listen(nni_posix_epdesc *);
extern void nni_posix_epdesc_accept(nni_posix_epdesc *, nni_aio *);
extern int  nni_posix_epdesc_sockname(nni_posix_epdesc *, nni_sockaddr *);
extern int  nni_posix_epdesc_set_permissions(nni_posix_epdesc *, mode_t);
#endif // PLATFORM_POSIX_AIO_H
