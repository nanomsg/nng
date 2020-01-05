//
// Copyright 2020 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
// Copyright 2018 Devolutions <info@devolutions.net>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#ifndef PLATFORM_POSIX_TCP_H
#define PLATFORM_POSIX_TCP_H

#include "core/nng_impl.h"

#include "platform/posix/posix_aio.h"

struct nni_tcp_conn {
	nng_stream      stream;
	nni_posix_pfd * pfd;
	nni_list        readq;
	nni_list        writeq;
	bool            closed;
	nni_mtx         mtx;
	nni_aio *       dial_aio;
	nni_tcp_dialer *dialer;
	nni_reap_item   reap;
};

struct nni_tcp_dialer {
	nni_list                connq; // pending connections
	bool                    closed;
	bool                    nodelay;
	bool                    keepalive;
	struct sockaddr_storage src;
	size_t                  srclen;
	nni_mtx                 mtx;
	nni_atomic_u64          ref;
	nni_atomic_bool         fini;
};

extern int  nni_posix_tcp_alloc(nni_tcp_conn **, nni_tcp_dialer *);
extern void nni_posix_tcp_init(nni_tcp_conn *, nni_posix_pfd *);
extern void nni_posix_tcp_start(nni_tcp_conn *, int, int);
extern void nni_posix_tcp_dialer_rele(nni_tcp_dialer *);

#endif // PLATFORM_POSIX_TCP_H