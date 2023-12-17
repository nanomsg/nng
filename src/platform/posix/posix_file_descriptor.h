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

#ifndef PLATFORM_POSIX_FILE_DESCRIPTOR_H
#define PLATFORM_POSIX_FILE_DESCRIPTOR_H

#include "core/nng_impl.h"

#include "platform/posix/posix_aio.h"

struct nni_file_descriptor_conn {
	nng_stream      stream;
	nni_posix_pfd * pfd;
	nni_list        readq;
	nni_list        writeq;
	bool            closed;
	nni_mtx         mtx;
	nni_aio *       dial_aio;
	nni_file_descriptor_dialer *dialer;
	nni_reap_node   reap;
};

struct nni_file_descriptor_dialer {
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

extern int  nni_posix_file_descriptor_alloc(nni_file_descriptor_conn **, nni_file_descriptor_dialer *);
extern void nni_posix_file_descriptor_init(nni_file_descriptor_conn *, nni_posix_pfd *);
extern void nni_posix_file_descriptor_start(nni_file_descriptor_conn *, int, int);
extern void nni_posix_file_descriptor_dialer_rele(nni_file_descriptor_dialer *);

#endif // PLATFORM_POSIX_FILE_DESCRIPTOR_H
