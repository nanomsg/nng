//
// Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "core/nng_impl.h"

#ifdef NNG_PLATFORM_POSIX
#include "platform/posix/posix_aio.h"

struct nni_tcp_conn {
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
	struct sockaddr_storage src;
	size_t                  srclen;
	nni_mtx                 mtx;
};

struct nni_tcp_listener {
	nni_posix_pfd *pfd;
	nni_list       acceptq;
	bool           started;
	bool           closed;
	nni_mtx        mtx;
};

extern int  nni_posix_tcp_conn_init(nni_tcp_conn **, nni_posix_pfd *);
extern void nni_posix_tcp_conn_start(nni_tcp_conn *);

#endif // NNG_PLATFORM_POSIX
