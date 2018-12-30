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

#include "core/nng_impl.h"

#ifdef NNG_PLATFORM_POSIX
#include "platform/posix/posix_aio.h"

#include <nng/transport/ipc/ipc.h>

#include <sys/types.h> // For mode_t

struct nni_ipc_conn {
	nni_posix_pfd * pfd;
	nni_list        readq;
	nni_list        writeq;
	bool            closed;
	nni_mtx         mtx;
	nni_aio *       dial_aio;
	nni_ipc_dialer *dialer;
	nni_reap_item   reap;
};

struct nni_ipc_dialer {
	nni_list connq; // pending connections
	bool     closed;
	nni_mtx  mtx;
};

struct nni_ipc_listener {
	nni_posix_pfd *pfd;
	nng_sockaddr   sa;
	nni_list       acceptq;
	bool           started;
	bool           closed;
	char *         path;
	mode_t         perms;
	nni_mtx        mtx;
};

extern int  nni_posix_ipc_conn_init(nni_ipc_conn **, nni_posix_pfd *);
extern void nni_posix_ipc_conn_start(nni_ipc_conn *);

#endif // NNG_PLATFORM_POSIX
