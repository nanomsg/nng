//
// Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#ifndef PLATFORM_WIN_IMPL_H
#define PLATFORM_WIN_IMPL_H

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

// These headers must be included first.
#include <windows.h>
#include <winsock2.h>

#include <mswsock.h>
#include <process.h>
#include <ws2tcpip.h>

#include "core/list.h"

// These types are provided for here, to permit them to be directly inlined
// elsewhere.

struct nni_plat_thr {
	void (*func)(void *);
	void * arg;
	HANDLE handle;
	DWORD  id;
};

struct nni_plat_mtx {
	SRWLOCK srl;
	DWORD   owner;
	int     init;
};

struct nni_plat_cv {
	CONDITION_VARIABLE cv;
	PSRWLOCK           srl;
};

struct nni_atomic_flag {
	unsigned f;
};

struct nni_atomic_bool {
	LONG v;
};

struct nni_atomic_int {
	LONG v;
};

struct nni_atomic_u64 {
	LONGLONG v;
};

// nni_win_io is used with io completion ports.  This allows us to get
// to a specific completion callback without requiring the poller (in the
// completion port) to know anything about the event itself.

typedef struct nni_win_io nni_win_io;
typedef void (*nni_win_io_cb)(nni_win_io *, int, size_t);

struct nni_win_io {
	OVERLAPPED    olpd;
	HANDLE        f;
	void *        ptr;
	nni_aio *     aio;
	nni_win_io_cb cb;
};

struct nni_plat_flock {
	HANDLE h;
};

extern int nni_win_error(int);

extern int nni_win_tcp_conn_init(nni_tcp_conn **, SOCKET);

extern int  nni_win_io_sysinit(void);
extern void nni_win_io_sysfini(void);

extern int  nni_win_ipc_sysinit(void);
extern void nni_win_ipc_sysfini(void);

extern int  nni_win_tcp_sysinit(void);
extern void nni_win_tcp_sysfini(void);

extern int  nni_win_udp_sysinit(void);
extern void nni_win_udp_sysfini(void);

extern int  nni_win_resolv_sysinit(void);
extern void nni_win_resolv_sysfini(void);

extern int  nni_win_io_init(nni_win_io *, nni_win_io_cb, void *);
extern void nni_win_io_fini(nni_win_io *);

extern int nni_win_io_register(HANDLE);

extern int nni_win_sockaddr2nn(nni_sockaddr *, const SOCKADDR_STORAGE *);
extern int nni_win_nn2sockaddr(SOCKADDR_STORAGE *, const nni_sockaddr *);

#define NNG_PLATFORM_DIR_SEP "\\"

#endif // PLATFORM_WIN_IMPL_H
