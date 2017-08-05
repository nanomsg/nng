//
// Copyright 2017 Garrett D'Amore <garrett@damore.org>
// Copyright 2017 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#ifndef PLATFORM_WIN_IMPL_H
#define PLATFORM_WIN_IMPL_H

#ifdef PLATFORM_WINDOWS

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

// nni_win_event is used with io completion ports.  This allows us to get
// to a specific completion callback without requiring the poller (in the
// completion port) to know anything about the event itself.  We also use
// this to pass back status and counts to the routine, which may not be
// conveyed in the OVERLAPPED directly.
typedef struct nni_win_event     nni_win_event;
typedef struct nni_win_event_ops nni_win_event_ops;

struct nni_win_event_ops {
	int (*wev_start)(nni_win_event *, nni_aio *);
	void (*wev_finish)(nni_win_event *, nni_aio *);
	void (*wev_cancel)(nni_win_event *);
};
struct nni_win_event {
	OVERLAPPED        olpd;
	void *            ptr;
	nni_aio *         aio;
	nni_mtx           mtx;
	nni_cv            cv;
	unsigned          run : 1;
	unsigned          fini : 1;
	int               count;
	int               status;
	nni_win_event_ops ops;
};

extern int nni_win_error(int);

extern int  nni_win_event_init(nni_win_event *, nni_win_event_ops *, void *);
extern void nni_win_event_fini(nni_win_event *);
extern void nni_win_event_submit(nni_win_event *, nni_aio *);
extern void nni_win_event_resubmit(nni_win_event *, nni_aio *);
extern void nni_win_event_close(nni_win_event *);
extern void nni_win_event_complete(nni_win_event *, int);

extern int nni_win_iocp_register(HANDLE);

extern int  nni_win_iocp_sysinit(void);
extern void nni_win_iocp_sysfini(void);

extern int  nni_win_ipc_sysinit(void);
extern void nni_win_ipc_sysfini(void);

extern int  nni_win_tcp_sysinit(void);
extern void nni_win_tcp_sysfini(void);

extern int  nni_win_resolv_sysinit(void);
extern void nni_win_resolv_sysfini(void);

#endif // PLATFORM_WINDOWS

#endif // PLATFORM_WIN_IMPL_H
