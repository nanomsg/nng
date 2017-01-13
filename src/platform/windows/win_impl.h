//
// Copyright 2017 Garrett D'Amore <garrett@damore.org>
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

#include <windows.h>
#include <winsock2.h>
#include <mswsock.h>
#include <process.h>
#include <ws2tcpip.h>


// These types are provided for here, to permit them to be directly inlined
// elsewhere.

struct nni_plat_tcpsock {
	SOCKET s;
};

struct nni_plat_ipcsock {
	HANDLE p;
};

struct nni_plat_thr {
	void (__stdcall *func)(void *);
	void *	arg;
	HANDLE	handle;
};

struct nni_plat_mtx {
	CRITICAL_SECTION	cs;
	DWORD			owner;
};

struct nni_plat_cv {
	CONDITION_VARIABLE	cv;
	CRITICAL_SECTION	*cs;
};

#endif  // PLATFORM_WINDOWS

#endif  // PLATFORM_WIN_IMPL_H
