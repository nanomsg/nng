//
// Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#ifndef PLATFORM_WIN_WINIPC_H
#define PLATFORM_WIN_WINIPC_H

// This header file is private to the IPC (named pipes) support for Windows.

#include "core/nng_impl.h"

#ifdef NNG_PLATFORM_WINDOWS

struct nni_ipc_conn {
	HANDLE            f;
	nni_win_io        recv_io;
	nni_win_io        send_io;
	nni_win_io        conn_io;
	nni_list          recv_aios;
	nni_list          send_aios;
	nni_aio *         conn_aio;
	nni_ipc_dialer *  dialer;
	nni_ipc_listener *listener;
	int               recv_rv;
	int               send_rv;
	int               conn_rv;
	bool              closed;
	nni_mtx           mtx;
	nni_cv            cv;
	nni_reap_item     reap;
};

struct nni_ipc_dialer {
	bool          closed; // dialers are locked by the worker lock
	nni_list      aios;
	nni_list_node node; // node on worker list
};

struct nni_ipc_listener {
	char *              path;
	bool                started;
	bool                closed;
	HANDLE              f;
	SECURITY_ATTRIBUTES sec_attr;
	nni_list            aios;
	nni_mtx             mtx;
	nni_cv              cv;
	nni_win_io          io;
	int                 rv;
};

extern int nni_win_ipc_conn_init(nni_ipc_conn **, HANDLE);

#endif // NNG_PLATFORM_WINDOWS

#endif // NNG_PLATFORM_WIN_WINIPC_H
