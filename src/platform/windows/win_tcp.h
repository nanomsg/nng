//
// Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#ifndef PLATFORM_WIN_WINTCP_H
#define PLATFORM_WIN_WINTCP_H

// This header file is private to the TCP support for Windows.

#include "core/nng_impl.h"

#ifdef NNG_PLATFORM_WINDOWS

struct nni_tcp_conn {
	SOCKET            s;
	nni_win_io        recv_io;
	nni_win_io        send_io;
	nni_win_io        conn_io;
	nni_list          recv_aios;
	nni_list          send_aios;
	nni_aio *         conn_aio;
	SOCKADDR_STORAGE  sockname;
	SOCKADDR_STORAGE  peername;
	nni_tcp_dialer *  dialer;
	nni_tcp_listener *listener;
	int               recv_rv;
	int               send_rv;
	int               conn_rv;
	bool              closed;
	char              buf[512]; // to hold acceptex results
	nni_mtx           mtx;
	nni_cv            cv;
};

struct nni_tcp_dialer {
	LPFN_CONNECTEX   connectex; // looked up name via ioctl
	nni_list         aios;      // in flight connections
	bool             closed;
	SOCKADDR_STORAGE src;
	size_t           srclen;
	nni_mtx          mtx;
	nni_reap_item    reap;
};

struct nni_tcp_listener {
	SOCKET                    s;
	nni_list                  aios;
	bool                      closed;
	bool                      started;
	LPFN_ACCEPTEX             acceptex;
	LPFN_GETACCEPTEXSOCKADDRS getacceptexsockaddrs;
	SOCKADDR_STORAGE          ss;
	nni_mtx                   mtx;
	nni_reap_item             reap;
};

extern int  nni_win_tcp_conn_init(nni_tcp_conn **, SOCKET);
extern void nni_win_tcp_conn_set_addrs(
    nni_tcp_conn *, const SOCKADDR_STORAGE *, const SOCKADDR_STORAGE *);

#endif // NNG_PLATFORM_WINDOWS

#endif // NNG_PLATFORM_WIN_WINTCP_H
