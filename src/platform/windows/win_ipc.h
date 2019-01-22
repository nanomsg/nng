//
// Copyright 2019 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
// Copyright 2019 Devolutions <info@devolutions.net>
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
#include "win_impl.h"

#define IPC_PIPE_PREFIX "\\\\.\\pipe\\"

extern int nni_win_ipc_init(nng_stream **, HANDLE, const nng_sockaddr *, bool);

#endif // NNG_PLATFORM_WIN_WINIPC_H
