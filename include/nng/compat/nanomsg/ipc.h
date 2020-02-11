//
// Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#ifndef NNG_COMPAT_IPC_H
#define NNG_COMPAT_IPC_H

// This header contains interfaces that are intended to offer compatibility
// with nanomsg v1.0.  These are not the "preferred" interfaces for nng,
// and consumers should only use these if they are porting software that
// previously used nanomsg.  New programs should use the nng native APIs.

#ifdef __cplusplus
extern "C" {
#endif

// IPC sockopt level.
#define NN_IPC (-2)

// IPC options.  Note that these are not currently supported.
// IPC_SEC_ATTR works quite differently in NNG, and must be
// configured using the new API.  The buffer sizing options are
// not supported at all.  None of these were ever documented, and
// are offered here only for source compatibility.
#define NN_IPC_SEC_ATTR 1
#define NN_IPC_OUTBUFSZ 2
#define NN_IPC_INBUFSZ 3

#ifdef __cplusplus
}
#endif

#endif // NNG_COMPAT_IPC_H
