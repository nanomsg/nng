//
// Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#ifndef NNG_COMPAT_WS_H
#define NNG_COMPAT_WS_H

// This header contains interfaces that are intended to offer compatibility
// with nanomsg v1.0.  These are not the "preferred" interfaces for nng,
// and consumers should only use these if they are porting software that
// previously used nanomsg.  New programs should use the nng native APIs.

#ifdef __cplusplus
extern "C" {
#endif

// WS sockopt level.
#define NN_WS (-4)

// WS options.

// Note that while legacy libnanomsg had *some* support for text messages,
// NNG only supports binary.  Binary types are required to pass protocol
// headers with NNG and nanomsg in any event.  This means that the NNG
// WebSocket support will not be compatible with some very old browsers.
#define NN_WS_MSG_TYPE 1

#define NN_WS_MSG_TYPE_TEXT 0x1
#define NN_WS_MSG_TYPE_BINARY 0x2

#ifdef __cplusplus
}
#endif

#endif // NNG_COMPAT_WS_H
