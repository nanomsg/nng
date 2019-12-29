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

#ifndef NNG_SUPPLEMENTAL_WEBSOCKET_WEBSOCKET_H
#define NNG_SUPPLEMENTAL_WEBSOCKET_WEBSOCKET_H

#include <stdbool.h>

typedef struct nni_ws          nni_ws;
typedef struct nni_ws_listener nni_ws_listener;
typedef struct nni_ws_dialer   nni_ws_dialer;

// Internal option, not for normal use (at present).  This sets the
// dialer/listener into message mode.  This is used by the SP transport.
// This is a boolean.
#define NNI_OPT_WS_MSGMODE "ws:msgmode"

// Specify URL as ws://[<host>][:port][/path]
// If host is missing, INADDR_ANY is assumed.  If port is missing,
// then either 80 or 443 are assumed.  Note that ws:// means listen
// on INADDR_ANY port 80, with path "/".  For connect side, INADDR_ANY
// makes no sense.  (TBD: return NNG_EADDRINVAL, or try loopback?)

// Much of the websocket API is still "private", meaning you should not
// rely upon it being around.
extern int nni_ws_listener_alloc(nng_stream_listener **, const nni_url *);
extern int nni_ws_dialer_alloc(nng_stream_dialer **, const nni_url *);
extern int nni_ws_checkopt(const char *, const void *, size_t, nni_type);

#endif // NNG_SUPPLEMENTAL_WEBSOCKET_WEBSOCKET_H
