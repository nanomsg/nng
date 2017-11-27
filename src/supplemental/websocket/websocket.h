//
// Copyright 2017 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2017 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#ifndef NNG_SUPPLEMENTAL_WEBSOCKET_WEBSOCKET_H
#define NNG_SUPPLEMENTAL_WEBSOCKET_WEBSOCKET_H

// Pre-defined types for some prototypes.  These are from other subsystems.
typedef struct nni_tls_config nni_tls_config;
typedef struct nni_http_req   nni_http_req;
typedef struct nni_http_res   nni_http_res;

typedef struct nni_ws          nni_ws;
typedef struct nni_ws_listener nni_ws_listener;
typedef struct nni_ws_dialer   nni_ws_dialer;

typedef int (*nni_ws_listen_hook)(void *, nni_http_req *, nni_http_res *);

// Specify URL as ws://[<host>][:port][/path]
// If host is missing, INADDR_ANY is assumed.  If port is missing,
// then either 80 or 443 are assumed.  Note that ws:// means listen
// on INADDR_ANY port 80, with path "/".  For connect side, INADDR_ANY
// makes no sense.  (TBD: return NNG_EADDRINVAL, or try loopback?)

extern int  nni_ws_listener_init(nni_ws_listener **, const char *);
extern void nni_ws_listener_fini(nni_ws_listener *);
extern void nni_ws_listener_close(nni_ws_listener *);
extern int  nni_ws_listener_proto(nni_ws_listener *, const char *);
extern int  nni_ws_listener_listen(nni_ws_listener *);
extern void nni_ws_listener_accept(nni_ws_listener *, nni_aio *);
extern void nni_ws_listener_hook(
    nni_ws_listener *, nni_ws_listen_hook, void *);
extern void nni_ws_listener_tls(nni_ws_listener *, nni_tls_config *);

extern int  nni_ws_dialer_init(nni_ws_dialer **, const char *);
extern void nni_ws_dialer_fini(nni_ws_dialer *);
extern void nni_ws_dialer_close(nni_ws_dialer *);
extern int  nni_ws_dialer_proto(nni_ws_dialer *, const char *);
extern int  nni_ws_dialer_header(nni_ws_dialer *, const char *, const char *);
extern void nni_ws_dialer_dial(nni_ws_dialer *, nni_aio *);

// Dialer does not get a hook chance, as it can examine the request and reply
// after dial is done; this is not a 3-way handshake, so the dialer does
// not confirm the server's response at the HTTP level.  (It can still issue
// a websocket close).

extern void          nni_ws_send_msg(nni_ws *, nni_aio *);
extern void          nni_ws_recv_msg(nni_ws *, nni_aio *);
extern nni_http_res *nni_ws_response(nni_ws *);
extern nni_http_req *nni_ws_request(nni_ws *);
extern void          nni_ws_close(nni_ws *);
extern void          nni_ws_close_error(nni_ws *, uint16_t);
extern void          nni_ws_fini(nni_ws *);

// The implementation will send periodic PINGs, and respond with PONGs.

#endif // NNG_SUPPLEMENTAL_WEBSOCKET_WEBSOCKET_H