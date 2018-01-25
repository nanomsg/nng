//
// Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
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

typedef int (*nni_ws_listen_hook)(void *, nng_http_req *, nng_http_res *);

// Specify URL as ws://[<host>][:port][/path]
// If host is missing, INADDR_ANY is assumed.  If port is missing,
// then either 80 or 443 are assumed.  Note that ws:// means listen
// on INADDR_ANY port 80, with path "/".  For connect side, INADDR_ANY
// makes no sense.  (TBD: return NNG_EADDRINVAL, or try loopback?)

extern int  nni_ws_listener_init(nni_ws_listener **, nni_url *);
extern void nni_ws_listener_fini(nni_ws_listener *);
extern void nni_ws_listener_close(nni_ws_listener *);
extern int  nni_ws_listener_proto(nni_ws_listener *, const char *);
extern int  nni_ws_listener_listen(nni_ws_listener *);
extern void nni_ws_listener_accept(nni_ws_listener *, nng_aio *);
extern void nni_ws_listener_hook(
    nni_ws_listener *, nni_ws_listen_hook, void *);
extern int nni_ws_listener_set_tls(nni_ws_listener *, nng_tls_config *);
extern int nni_ws_listener_get_tls(nni_ws_listener *, nng_tls_config **s);

extern int  nni_ws_dialer_init(nni_ws_dialer **, nni_url *);
extern void nni_ws_dialer_fini(nni_ws_dialer *);
extern void nni_ws_dialer_close(nni_ws_dialer *);
extern int  nni_ws_dialer_proto(nni_ws_dialer *, const char *);
extern int  nni_ws_dialer_header(nni_ws_dialer *, const char *, const char *);
extern void nni_ws_dialer_dial(nni_ws_dialer *, nng_aio *);
extern int  nni_ws_dialer_set_tls(nni_ws_dialer *, nng_tls_config *);
extern int  nni_ws_dialer_get_tls(nni_ws_dialer *, nng_tls_config **);

// Dialer does not get a hook chance, as it can examine the request and reply
// after dial is done; this is not a 3-way handshake, so the dialer does
// not confirm the server's response at the HTTP level.  (It can still issue
// a websocket close).

extern void          nni_ws_send_msg(nni_ws *, nng_aio *);
extern void          nni_ws_recv_msg(nni_ws *, nng_aio *);
extern nng_http_res *nni_ws_response(nni_ws *);
extern nng_http_req *nni_ws_request(nni_ws *);
extern int           nni_ws_sock_addr(nni_ws *, nni_sockaddr *);
extern int           nni_ws_peer_addr(nni_ws *, nni_sockaddr *);
extern void          nni_ws_close(nni_ws *);
extern void          nni_ws_close_error(nni_ws *, uint16_t);
extern void          nni_ws_fini(nni_ws *);
extern const char *  nni_ws_response_headers(nni_ws *);
extern const char *  nni_ws_request_headers(nni_ws *);
extern bool          nni_ws_tls_verified(nni_ws *);

// The implementation will send periodic PINGs, and respond with PONGs.

#endif // NNG_SUPPLEMENTAL_WEBSOCKET_WEBSOCKET_H
