//
// Copyright 2020 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#ifndef NNG_PROTOCOL_REQREP0_REQ_H
#define NNG_PROTOCOL_REQREP0_REQ_H

#ifdef __cplusplus
extern "C" {
#endif

NNG_DECL int nng_req0_open(nng_socket *);
NNG_DECL int nng_req0_open_raw(nng_socket *);

#ifndef nng_req_open
#define nng_req_open nng_req0_open
#endif
#ifndef nng_req_open_raw
#define nng_req_open_raw nng_req0_open_raw
#endif

#define NNG_REQ0_SELF 0x30
#define NNG_REQ0_PEER 0x31
#define NNG_REQ0_SELF_NAME "req"
#define NNG_REQ0_PEER_NAME "rep"

#define NNG_OPT_REQ_RESENDTIME "req:resend-time"

#ifdef __cplusplus
}
#endif

#endif // NNG_PROTOCOL_REQREP0_REQ_H
