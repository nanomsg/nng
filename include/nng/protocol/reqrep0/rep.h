//
// Copyright 2020 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#ifndef NNG_PROTOCOL_REQREP0_REP_H
#define NNG_PROTOCOL_REQREP0_REP_H

#ifdef __cplusplus
extern "C" {
#endif

NNG_DECL int nng_rep0_open(nng_socket *);
NNG_DECL int nng_rep0_open_raw(nng_socket *);

#ifndef nng_rep_open
#define nng_rep_open nng_rep0_open
#endif

#ifndef nng_rep_open_raw
#define nng_rep_open_raw nng_rep0_open_raw
#endif

#define NNG_REP0_SELF 0x31
#define NNG_REP0_PEER 0x30
#define NNG_REP0_SELF_NAME "rep"
#define NNG_REP0_PEER_NAME "req"

#ifdef __cplusplus
}
#endif

#endif // NNG_PROTOCOL_REQREP0_REP_H
