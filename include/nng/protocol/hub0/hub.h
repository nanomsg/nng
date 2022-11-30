//
// Copyright 2022 Cogent Embedded, Inc.
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//
#ifndef NNG_PROTOCOL_HUB0_HUB_H
#define NNG_PROTOCOL_HUB0_HUB_H

#ifdef __cplusplus
extern "C" {
#endif

#define NNG_HUB0_SELF 0x10
#define NNG_HUB0_PEER 0x10
#define NNG_HUB0_SELF_NAME "hub"
#define NNG_HUB0_PEER_NAME "hub"

NNG_DECL int nng_hub0_open(nng_socket *);

#ifndef nng_hub_open
#define nng_hub_open nng_hub0_open
#endif

#ifdef __cplusplus
}
#endif

#endif /* NNG_PROTOCOL_HUB0_HUB_H_ */
