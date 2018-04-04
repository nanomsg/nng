//
// Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#ifndef NNG_PROTOCOL_BUS0_BUS_H
#define NNG_PROTOCOL_BUS0_BUS_H

#ifdef __cplusplus
extern "C" {
#endif

NNG_DECL int nng_bus0_open(nng_socket *);

NNG_DECL int nng_bus0_open_raw(nng_socket *);

#ifndef nng_bus_open
#define nng_bus_open nng_bus0_open
#endif

#ifndef nng_bus_open_raw
#define nng_bus_open_raw nng_bus0_open_raw
#endif

#ifdef __cplusplus
}
#endif

#endif // NNG_PROTOCOL_BUS0_BUS_H
