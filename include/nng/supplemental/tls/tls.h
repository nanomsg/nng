//
// Copyright 2024 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#ifndef NNG_SUPPLEMENTAL_TLS_TLS_H
#define NNG_SUPPLEMENTAL_TLS_TLS_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

#include <nng/nng.h>

// Note that TLS functions may be stubbed out if TLS is not enabled in
// the build.

// nng_tls_engine_name returns the "name" of the TLS engine.  If no
// TLS engine support is enabled, then "none" is returned.
NNG_DECL const char *nng_tls_engine_name(void);

// nng_tls_engine_description returns the "description" of the TLS engine.
// If no TLS engine support is enabled, then an empty string is returned.
NNG_DECL const char *nng_tls_engine_description(void);

// nng_tls_engine_fips_mode returns true if the engine is in FIPS 140-2 mode.
NNG_DECL bool nng_tls_engine_fips_mode(void);

#ifdef __cplusplus
}
#endif

#endif // NNG_SUPPLEMENTAL_TLS_TLS_H
