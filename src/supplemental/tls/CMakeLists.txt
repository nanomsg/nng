#
# Copyright 2025 Staysail Systems, Inc. <info@staysail.tech>
# Copyright 2018 Capitar IT Group BV <info@capitar.com>
# Copyright 2019 Devolutions <info@devolutions.net>
#

#
# This software is supplied under the terms of the MIT License, a
# copy of which should be located in the distribution where this
# file was obtained (LICENSE.txt).  A copy of the license may also be
# found online at https://opensource.org/licenses/MIT.
#

if (NNG_ENABLE_TLS)
    # List of TLS engines we support.  TLS engines must support TLS 1.2 or better,
    # and must also support DTLS.  Support for PSK is preferred.
    set(NNG_TLS_ENGINES mbed wolf openssl none)
    # We assume Mbed for now.
    set(NNG_TLS_ENGINE mbed CACHE STRING "TLS engine to use.")
    set_property(CACHE NNG_TLS_ENGINE PROPERTY STRINGS ${NNG_TLS_ENGINES})
else ()
    set(NNG_TLS_ENGINE none)
endif ()

if (NOT NNG_TLS_ENGINE STREQUAL "none")
    nng_test(tls_test)
endif ()

add_subdirectory(mbedtls)
add_subdirectory(wolfssl)
add_subdirectory(openssl)

if (NNG_ENABLE_TLS)
    nng_sources(tls_common.c tls_dialer.c tls_listener.c tls_stream.c)
    nng_sources(tls_api.h tls_common.h tls_engine.h tls_stream.h)
else()
    nng_sources(tls_stubs.c)
endif()
