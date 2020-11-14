#
# Copyright 2020 Staysail Systems, Inc. <info@staysail.tech>
#
# This software is supplied under the terms of the MIT License, a
# copy of which should be located in the distribution where this
# file was obtained (LICENSE.txt).  A copy of the license may also be
# found online at https://opensource.org/licenses/MIT.
#

if (NNG_TLS_ENGINE STREQUAL "mbed")
    message(WARNING "
        ************************************************************
        Linking against Mbed TLS changes license terms (Apache 2.0).
        Consult a lawyer and the license files for details.
        ************************************************************")
    nng_sources(tls.c)
    nng_defines(NNG_TLS_ENGINE_INIT=nng_tls_engine_init_mbed)
    nng_defines(NNG_TLS_ENGINE_FINI=nng_tls_engine_fini_mbed)
    nng_defines(NNG_SUPP_TLS)

    # If Mbed TLS was added by a consuming project, then we should use that
    # instance of it, instead of configuring our own.
    if (TARGET mbedtls)
        nng_link_libraries(mbedtls)
    else()
        find_package(mbedTLS REQUIRED)
        nng_link_libraries(${MBEDTLS_LIBRARIES})
        nng_include_directories(${MBEDTLS_INCLUDE_DIR})
    endif()
endif()
