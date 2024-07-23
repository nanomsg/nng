#
# Copyright 2024 Staysail Systems, Inc. <info@staysail.tech>
#
# This software is supplied under the terms of the MIT License, a
# copy of which should be located in the distribution where this
# file was obtained (LICENSE.txt).  A copy of the license may also be
# found online at https://opensource.org/licenses/MIT.
#

if (NNG_TLS_ENGINE STREQUAL "mbed")
    message(NOTICE "
        ************************************************************
        Linking against Mbed TLS may change license terms.
        Consult a lawyer and the license files for details.
        ************************************************************")
    nng_sources(tls.c)
    nng_defines(NNG_TLS_ENGINE_INIT=nng_tls_engine_init_mbed)
    nng_defines(NNG_TLS_ENGINE_FINI=nng_tls_engine_fini_mbed)
    nng_defines(NNG_SUPP_TLS)
    # For now Mbed TLS has PSK unconditionally
    nng_defines(NNG_SUPP_TLS_PSK)
    nng_defines(NNG_TLS_ENGINE_MBEDTLS)

    # If Mbed TLS was added by a consuming project, then we should use that
    # instance of it, instead of configuring our own.
    if (TARGET mbedtls)
        nng_link_libraries(mbedtls)
    else()
        # We want to prefer config mode over our local find package.
        # mbedTLS v3 has a config file, which should work better than
        # what we do here.  We only make this override locally, to
        # avoid confounding any other package consumers, and we honor overrides.
        if (NOT (DEFINED CMAKE_FIND_PACKAGE_PREFER_CONFIG))
            set(CMAKE_FIND_PACKAGE_PREFER_CONFIG TRUE)
            find_package(MbedTLS REQUIRED)
            unset(CMAKE_FIND_PACKAGE_PREFER_CONFIG)
        else()
            find_package(MbedTLS REQUIRED)
        endif()
        nng_link_libraries_public(MbedTLS::mbedtls MbedTLS::mbedcrypto MbedTLS::mbedx509)
    endif()
endif()
