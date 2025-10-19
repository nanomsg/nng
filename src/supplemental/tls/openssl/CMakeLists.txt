#
# Copyright 2025 Staysail Systems, Inc. <info@staysail.tech>
#
# This software is supplied under the terms of the MIT License, a
# copy of which should be located in the distribution where this
# file was obtained (LICENSE.txt).  A copy of the license may also be
# found online at https://opensource.org/licenses/MIT.
#
include(FindThreads)

if (NNG_TLS_ENGINE STREQUAL "openssl")
    message(NOTICE "
        ************************************************************
        Linking against OpenSSL may change license terms.
        Consult a lawyer and the license files for details.
        ************************************************************")
    nng_sources(openssl.c)

    find_package(OpenSSL 3.5 REQUIRED)

    if (OPENSSL_FOUND)
        message(STATUS "OpenSSL found: ${OPENSSL_VERSION}")
        target_include_directories(nng PRIVATE ${OPENSSL_INCLUDE_DIR})
        target_include_directories(nng_testing PRIVATE ${OPENSSL_INCLUDE_DIR})
        nng_link_libraries_public(PRIVATE ${OPENSSL_LIBRARIES})

    endif()

    nng_defines(NNG_SUPP_TLS)
    nng_defines(NNG_SUPP_TLS_PSK)
    nng_defines(NNG_TLS_ENGINE_OPENSSL)
endif ()
