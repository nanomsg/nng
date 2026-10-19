#
# Copyright 2026 Staysail Systems, Inc. <info@staysail.tech>
#
# This software is supplied under the terms of the MIT License, a
# copy of which should be located in the distribution where this
# file was obtained (LICENSE.txt).  A copy of the license may also be
# found online at https://opensource.org/licenses/MIT.
#
include(FindThreads)
include(CMakePushCheckState)

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

        cmake_push_check_state(RESET)
        set(CMAKE_REQUIRED_INCLUDES ${OPENSSL_INCLUDE_DIR})
        unset(NNG_OPENSSL_HAVE_DTLS13 CACHE)
        check_c_source_compiles("\
            #include <openssl/ssl.h>
            #if !defined(DTLS1_3_VERSION) || defined(OPENSSL_NO_DTLS1_3)
            #error DTLS 1.3 is unavailable
            #endif
            int main(void) { return 0; }" NNG_OPENSSL_HAVE_DTLS13)
        cmake_pop_check_state()
        if (NNG_OPENSSL_HAVE_DTLS13)
            nng_defines(NNG_SUPP_DTLS_1_3)
        endif ()

        nng_test(openssl_test)
        if (NNG_TESTS)
            target_include_directories(openssl_test PRIVATE ${OPENSSL_INCLUDE_DIR})
        endif ()

    endif()

    nng_defines(NNG_SUPP_TLS)
    nng_defines(NNG_SUPP_TLS_PSK)
    nng_defines(NNG_TLS_ENGINE_OPENSSL)
endif ()
