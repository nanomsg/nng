#
# Copyright 2025 Staysail Systems, Inc. <info@staysail.tech>
#
# This software is supplied under the terms of the MIT License, a
# copy of which should be located in the distribution where this
# file was obtained (LICENSE.txt).  A copy of the license may also be
# found online at https://opensource.org/licenses/MIT.
#
include(FindThreads)
include(CMakePushCheckState)

if (NNG_TLS_ENGINE STREQUAL "wolf")
    message(NOTICE "
        ************************************************************
        Linking against WolfSSL may change license terms.
        Consult a lawyer and the license files for details.
        ************************************************************")
    nng_sources(wolfssl.c)

    # If wolfSSL was added by a consuming project, then we should use that
    # instance of it, instead of configuring our own.
    if (TARGET wolfssl)
        set(NNG_WOLFSSL_TARGET wolfssl)
        nng_link_libraries(wolfssl)
    else()
        # We want to prefer config mode over our local find package.
        if (NOT (DEFINED CMAKE_FIND_PACKAGE_PREFER_CONFIG))
            set(CMAKE_FIND_PACKAGE_PREFER_CONFIG TRUE)
            nng_find_package(wolfSSL)
            unset(CMAKE_FIND_PACKAGE_PREFER_CONFIG)
        else()
            nng_find_package(wolfSSL)
        endif()
        set(NNG_WOLFSSL_TARGET wolfssl::wolfssl)
        nng_link_libraries_public(wolfssl::wolfssl)
    endif()

    check_library_exists(${NNG_WOLFSSL_TARGET} wolfSSL_CTX_LoadCRLBuffer "" NNG_WOLFSSL_HAVE_CRL)
    check_library_exists(${NNG_WOLFSSL_TARGET} wolfSSL_get_verify_result "" NNG_WOLFSSL_HAVE_VERIFY)
    check_library_exists(${NNG_WOLFSSL_TARGET} wolfSSL_CTX_set_default_passwd_cb "" NNG_WOLFSSL_HAVE_PASSWORD)
    check_library_exists(${NNG_WOLFSSL_TARGET} wolfSSL_CTX_SetTmpDH "" NNG_WOLFSSL_HAVE_DH)
    check_library_exists(${NNG_WOLFSSL_TARGET} wolfSSL_CTX_set_psk_client_callback "" NNG_WOLFSSL_HAVE_PSK)

    # A CMake-built wolfSSL supplies the configuration used to build the
    # library in wolfssl/options.h.  Make it visible to NNG when present;
    # otherwise optional APIs can be declared differently from the library.
    cmake_push_check_state(RESET)
    set(CMAKE_REQUIRED_LIBRARIES ${NNG_WOLFSSL_TARGET})
    set(CMAKE_REQUIRED_DEFINITIONS -DWOLFSSL_USE_OPTIONS_H)
    check_c_source_compiles("\
        #include <wolfssl/ssl.h>
        #ifndef WOLFSSL_OPTIONS_H
        #error wolfssl/options.h is unavailable
        #endif
        int main(void) { return 0; }"
        NNG_WOLFSSL_USE_OPTIONS_H)
    cmake_pop_check_state()

    if (NNG_WOLFSSL_USE_OPTIONS_H)
        nng_defines(WOLFSSL_USE_OPTIONS_H)
    endif ()

    # Checking only for the library symbol is insufficient: certificate
    # accessors are conditional in wolfSSL's headers.  Verify that the headers
    # and library agree on the declarations NNG needs before enabling them.
    cmake_push_check_state(RESET)
    set(CMAKE_REQUIRED_LIBRARIES ${NNG_WOLFSSL_TARGET})
    if (NNG_WOLFSSL_USE_OPTIONS_H)
        set(CMAKE_REQUIRED_DEFINITIONS -DWOLFSSL_USE_OPTIONS_H)
    endif ()
    check_c_source_compiles("\
        #include <wolfssl/ssl.h>
        #if !(defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL) || defined(KEEP_PEER_CERT) || defined(KEEP_OUR_CERT) || defined(SESSION_CERTS))
        #error wolfSSL certificate accessors are unavailable
        #endif
        int main(void) {
            WOLFSSL_X509 *cert = wolfSSL_get_peer_certificate((WOLFSSL *) 0);
            WOLFSSL_X509_NAME *name = wolfSSL_X509_get_subject_name(cert);
            WOLFSSL_ASN1_TIME *time = wolfSSL_X509_get_notBefore(cert);
            return (name == 0) || (time == 0);
        }"
        NNG_WOLFSSL_HAVE_PEER_CERT)
    cmake_pop_check_state()

    if (NNG_WOLFSSL_HAVE_DH)
        nng_defines(NNG_WOLFSSL_HAVE_DH)
    else ()
        message(STATUS "wolfSSL configured without DH support.")
    endif ()

    if (NNG_WOLFSSL_HAVE_CRL)
        nng_defines(NNG_WOLFSSL_HAVE_CRL)
    else ()
        message(STATUS "wolfSSL configured without CRL support.")
    endif ()

    if (NNG_WOLFSSL_HAVE_PASSWORD)
        nng_defines(NNG_WOLFSSL_HAVE_PASSWORD)
    else ()
        message(STATUS "wolfSSL configured without password support.")
    endif ()

    if (NNG_WOLFSSL_HAVE_PEER_CERT)
        nng_defines(NNG_WOLFSSL_HAVE_PEER_CERT)
    else ()
        message(STATUS "wolfSSL configured without full certificate APIs.")
        message(NOTICE "
        ************************************************************
        WolfSSL functionality for working with certificates is missing.
        Consider rebuilding WolfSSL for full functionality.
        ************************************************************")

    endif ()

    if (NNG_WOLFSSL_HAVE_PSK)
        nng_defines(NNG_SUPP_TLS_PSK)
    else ()
        message(STATUS "wolfSSL configured without pre-shared key (PSK) support.")
    endif()

    nng_defines(NNG_SUPP_TLS)
    nng_defines(NNG_TLS_ENGINE_WOLFSSL)
endif ()
