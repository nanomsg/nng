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
    set(NNG_WOLFSSL_IN_TREE OFF)
    if (TARGET wolfssl)
        set(NNG_WOLFSSL_TARGET wolfssl)
        get_target_property(NNG_WOLFSSL_TARGET_IMPORTED wolfssl IMPORTED)
        if (NOT NNG_WOLFSSL_TARGET_IMPORTED)
            set(NNG_WOLFSSL_IN_TREE ON)
        endif ()
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

    # CMake feature checks can link imported targets, but normal targets made
    # by add_subdirectory are unavailable to their isolated try_compile
    # project.  For an in-tree wolfSSL, test the configured headers instead:
    # they and the library are built from the same source and configuration.
    if (NNG_WOLFSSL_IN_TREE)
        set(NNG_WOLFSSL_CHECK_INCLUDES)
        foreach (NNG_WOLFSSL_INCLUDE_PROPERTY
                INTERFACE_INCLUDE_DIRECTORIES
                INTERFACE_SYSTEM_INCLUDE_DIRECTORIES
                INCLUDE_DIRECTORIES)
            get_target_property(NNG_WOLFSSL_INCLUDE_DIRS wolfssl
                ${NNG_WOLFSSL_INCLUDE_PROPERTY})
            if (NNG_WOLFSSL_INCLUDE_DIRS)
                foreach (NNG_WOLFSSL_INCLUDE_DIR IN LISTS NNG_WOLFSSL_INCLUDE_DIRS)
                    # Keep build-interface paths, including wolfSSL's
                    # generated options.h directory.  GENEX_STRIP would
                    # discard the whole BUILD_INTERFACE expression.
                    if (NNG_WOLFSSL_INCLUDE_DIR MATCHES
                            "^\\$<BUILD_INTERFACE:(.*)>$")
                        set(NNG_WOLFSSL_INCLUDE_DIR "${CMAKE_MATCH_1}")
                    elseif (NNG_WOLFSSL_INCLUDE_DIR MATCHES
                            "^\\$<INSTALL_INTERFACE:.*>$")
                        set(NNG_WOLFSSL_INCLUDE_DIR "")
                    else ()
                        string(GENEX_STRIP "${NNG_WOLFSSL_INCLUDE_DIR}"
                            NNG_WOLFSSL_INCLUDE_DIR)
                    endif ()
                    if (NNG_WOLFSSL_INCLUDE_DIR)
                        list(APPEND NNG_WOLFSSL_CHECK_INCLUDES
                            "${NNG_WOLFSSL_INCLUDE_DIR}")
                    endif ()
                endforeach ()
            endif ()
        endforeach ()
        list(REMOVE_DUPLICATES NNG_WOLFSSL_CHECK_INCLUDES)

        set(NNG_WOLFSSL_CHECK_DEFINITIONS)
        foreach (NNG_WOLFSSL_DEFINITION_PROPERTY
                INTERFACE_COMPILE_DEFINITIONS
                COMPILE_DEFINITIONS)
            get_target_property(NNG_WOLFSSL_DEFINITIONS wolfssl
                ${NNG_WOLFSSL_DEFINITION_PROPERTY})
            if (NNG_WOLFSSL_DEFINITIONS)
                foreach (NNG_WOLFSSL_DEFINITION IN LISTS NNG_WOLFSSL_DEFINITIONS)
                    string(GENEX_STRIP "${NNG_WOLFSSL_DEFINITION}"
                        NNG_WOLFSSL_DEFINITION)
                    if (NNG_WOLFSSL_DEFINITION)
                        list(APPEND NNG_WOLFSSL_CHECK_DEFINITIONS
                            "-D${NNG_WOLFSSL_DEFINITION}")
                    endif ()
                endforeach ()
            endif ()
        endforeach ()
        list(REMOVE_DUPLICATES NNG_WOLFSSL_CHECK_DEFINITIONS)
    endif ()

    function(nng_wolfssl_check_function FUNCTION RESULT CONDITION)
        if (NNG_WOLFSSL_IN_TREE)
            cmake_push_check_state(RESET)
            set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)
            set(CMAKE_REQUIRED_INCLUDES ${NNG_WOLFSSL_CHECK_INCLUDES})
            set(CMAKE_REQUIRED_DEFINITIONS ${NNG_WOLFSSL_CHECK_DEFINITIONS})
            check_c_source_compiles("\
                #include <wolfssl/ssl.h>
                #if !(${CONDITION})
                #error wolfSSL function is disabled by its configuration
                #endif
                int main(void) { (void) &${FUNCTION}; return 0; }"
                ${RESULT})
            cmake_pop_check_state()
        else ()
            check_library_exists(${NNG_WOLFSSL_TARGET} ${FUNCTION} "" ${RESULT})
        endif ()
    endfunction()

    nng_wolfssl_check_function(wolfSSL_CTX_LoadCRLBuffer NNG_WOLFSSL_HAVE_CRL
        "defined(HAVE_CRL) && !defined(NO_CERTS)")
    nng_wolfssl_check_function(wolfSSL_get_verify_result NNG_WOLFSSL_HAVE_VERIFY
        "defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL) || defined(OPENSSL_ALL)")
    nng_wolfssl_check_function(wolfSSL_CTX_set_default_passwd_cb NNG_WOLFSSL_HAVE_PASSWORD
        "defined(WOLFSSL_ENCRYPTED_KEYS)")
    nng_wolfssl_check_function(wolfSSL_CTX_SetTmpDH NNG_WOLFSSL_HAVE_DH
        "!defined(NO_DH)")
    nng_wolfssl_check_function(wolfSSL_CTX_set_psk_client_callback NNG_WOLFSSL_HAVE_PSK
        "!defined(NO_PSK)")
    # This API has no feature macro; its declaration is introduced with
    # wolfSSL 5.9.0 and its implementation is compiled unconditionally.
    nng_wolfssl_check_function(wolfSSL_check_ip_address NNG_WOLFSSL_HAVE_CHECK_IP "1")

    # A CMake-built wolfSSL supplies the configuration used to build the
    # library in wolfssl/options.h.  Make it visible to NNG when present;
    # otherwise optional APIs can be declared differently from the library.
    cmake_push_check_state(RESET)
    if (NNG_WOLFSSL_IN_TREE)
        set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)
        set(CMAKE_REQUIRED_INCLUDES ${NNG_WOLFSSL_CHECK_INCLUDES})
        set(CMAKE_REQUIRED_DEFINITIONS
            ${NNG_WOLFSSL_CHECK_DEFINITIONS} -DWOLFSSL_USE_OPTIONS_H)
    else ()
        set(CMAKE_REQUIRED_LIBRARIES ${NNG_WOLFSSL_TARGET})
        set(CMAKE_REQUIRED_DEFINITIONS -DWOLFSSL_USE_OPTIONS_H)
    endif ()
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
    if (NNG_WOLFSSL_IN_TREE)
        set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)
        set(CMAKE_REQUIRED_INCLUDES ${NNG_WOLFSSL_CHECK_INCLUDES})
        set(CMAKE_REQUIRED_DEFINITIONS ${NNG_WOLFSSL_CHECK_DEFINITIONS})
    else ()
        set(CMAKE_REQUIRED_LIBRARIES ${NNG_WOLFSSL_TARGET})
    endif ()
    if (NNG_WOLFSSL_USE_OPTIONS_H)
        list(APPEND CMAKE_REQUIRED_DEFINITIONS -DWOLFSSL_USE_OPTIONS_H)
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

    if (NNG_WOLFSSL_HAVE_CHECK_IP)
        nng_defines(NNG_WOLFSSL_HAVE_CHECK_IP)
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
