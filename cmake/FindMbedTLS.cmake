#
# Copyright 2024 Staysail Systems, Inc. <info@staysail.tech>
# Copyright 2017 Capitar IT Group BV <info@capitar.com>
#
# This software is supplied under the terms of the MIT License, a
# copy of which should be located in the distribution where this
# file was obtained (LICENSE.txt).  A copy of the license may also be
# found online at https://opensource.org/licenses/MIT.
#

#
# Try to find the Mbed TLS libraries.
# This tries to emulate the same expectations that the stock Mbed TLS
# module uses in Mbed TLS v3.x.
#
# Sets the following:
#
#  MbedTLS_FOUND          - True if we found Mbed TLS.
#  MbedTLS_TARGET         - Target of the mbedtls library.
#  MbedX509_TARGET        - Target of the mbedx509 library.
#  MbedCrypto_TARGET      - Target of the mbedcrypto library.
#  MbedTLS_VERSION        - $major.$minor.$revision (e.g. ``2.6.0``).
#
#  MBEDTLS_CRYPTO_LIBRARY - The mbedcrypto library.
#  MBEDTLS_X509_LIBRARY   - The mbedx509 library.
#  MBEDTLS_TLS_LIBRARY    - The mbedtls library.
#  MBEDTLS_LIBRARIES      - List of all three Mbed TLS libraries.
#
# Hints:
#
# Set ``MBEDTLS_ROOT`` to the root directory of Mbed TLS installation.
#

set(_MBEDTLS_ROOT_HINTS ${MBEDTLS_ROOT} ENV MBEDTLS_ROOT)
if (NOT _MBEDTLS_ROOT_HINTS)
    set(_MBEDTLS_ROOT_HINTS ${MBEDTLS_ROOT_DIR} ENV MBEDTLS_ROOT_DIR)
endif()

set(_MBED_REQUIRED_VARS MbedTLS_TARGET MbedX509_TARGET MbedCrypto_TARGET MbedTLS_VERSION)

include(FindPackageHandleStandardArgs)
include(CMakePushCheckState)

find_path(_MBEDTLS_INCLUDE_DIR
        NAMES mbedtls/ssl.h
        HINTS ${_MBEDTLS_ROOT_HINTS}
        # PATHS /usr/local
        PATH_SUFFIXES include)

find_library(_MBEDCRYPTO_LIBRARY
        NAMES mbedcrypto
        HINTS ${_MBEDTLS_ROOT_HINTS}
        # PATHS /usr/local
        # PATH_SUFFIXES lib
        )

find_library(_MBEDX509_LIBRARY
        NAMES mbedx509
        HINTS ${_MBEDTLS_ROOT_HINTS}
        #PATHS /usr/local
        # PATH_SUFFIXES lib
        )

find_library(_MBEDTLS_LIBRARY
        NAMES mbedtls
        HINTS ${_MBEDTLS_ROOT_HINTS}
        #PATHS /usr/local
        #PATH_SUFFIXES lib
        )

if ("${_MBEDTLS_TLS_LIBRARY}" STREQUAL "_MBEDTLS_TLS_LIBRARY-NOTFOUND")
    message("Failed to find Mbed TLS library")
else()

    cmake_push_check_state(RESET)
    set(CMAKE_REQUIRED_INCLUDES ${_MBEDTLS_INCLUDE_DIR} ${CMAKE_REQUIRED_INCLUDES_${BUILD_TYPE}})
    list(APPEND CMAKE_REQUIRED_LIBRARIES ${_MBEDTLS_LIBRARY} ${_MBEDX509_LIBRARY} ${_MBEDCRYPTO_LIBRARY})
    check_symbol_exists(mbedtls_ssl_init "mbedtls/ssl.h" _MBEDTLS_V2_OR_NEWER)
    cmake_pop_check_state()

    if (NOT _MBEDTLS_V2_OR_NEWER)
        message("Mbed TLS too old (must be version 2 or newer) ${_MBEDTLS_V2_OR_NEWER} UP ${_MbedTLS_V2}")

    else()
        # Extract the version from the header... hopefully it matches the library.
        if (EXISTS ${_MBEDTLS_INCLUDE_DIR}/mbedtls/build_info.h)
            file(STRINGS ${_MBEDTLS_INCLUDE_DIR}/mbedtls/build_info.h _MBEDTLS_VERLINE
                    REGEX "^#define[ \t]+MBEDTLS_VERSION_STRING[\t ].*")
        else ()
            file(STRINGS ${_MBEDTLS_INCLUDE_DIR}/mbedtls/version.h _MBEDTLS_VERLINE
                    REGEX "^#define[ \t]+MBEDTLS_VERSION_STRING[\t ].*")
        endif ()

        string(REGEX REPLACE ".*MBEDTLS_VERSION_STRING[\t ]+\"(.*)\"" "\\1" MbedTLS_VERSION ${_MBEDTLS_VERLINE})
        message("Mbed TLS version: ${MbedTLS_VERSION}")
    endif()
endif()


add_library(MbedTLS::mbedtls UNKNOWN IMPORTED)
add_library(MbedTLS::mbedx509 UNKNOWN IMPORTED)
add_library(MbedTLS::mbedcrypto UNKNOWN IMPORTED)


set_target_properties(MbedTLS::mbedtls PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${_MBEDTLS_INCLUDE_DIR}")
set_target_properties(MbedTLS::mbedx509 PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${_MBEDTLS_INCLUDE_DIR}")
set_target_properties(MbedTLS::mbedcrypto PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${_MBEDTLS_INCLUDE_DIR}")

set_target_properties(MbedTLS::mbedtls PROPERTIES IMPORTED_LOCATION "${_MBEDTLS_LIBRARY}")
set_target_properties(MbedTLS::mbedx509 PROPERTIES IMPORTED_LOCATION "${_MBEDX509_LIBRARY}")
set_target_properties(MbedTLS::mbedcrypto PROPERTIES IMPORTED_LOCATION "${_MBEDCRYPTO_LIBRARY}")

set(MbedTLS_TARGET MbedTLS::mbedtls)
set(MbedX509_TARGET MbedTLS::mbedx509)
set(MbedCrypto_TARGET MbedTLS::mbedcrypto)

find_package_handle_standard_args(MbedTLS REQUIRED_VARS ${_MBED_REQUIRED_VARS})
mark_as_advanced(${_MBED_REQUIRED_VARS})

