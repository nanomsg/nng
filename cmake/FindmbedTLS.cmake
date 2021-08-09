#
# Copyright 2020 Staysail Systems, Inc. <info@staysail.tech>
# Copyright 2017 Capitar IT Group BV <info@capitar.com>
#
# This software is supplied under the terms of the MIT License, a
# copy of which should be located in the distribution where this
# file was obtained (LICENSE.txt).  A copy of the license may also be
# found online at https://opensource.org/licenses/MIT.
#

#
# Try to find the Mbed TLS libraries.
#
# Sets the following:
#
#  MBEDTLS_INCLUDE_DIR    - Where to find mbedtls/ssl.h, etc.
#  MBEDTLS_FOUND          - True if we found Mbed TLS.
#  MBEDTLS_CRYPTO_LIBRARY - The mbedcrypto library.
#  MBEDTLS_X509_LIBRARY   - The mbedx509 library.
#  MBEDTLS_TLS_LIBRARY    - The mbedtls library.
#  MBEDTLS_LIBRARIES      - List of all three Mbed TLS libraries.
#  MBEDTLS_VERSION        - $major.$minor.$revision (e.g. ``2.6.0``).
#
# Hints:
#
# Set ``MBEDTLS_ROOT_DIR`` to the root directory of Mbed TLS installation.
#

set(_MBEDTLS_ROOT_HINTS ${MBEDTLS_ROOT_DIR} ENV MBEDTLS_ROOT_DIR)

include(FindPackageHandleStandardArgs)

find_path(MBEDTLS_INCLUDE_DIR
        NAMES mbedtls/ssl.h
        HINTS ${_MBEDTLS_ROOT_HINTS}
        PATHS /usr/local
        PATH_SUFFIXES include)

find_library(MBEDTLS_CRYPTO_LIBRARY
        NAMES mbedcrypto
        HINTS ${_MBEDTLS_ROOT_HINTS}
        PATHS /usr/local
        PATH_SUFFIXES lib)

find_library(MBEDTLS_X509_LIBRARY
        NAMES mbedx509
        HINTS ${_MBEDTLS_ROOT_HINTS}
        PATHS /usr/local
        PATH_SUFFIXES lib)

find_library(MBEDTLS_TLS_LIBRARY
        NAMES mbedtls
        HINTS ${_MBEDTLS_ROOT_HINTS}
        PATHS /usr/local
        PATH_SUFFIXES lib)

set(MBEDTLS_LIBRARIES
        ${MBEDTLS_TLS_LIBRARY}
        ${MBEDTLS_X509_LIBRARY}
        ${MBEDTLS_CRYPTO_LIBRARY})

if (${MBEDTLS_TLS_LIBRARY-NOTFOUND})
    message(FATAL_ERROR "Failed to find Mbed TLS library")
endif ()

mark_as_advanced(
        MBEDSSL_INCLUDE_DIR
        MBEDTLS_LIBRARIES
        MBEDTLS_CRYPTO_LIBRARY
        MBEDTLS_X509_LIBRARY
        MBEDTLS_TLS_LIBRARY)

# Extract the version from the header... hopefully it matches the library.
if (EXISTS ${MBEDTLS_INCLUDE_DIR}/mbedtls/build_info.h)
    file(STRINGS ${MBEDTLS_INCLUDE_DIR}/mbedtls/build_info.h _MBEDTLS_VERLINE
            REGEX "^#define[ \t]+MBEDTLS_VERSION_STRING[\t ].*")
else ()
    file(STRINGS ${MBEDTLS_INCLUDE_DIR}/mbedtls/version.h _MBEDTLS_VERLINE
            REGEX "^#define[ \t]+MBEDTLS_VERSION_STRING[\t ].*")
endif ()

string(REGEX REPLACE ".*MBEDTLS_VERSION_STRING[\t ]+\"(.*)\"" "\\1" MBEDTLS_VERSION ${_MBEDTLS_VERLINE})

find_package_handle_standard_args(mbedTLS
        REQUIRED_VARS MBEDTLS_TLS_LIBRARY MBEDTLS_CRYPTO_LIBRARY MBEDTLS_X509_LIBRARY MBEDTLS_INCLUDE_DIR VERSION_VAR MBEDTLS_VERSION)

