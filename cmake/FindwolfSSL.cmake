#
# Copyright 2024 Staysail Systems, Inc. <info@staysail.tech>
#
# This software is supplied under the terms of the MIT License, a
# copy of which should be located in the distribution where this
# file was obtained (LICENSE.txt).  A copy of the license may also be
# found online at https://opensource.org/licenses/MIT.
#

#
# Try to find the wolfSSL library.  We only support modern wolfSSL,
# not the older CyaSSL.
#
# Sets the following:
#
#  WOLFSSL_INCLUDE_DIR  - Where to find wolfssl/ssl.h, etc.
#  WOLFSSL_FOUND        - True if we found wolfSSL.
#  WOLFSSL_LIBRARIES    - The wolfSSL library (libwolfssl).
#  WOLFSSL_LIBRARY      - The wolfSSL library (libwolfssl).
#  WOLFSSL_VERSION      - $major.$minor.$revision (e.g. ``3.13.0``).
#
# Adds wolfSSL::wolfssl target for the library.
#
# Hints:
#
# Set ``WOLFSSL_ROOT_DIR`` to the root directory of wolfSSL installation.
#

set(_WOLFSSL_ROOT_HINTS ${WOLFSSL_ROOT_DIR} ENV WOLFSSL_ROOT_DIR)

include(FindPackageHandleStandardArgs)
include(CMakePushCheckState)

find_path(WOLFSSL_INCLUDE_DIR
    NAMES wolfssl/ssl.h
    HINTS ${_WOLFSSL_ROOT_HINTS}
    PATHS /usr/local
    PATH_SUFFIXES include)

find_library(WOLFSSL_LIBRARY
    NAMES wolfssl
    HINTS ${_WOLFSSL_ROOT_HINTS}
    PATHS /usr/local
    PATH_SUFFIXES lib)

set(WOLFSSL_LIBRARIES ${WOLFSSL_LIBRARY})
if (${WOLFSSL_LIBRARY-NOTFOUND})
    message(FATAL_ERROR "Failed to find wolfSSL library")
endif()

mark_as_advanced(WOLFSSL_INCLUDE_DIR WOLFSSL_LIBRARY)

# Extract the version from the header... hopefully it matches the library.
file(STRINGS ${WOLFSSL_INCLUDE_DIR}/wolfssl/version.h _WOLFSSL_VERLINE
    REGEX "^#define[ \t]+LIBWOLFSSL_VERSION_STRING[\t ].*")
string(REGEX REPLACE ".*WOLFSSL_VERSION_STRING[\t ]+\"(.*)\"" "\\1" WOLFSSL_VERSION ${_WOLFSSL_VERLINE})

add_library(wolfSSL::wolfssl UNKNOWN IMPORTED)

set_target_properties(wolfSSL::wolfssl PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${WOLFSSL_INCLUDE_DIR}")
set_target_properties(wolfSSL::wolfssl PROPERTIES IMPORTED_LOCATION "${WOLFSSL_LIBRARY}")

set(wolfSSL_TARGET wolfssl::wolfssl)

find_package_handle_standard_args(wolfSSL
    REQUIRED_VARS WOLFSSL_LIBRARY WOLFSSL_INCLUDE_DIR VERSION_VAR WOLFSSL_VERSION)
