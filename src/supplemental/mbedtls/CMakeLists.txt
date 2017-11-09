#
# Copyright 2017 Garrett D'Amore <garrett@damore.org>
# Copyright 2017 Capitar IT Group BV <info@capitar.com>
#
# This software is supplied under the terms of the MIT License, a
# copy of which should be located in the distribution where this
# file was obtained (LICENSE.txt).  A copy of the license may also be
# found online at https://opensource.org/licenses/MIT.
#

#  MBEDTLS library

# This requires the mbedTLS library be installed somewhere.  You can
# point this at a suitable installation of mbedTLS by setting
# MBEDTLS_ROOT_DIR to point at the root of the installation (prefix).

# It is possible to minimize the mbedTLS library quite a bit.  We do
# not require legacy algorithms, the net_sockets layer, the filesystem
# I/O, as well as various other tidbits.  We provide an entropy source,
# so you can disable that in mbedTLS too.  You may disable fallback support,
# as we only support TLS v1.2 at present.  (You may also therefore remove
# code to support older versions of TLS/SSL.)  You may also remove DTLS,
# since we're not using it now (nor are we likely to in the near feature).
# Also you may remove support for ZLIB compression, we don't use it either
# (and it would be insecure to do so.)  PEM and X509 writing (encoding)
# is not needed (but parse support is!)  You may also remove session support,
# as we don't use that either.
#
# (Look for a sample config.h in this directory, if you want to build
# a minimized version just for nng.)

# What we do require is support for TLSv1.2

if (NNG_MBEDTLS_ENABLE)
    set(SUPP_SOURCES supplemental/mbedtls/tls.c supplemental/tls.h)
    Find_Package(mbedTLS REQUIRED)

    # If it isn't already in the link list, add the TLS libraries there. 
    # or something, so we take care not to duplicate it).
    list(FIND NNG_REQUIRED_LIBRARIES ${MBEDTLS_TLS_LIBRARY} _index)
    if (_index EQUAL -1)
        set(NNG_REQUIRED_LIBRARIES ${NNG_REQUIRED_LIBRARIES} ${MBEDTLS_LIBRARIES})
        set(NNG_REQUIRED_LIBRARIES ${NNG_REQUIRED_LIBRARIES} PARENT_SCOPE)
    endif()

    # Likewise for the include search path.
    list(FIND NNG_REQUIRED_INCLUDES ${MBEDTLS_INCLUDE_DIR} _index)
    if (_index EQUAL -1)
        set(NNG_REQUIRED_INCLUDES ${NNG_REQUIRED_INCLUDES} ${MBEDTLS_INCLUDE_DIR})
        set(NNG_REQUIRED_INCLUDES ${NNG_REQUIRED_INCLUDES} PARENT_SCOPE)
    endif()
endif()

set(NNG_SOURCES ${NNG_SOURCES} ${SUPP_SOURCES} PARENT_SCOPE)
