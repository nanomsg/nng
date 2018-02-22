#
# Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
# Copyright 2018 Capitar IT Group BV <info@capitar.com>
#
# This software is supplied under the terms of the MIT License, a
# copy of which should be located in the distribution where this
# file was obtained (LICENSE.txt).  A copy of the license may also be
# found online at https://opensource.org/licenses/MIT.
#

# TLS transport

if (NNG_TRANSPORT_TLS)
    set(TLS_SOURCES transport/tls/tls.c transport/tls/tls.h)
    set(TLS_HEADERS transport/tls/tls.h)
endif()

set(NNG_SOURCES ${NNG_SOURCES} ${TLS_SOURCES} PARENT_SCOPE)
set(NNG_HEADERS ${NNG_HEADERS} ${TLS_HEADERS} PARENT_SCOPE)
