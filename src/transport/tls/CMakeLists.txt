#
# Copyright 2017 Staysail Systems, Inc. <info@staysail.tech>
# Copyright 2017 Capitar IT Group BV <info@capitar.com>
#
# This software is supplied under the terms of the MIT License, a
# copy of which should be located in the distribution where this
# file was obtained (LICENSE.txt).  A copy of the license may also be
# found online at https://opensource.org/licenses/MIT.
#

# TLS transport

if (NNG_TRANSPORT_TLS)
    set(TLS_SOURCES transport/tls/tls.c transport/tls/tls.h)
    install(FILES tls.h DESTINATION include/nng/transport/tls)
    
endif()

set(NNG_SOURCES ${NNG_SOURCES} ${TLS_SOURCES} PARENT_SCOPE)
