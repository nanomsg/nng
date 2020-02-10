#
# Copyright 2020 Staysail Systems, Inc. <info@staysail.tech>
# Copyright 2018 Capitar IT Group BV <info@capitar.com>
# Copyright 2019 Devolutions <info@devolutions.net>
#

#
# This software is supplied under the terms of the MIT License, a
# copy of which should be located in the distribution where this
# file was obtained (LICENSE.txt).  A copy of the license may also be
# found online at https://opensource.org/licenses/MIT.
#

nng_headers(nng/supplemental/tls/tls.h)

if (NNG_SUPP_TLS)
	# default TLS implementation for now is Mbed.
	set(NNG_SUPP_TLS_MBEDTLS ON)
	set(_DEFS -DNNG_SUPP_TLS)
endif()

nng_sources(tls_common.c engine.h)

add_subdirectory(mbedtls)

list(APPEND NNG_DEFS ${_DEFS})
list(APPEND NNG_SRCS ${_SRCS})
list(APPEND NNG_LIBS ${_LIBS})
list(APPEND NNG_INCS ${_INCS})

set(NNG_DEFS ${NNG_DEFS} PARENT_SCOPE)
set(NNG_SRCS ${NNG_SRCS} PARENT_SCOPE)
set(NNG_LIBS ${NNG_LIBS} PARENT_SCOPE)
set(NNG_INCS ${NNG_INCS} PARENT_SCOPE)
