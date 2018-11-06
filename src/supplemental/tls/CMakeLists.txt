#
# Copyright 2018 Capitar IT Group BV <info@capitar.com>
# Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
#
# This software is supplied under the terms of the MIT License, a
# copy of which should be located in the distribution where this
# file was obtained (LICENSE.txt).  A copy of the license may also be
# found online at https://opensource.org/licenses/MIT.
#

if (NNG_SUPP_TLS)
	set(NNG_SUPP_TLS_MBEDTLS ON)
	set(_DEFS -DNNG_SUPP_TLS)
endif()

set(_SRCS supplemental/tls/tls.h)
set(_HDRS supplemental/tls/tls.h)

# For now we only support the ARM mbedTLS library.
if (NNG_SUPP_TLS_MBEDTLS)

    message(WARNING "
        ************************************************************
        Linking against mbedTLS changes license terms (Apache 2.0).
        Consult a lawyer and the license files for details.
        ************************************************************")

	find_package(mbedTLS REQUIRED)
	set(_LIBS ${MBEDTLS_LIBRARIES})
	set(_INCS ${MBEDTLS_INCLUDE_DIR})
	list(APPEND _SRCS supplemental/tls/mbedtls/tls.c)

else()
	list(APPEND _SRCS supplemental/tls/none/tls.c)
endif()

list(APPEND NNG_DEFS ${_DEFS})
list(APPEND NNG_SRCS ${_SRCS})
list(APPEND NNG_HDRS ${_HDRS})
list(APPEND NNG_LIBS ${_LIBS})
list(APPEND NNG_INCS ${_INCS})

set(NNG_DEFS ${NNG_DEFS} PARENT_SCOPE)
set(NNG_SRCS ${NNG_SRCS} PARENT_SCOPE)
set(NNG_HDRS ${NNG_HDRS} PARENT_SCOPE)
set(NNG_LIBS ${NNG_LIBS} PARENT_SCOPE)
set(NNG_INCS ${NNG_INCS} PARENT_SCOPE)
