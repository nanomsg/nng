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
	set(TLS_DEFINES -DNNG_SUPP_TLS)
endif()
set(TLS_SOURCES supplemental/tls/tls.h)

# For now we only support the ARM mbedTLS library.
if (NNG_SUPP_TLS_MBEDTLS)

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
	set(TLS_SOURCES ${TLS_SOURCES} supplemental/tls/mbedtls/tls.c)
else()
	set(TLS_SOURCES ${TLS_SOURCES} supplemental/tls/none/tls.c)
endif()

set(TLS_HEADERS supplemental/tls/tls.h)

set(NNG_DEFINES ${NNG_DEFINES} ${TLS_DEFINES} PARENT_SCOPE)
set(NNG_SOURCES ${NNG_SOURCES} ${TLS_SOURCES} PARENT_SCOPE)
set(NNG_HEADERS ${NNG_HEADERS} ${TLS_HEADERS} PARENT_SCOPE)
