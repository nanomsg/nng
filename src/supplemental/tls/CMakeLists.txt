#
# Copyright 2017 Capitar IT Group BV <info@capitar.com>
# Copyright 2017 Staysail Systems, Inc. <info@staysail.tech>
#
# This software is supplied under the terms of the MIT License, a
# copy of which should be located in the distribution where this
# file was obtained (LICENSE.txt).  A copy of the license may also be
# found online at https://opensource.org/licenses/MIT.
#

if (NNG_SUPP_TLS)
	set(NNG_SUPP_TLS_MBEDTLS ON)
	set(TLS_SOURCES supplemental/tls/tls.h)
endif()

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
endif()

set(NNG_SOURCES ${NNG_SOURCES} ${TLS_SOURCES} PARENT_SCOPE)
