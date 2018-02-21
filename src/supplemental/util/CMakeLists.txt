#
# Copyright 2018 Capitar IT Group BV <info@capitar.com>
# Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
#
# This software is supplied under the terms of the MIT License, a
# copy of which should be located in the distribution where this
# file was obtained (LICENSE.txt).  A copy of the license may also be
# found online at https://opensource.org/licenses/MIT.
#

set(SUPP_PLATFORM_SOURCES
	supplemental/util/platform.c)

install(FILES platform.h DESTINATION include/nng/supplemental/util)
set(NNG_SOURCES ${NNG_SOURCES} ${SUPP_PLATFORM_SOURCES} PARENT_SCOPE)
