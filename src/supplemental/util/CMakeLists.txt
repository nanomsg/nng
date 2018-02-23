#
# Copyright 2018 Capitar IT Group BV <info@capitar.com>
# Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
#
# This software is supplied under the terms of the MIT License, a
# copy of which should be located in the distribution where this
# file was obtained (LICENSE.txt).  A copy of the license may also be
# found online at https://opensource.org/licenses/MIT.
#

set(SUPP_UTIL_SOURCES supplemental/util/options.c supplemental/util/platform.c)
set(SUPP_UTIL_HEADERS supplemental/util/options.h supplemental/util/platform.h)

set(NNG_SOURCES ${NNG_SOURCES} ${SUPP_UTIL_SOURCES} PARENT_SCOPE)
set(NNG_HEADERS ${NNG_HEADERS} ${SUPP_UTIL_HEADERS} PARENT_SCOPE)
