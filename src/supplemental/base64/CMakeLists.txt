#
# Copyright 2017 Capitar IT Group BV <info@capitar.com>
# Copyright 2017 Staysail Systems, Inc. <info@staysail.tech>
#
# This software is supplied under the terms of the MIT License, a
# copy of which should be located in the distribution where this
# file was obtained (LICENSE.txt).  A copy of the license may also be
# found online at https://opensource.org/licenses/MIT.
#

if (NNG_SUPP_BASE64)
        set(BASE64_SOURCES
                supplemental/base64/base64.c
                supplemental/base64/base64.h)
endif()
set(NNG_SOURCES ${NNG_SOURCES} ${BASE64_SOURCES} PARENT_SCOPE)
