#
# Copyright 2017 Capitar IT Group BV <info@capitar.com>
# Copyright 2017 Staysail Systems, Inc. <info@staysail.tech>
#
# This software is supplied under the terms of the MIT License, a
# copy of which should be located in the distribution where this
# file was obtained (LICENSE.txt).  A copy of the license may also be
# found online at https://opensource.org/licenses/MIT.
#

set(HTTP_SOURCES
        supplemental/http/http.c
        supplemental/http/http_msg.c
        supplemental/http/server.c
        supplemental/http/client.c
        supplemental/http/http.h)
set(NNG_SOURCES ${NNG_SOURCES} ${HTTP_SOURCES} PARENT_SCOPE)
