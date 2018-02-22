#
# Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
# Copyright 2018 Capitar IT Group BV <info@capitar.com>
#
# This software is supplied under the terms of the MIT License, a
# copy of which should be located in the distribution where this
# file was obtained (LICENSE.txt).  A copy of the license may also be
# found online at https://opensource.org/licenses/MIT.
#

if (NNG_SUPP_HTTP)
        set(HTTP_DEFINES -DNNG_SUPP_HTTP)
        set(HTTP_HEADERS
                supplemental/http/http.h)
        set(HTTP_SOURCES
                supplemental/http/http.h
                supplemental/http/http_api.h
                supplemental/http/http_client.c
                supplemental/http/http_conn.c
                supplemental/http/http_msg.c
                supplemental/http/http_public.c
                supplemental/http/http_server.c)
else()
        set(HTTP_SOURCES
                supplemental/http/http.h
                supplemental/http/http_api.h
                supplemental/http/http_public.c)
        set(HTTP_HEADERS
                supplemental/http/http.h)
endif()

set(NNG_DEFINES ${NNG_DEFINES} ${HTTP_DEFINES} PARENT_SCOPE)
set(NNG_SOURCES ${NNG_SOURCES} ${HTTP_SOURCES} PARENT_SCOPE)
set(NNG_HEADERS ${NNG_HEADERS} ${HTTP_HEADERS} PARENT_SCOPE)
