#
# Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
# Copyright 2018 Capitar IT Group BV <info@capitar.com>
#
# This software is supplied under the terms of the MIT License, a
# copy of which should be located in the distribution where this
# file was obtained (LICENSE.txt).  A copy of the license may also be
# found online at https://opensource.org/licenses/MIT.
#

option (NNG_ENABLE_HTTP "Enable HTTP API" ON)
if (NNG_ENABLE_HTTP)
    set(NNG_SUPP_HTTP ON)
endif()
mark_as_advanced(NNG_ENABLE_HTTP)
set(_SRCS supplemental/http/http_public.c
    ${PROJECT_SOURCE_DIR}/include/nng/supplemental/http/http.h
    supplemental/http/http_api.h)

if (NNG_SUPP_HTTP)
        set(_DEFS -DNNG_SUPP_HTTP)
        list(APPEND _SRCS
                supplemental/http/http_client.c
                supplemental/http/http_chunk.c
                supplemental/http/http_conn.c
                supplemental/http/http_msg.c
                supplemental/http/http_public.c
                supplemental/http/http_server.c)
endif()

set(NNG_DEFS ${NNG_DEFS} ${_DEFS} PARENT_SCOPE)
set(NNG_SRCS ${NNG_SRCS} ${_SRCS} PARENT_SCOPE)
