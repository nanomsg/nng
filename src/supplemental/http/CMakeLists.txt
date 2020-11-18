#
# Copyright 2020 Staysail Systems, Inc. <info@staysail.tech>
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

nng_sources(http_public.c http_api.h)
nng_headers(nng/supplemental/http/http.h)

nng_defines_if(NNG_SUPP_HTTP NNG_SUPP_HTTP)
nng_sources_if(NNG_SUPP_HTTP
        http_client.c
        http_chunk.c
        http_conn.c
        http_msg.c
        http_public.c
        http_schemes.c
        http_server.c)
