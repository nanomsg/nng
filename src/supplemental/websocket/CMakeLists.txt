#
# Copyright 2019 Staysail Systems, Inc. <info@staysail.tech>
# Copyright 2017 Capitar IT Group BV <info@capitar.com>
#
# This software is supplied under the terms of the MIT License, a
# copy of which should be located in the distribution where this
# file was obtained (LICENSE.txt).  A copy of the license may also be
# found online at https://opensource.org/licenses/MIT.
#

if (NNG_SUPP_WEBSOCKET)
    nng_sources(websocket.c websocket.h)
    if (NNG_SUPP_TLS)
        nng_test(wssfile_test)
    endif ()
else ()
    nng_sources(stub.c)
endif ()
nng_test(websocket_test)
