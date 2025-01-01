#
# Copyright 2025 Staysail Systems, Inc. <info@staysail.tech>
# Copyright 2017 Capitar IT Group BV <info@capitar.com>
#
# This software is supplied under the terms of the MIT License, a
# copy of which should be located in the distribution where this
# file was obtained (LICENSE.txt).  A copy of the license may also be
# found online at https://opensource.org/licenses/MIT.
#

if (NNG_SUPP_WEBSOCKET)
    nng_sources(base64.c base64.h sha1.c sha1.h websocket.c websocket.h)
    nng_test(sha1_test)
    nng_test(base64_test)
else ()
    nng_sources(stub.c)
endif ()
nng_test(wssfile_test)
nng_test(websocket_test)
