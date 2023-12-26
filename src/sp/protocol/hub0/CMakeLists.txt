#
# Copyright 2022 Cogent Embedded, Inc.
#
# This software is supplied under the terms of the MIT License, a
# copy of which should be located in the distribution where this
# file was obtained (LICENSE.txt).  A copy of the license may also be
# found online at https://opensource.org/licenses/MIT.
#

nng_directory(hub0)

nng_sources_if(NNG_PROTO_HUB0 hub.c)
nng_headers_if(NNG_PROTO_HUB0 nng/protocol/hub0/hub.h)
nng_defines_if(NNG_PROTO_HUB0 NNG_HAVE_HUB0)

nng_test(hub_test)