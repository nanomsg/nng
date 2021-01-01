#
# Copyright 2019 Staysail Systems, Inc. <info@staysail.tech>
# Copyright 2018 Capitar IT Group BV <info@capitar.com>
#
# This software is supplied under the terms of the MIT License, a
# copy of which should be located in the distribution where this
# file was obtained (LICENSE.txt).  A copy of the license may also be
# found online at https://opensource.org/licenses/MIT.
#

#  Pipeline protocol
nng_directory(pipeline0)

nng_sources_if(NNG_PROTO_PUSH0 push.c)
nng_headers_if(NNG_PROTO_PUSH0 nng/protocol/pipeline0/push.h)
nng_defines_if(NNG_PROTO_PUSH0 NNG_HAVE_PUSH0)

nng_sources_if(NNG_PROTO_PULL0 pull.c)
nng_headers_if(NNG_PROTO_PULL0 nng/protocol/pipeline0/pull.h)
nng_defines_if(NNG_PROTO_PULL0 NNG_HAVE_PULL0)

nng_test(pull_test)
nng_test(push_test)
