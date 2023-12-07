#
# Copyright 2023 Staysail Systems, Inc. <info@staysail.tech>
#
# This software is supplied under the terms of the MIT License, a
# copy of which should be located in the distribution where this
# file was obtained (LICENSE.txt).  A copy of the license may also be
# found online at https://opensource.org/licenses/MIT.
#

nng_sources(nn.c)

set(NNG_TEST_PREFIX ${NNG_TEST_PREFIX}.compat.nanomsg)

nng_test(compat_msg_test)
nng_test(compat_tcp_test)
