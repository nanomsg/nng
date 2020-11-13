#
# Copyright 2020 Staysail Systems, Inc. <info@staysail.tech>
#
# This software is supplied under the terms of the MIT License, a
# copy of which should be located in the distribution where this
# file was obtained (LICENSE.txt).  A copy of the license may also be
# found online at https://opensource.org/licenses/MIT.
#

nng_sources_if(NNG_SUPP_BASE64
        base64.c
        base64.h)

nng_test_if(NNG_SUPP_BASE64
        base64_test)
