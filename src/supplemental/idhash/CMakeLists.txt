#
# Copyright 2023 Staysail Systems, Inc. <info@staysail.tech>
#
# This software is supplied under the terms of the MIT License, a
# copy of which should be located in the distribution where this
# file was obtained (LICENSE.txt).  A copy of the license may also be
# found online at https://opensource.org/licenses/MIT.
#

nng_sources_if(NNG_SUPP_IDHASH idhash.c idhash.h)
nng_test_if(NNG_SUPP_IDHASH idhash_test)
