#
# Copyright 2025 Staysail Systems, Inc. <info@staystail.tech>
# Copyright 2018 Capitar IT Group BV <info@capitar.com>
#
# This software is supplied under the terms of the MIT License, a
# copy of which should be located in the distribution where this
# file was obtained (LICENSE.txt).  A copy of the license may also be
# found online at https://opensource.org/licenses/MIT.
#

#  PAIRv1 protocol
nng_directory(pair1)

nng_sources_if(NNG_PROTO_PAIR1 pair.c pair1_poly.c)
nng_defines_if(NNG_PROTO_PAIR1 NNG_HAVE_PAIR1)

nng_test(pair1_test)
nng_test(pair1_poly_test)
