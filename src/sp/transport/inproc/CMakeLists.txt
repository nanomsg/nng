#
# Copyright 2025 Staysail Systems, Inc. <info@staysail.tech>
# Copyright 2018 Capitar IT Group BV <info@capitar.com>
#
# This software is supplied under the terms of the MIT License, a
# copy of which should be located in the distribution where this
# file was obtained (LICENSE.txt).  A copy of the license may also be
# found online at https://opensource.org/licenses/MIT.
#

# inproc protocol
nng_directory(inproc)

if (NNG_TRANSPORT_INPROC)
    nng_sources(inproc.c)
    nng_defines(NNG_TRANSPORT_INPROC)
    nng_test(inproc_test)
endif()
