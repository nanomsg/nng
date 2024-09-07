#
# Copyright 2024 Staysail Systems, Inc. <info@staysail.tech>
# Copyright 2018 Capitar IT Group BV <info@capitar.com>
#
# This software is supplied under the terms of the MIT License, a
# copy of which should be located in the distribution where this
# file was obtained (LICENSE.txt).  A copy of the license may also be
# found online at https://opensource.org/licenses/MIT.
#

# inproc protocol
nng_directory(inproc)

nng_sources_if(NNG_TRANSPORT_INPROC inproc.c)
nng_defines_if(NNG_TRANSPORT_INPROC NNG_TRANSPORT_INPROC)
