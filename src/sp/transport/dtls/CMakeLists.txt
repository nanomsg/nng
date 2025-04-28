#
# Copyright 2025 Staysail Systems, Inc. <info@staysail.tech>
#
# This software is supplied under the terms of the MIT License, a
# copy of which should be located in the distribution where this
# file was obtained (LICENSE.txt).  A copy of the license may also be
# found online at https://opensource.org/licenses/MIT.
#

# DTLS transport
nng_directory(dtls)

if (NNG_TRANSPORT_DTLS)
    nng_sources(dtls.c)
    nng_defines(NNG_TRANSPORT_DTLS)
    nng_test(dtls_tran_test)
endif()
