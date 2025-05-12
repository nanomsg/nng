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

nng_sources_if(NNG_TRANSPORT_TLS dtls.c)
nng_defines_if(NNG_TRANSPORT_TLS NNG_TRANSPORT_TLS)
# nng_test_if(NNG_ENABLE_TLS tls_tran_test)
