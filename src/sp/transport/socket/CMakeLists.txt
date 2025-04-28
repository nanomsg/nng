#
# Copyright 2025 Staysail Systems, Inc. <info@staysail.tech>
#
# This software is supplied under the terms of the MIT License, a
# copy of which should be located in the distribution where this
# file was obtained (LICENSE.txt).  A copy of the license may also be
# found online at https://opensource.org/licenses/MIT.
#

# File Descriptor (or Handle) based connections
nng_directory(socket)

if (NNG_TRANSPORT_FDC)
    nng_sources(sockfd.c)
    nng_defines(NNG_TRANSPORT_FDC)
    nng_test(sockfd_test)
endif()
