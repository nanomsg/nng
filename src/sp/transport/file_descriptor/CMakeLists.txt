#
# Copyright 2023 Pat Maddox <pat@patmaddox.com>
# Copyright 2020 Staysail Systems, Inc. <info@staysail.tech>
# Copyright 2018 Capitar IT Group BV <info@capitar.com>
#
# This software is supplied under the terms of the MIT License, a
# copy of which should be located in the distribution where this
# file was obtained (LICENSE.txt).  A copy of the license may also be
# found online at https://opensource.org/licenses/MIT.
#

# file descriptor protocol
nng_directory(file_descriptor)

nng_sources_if(NNG_TRANSPORT_FILE_DESCRIPTOR file_descriptor.c)
nng_headers_if(NNG_TRANSPORT_FILE_DESCRIPTOR nng/transport/file_descriptor/file_descriptor.h)
nng_defines_if(NNG_TRANSPORT_FILE_DESCRIPTOR NNG_TRANSPORT_FILE_DESCRIPTOR)
nng_test(file_descriptor_test)
