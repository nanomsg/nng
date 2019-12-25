#
# Copyright 2019 Staysail Systems, Inc. <info@staysail.tech>
# Copyright 2018 Capitar IT Group BV <info@capitar.com>
#
# This software is supplied under the terms of the MIT License, a
# copy of which should be located in the distribution where this
# file was obtained (LICENSE.txt).  A copy of the license may also be
# found online at https://opensource.org/licenses/MIT.
#

# ipc protocol
option (NNG_TRANSPORT_IPC "Enable IPC transport." ON)
mark_as_advanced(NNG_TRANSPORT_IPC)

nng_sources_if(NNG_TRANSPORT_IPC ipc.c)
nng_headers_if(NNG_TRANSPORT_IPC nng/transport/ipc/ipc.h)
nng_defines_if(NNG_TRANSPORT_IPC NNG_TRANSPORT_IPC)