#
# Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
# Copyright 2018 Capitar IT Group BV <info@capitar.com>
#
# This software is supplied under the terms of the MIT License, a
# copy of which should be located in the distribution where this
# file was obtained (LICENSE.txt).  A copy of the license may also be
# found online at https://opensource.org/licenses/MIT.
#

# ipc protocol

if (NNG_TRANSPORT_IPC)
    set(IPC_SOURCES transport/ipc/ipc.c transport/ipc/ipc.h)
    set(IPC_HEADERS transport/ipc/ipc.h)
endif()

set(NNG_SOURCES ${NNG_SOURCES} ${IPC_SOURCES} PARENT_SCOPE)
set(NNG_HEADERS ${NNG_HEADERS} ${IPC_HEADERS} PARENT_SCOPE)
