#
# Copyright 2017 Garrett D'Amore <garrett@damore.org>
# Copyright 2017 Capitar IT Group BV <info@capitar.com>
#
# This software is supplied under the terms of the MIT License, a
# copy of which should be located in the distribution where this
# file was obtained (LICENSE.txt).  A copy of the license may also be
# found online at https://opensource.org/licenses/MIT.
#

# ipc protocol

if (NNG_TRANSPORT_IPC)
    set(IPC_SOURCES transport/ipc/ipc.c transport/ipc/ipc.h)
    install(FILES ipc.h DESTINATION include/nng/transport/ipc)
endif()

set(NNG_SOURCES ${NNG_SOURCES} ${IPC_SOURCES} PARENT_SCOPE)
