#
# Copyright 2017 Garrett D'Amore <garrett@damore.org>
# Copyright 2017 Capitar IT Group BV <info@capitar.com>
#
# This software is supplied under the terms of the MIT License, a
# copy of which should be located in the distribution where this
# file was obtained (LICENSE.txt).  A copy of the license may also be
# found online at https://opensource.org/licenses/MIT.
#

# inproc protocol

if (NNG_TRANSPORT_INPROC)
    set(INPROC_SOURCES transport/inproc/inproc.c transport/inproc/inproc.h)
    install(FILES inproc.h DESTINATION include/nng/transport/inproc)
endif()

set(NNG_SOURCES ${NNG_SOURCES} ${INPROC_SOURCES} PARENT_SCOPE)
