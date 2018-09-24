#
# Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
# Copyright 2018 Capitar IT Group BV <info@capitar.com>
#
# This software is supplied under the terms of the MIT License, a
# copy of which should be located in the distribution where this
# file was obtained (LICENSE.txt).  A copy of the license may also be
# found online at https://opensource.org/licenses/MIT.
#

# ZeroTier protocol

if (NNG_TRANSPORT_ZEROTIER)

    # The zerotiercore project will have been found at the top level
    # of the package.  This is necessary because import libraries cannot
    # percolate back to the parent tree.

    # NB: As we wind up linking libzerotiercore.a into the application,
    # this means that your application will *also* need to either be licensed
    # under the GPLv3, or you will need to have a commercial license from
    # ZeroTier permitting its use elsewhere.

    message(WARNING "
        ************************************************************
        Linking against zerotiercore changes license terms (GPLv3).
        Consult a lawyer and the license files for details.
        ************************************************************")

    set(NNG_REQUIRED_LIBRARIES ${NNG_REQUIRED_LIBRARIES} zerotiercore::zerotiercore)
    set(NNG_REQUIRED_LIBRARIES ${NNG_REQUIRED_LIBRARIES} PARENT_SCOPE)

    set(ZT_SOURCES transport/zerotier/zerotier.c transport/zerotier/zerotier.h)
    set(ZT_HEADERS transport/zerotier/zerotier.h)

    set(NNG_SOURCES ${NNG_SOURCES} ${ZT_SOURCES} PARENT_SCOPE)
    set(NNG_HEADERS ${NNG_HEADERS} ${ZT_HEADERS} PARENT_SCOPE)
endif()
