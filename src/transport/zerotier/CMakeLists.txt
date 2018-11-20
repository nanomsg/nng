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

option (NNG_TRANSPORT_ZEROTIER "Enable ZeroTier transport (requires libzerotiercore)." OFF)
mark_as_advanced(NNG_TRANSPORT_ZEROTIER)

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

    find_package(zerotiercore REQUIRED)
    set(_PKGS zerotiercore)
    set(_LIBS zerotiercore::zerotiercore)
    set(_DEFS -DNNG_TRANSPORT_ZEROTIER)

    set(_SRCS transport/zerotier/zerotier.c ${PROJECT_SOURCE_DIR}/include/nng/transport/zerotier/zerotier.h)

    set(NNG_DEFS ${NNG_DEFS} ${_DEFS} PARENT_SCOPE)
    set(NNG_LIBS ${NNG_LIBS} ${_LIBS} PARENT_SCOPE)
    set(NNG_PKGS ${NNG_PKGS} ${_PKGS} PARENT_SCOPE)
    set(NNG_SRCS ${NNG_SRCS} ${_SRCS} PARENT_SCOPE)

endif()
