#
# Copyright 2020 Staysail Systems, Inc. <info@staysail.tech>
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

nng_directory(zerotier)

if (NNG_TRANSPORT_ZEROTIER)

    # NB: As we wind up linking libzerotiercore.a into the application,
    # this means that your application will *also* need to either be licensed
    # under the GPLv3, or you will need to have a commercial license from
    # ZeroTier permitting its use elsewhere.

    message(WARNING "
        ************************************************************
        Linking against zerotiercore changes license terms.
        Consult a lawyer and the license files for details.
        ************************************************************")

    find_package(zerotiercore REQUIRED)

    nng_link_libraries(zerotiercore::zerotiercore)
    nng_defines(NNG_TRANSPORT_ZEROTIER)
    nng_sources(zerotier.c zthash.c)
    nng_headers(nng/transport/zerotier/zerotier.h)
endif()
