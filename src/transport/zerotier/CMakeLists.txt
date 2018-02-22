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

set (NNG_TRANSPORT_ZEROTIER_SOURCE "" CACHE PATH "Location of ZeroTier source tree.")
mark_as_advanced(NNG_TRANSPORT_ZEROTIER_SOURCE)

if (NNG_TRANSPORT_ZEROTIER)

    # We use the libzerotiercore.a library, which is unfortunately a C++ object
    # even though it exposes only public C symbols.  It would be extremely
    # helpful if libzerotiercore didn't make us carry the whole C++ runtime
    # behind us.  The user must specify the location of the ZeroTier source
    # tree (dev branch for now, and already compiled please) by setting the
    # NNG_ZEROTIER_SOURCE macro.
    # NB: This needs to be the zerotierone tree, not the libzt library.
    # This is because we don't access the API, but instead use the low
    # level zerotiercore functionality directly.
    # NB: As we wind up linking libzerotiercore.a into the application,
    # this means that your application will *also* need to either be licensed
    # under the GPLv3, or you will need to have a commercial license from
    # ZeroTier permitting its use elsewhere.
    
    enable_language(CXX)
    find_library(NNG_LIBZTCORE zerotiercore PATHS ${NNG_TRANSPORT_ZEROTIER_SOURCE})
    if (NNG_LIBZTCORE)
        set(CMAKE_REQUIRED_INCLUDES ${NNG_TRANSPORT_ZEROTIER_SOURCE}/include)
        message(STATUS "C++ ${CMAKE_CXX_IMPLICIT_LINK_LIBRARIES}")
        set(CMAKE_REQUIRED_LIBRARIES ${CMAKE_REQUIRED_LIBRARIES} ${NNG_LIBZTCORE} ${CMAKE_CXX_IMPLICIT_LINK_LIBRARIES})
        set(NNG_REQUIRED_LIBRARIES ${NNG_REQUIRED_LIBRARIES} ${NNG_LIBZTCORE} ${CMAKE_CXX_IMPLICIT_LINK_LIBRARIES} PARENT_SCOPE)
        set(NNG_REQUIRED_INCLUDES ${NNG_REQUIRED_INCLUDES} ${NNG_TRANSPORT_ZEROTIER_SOURCE}/include PARENT_SCOPE)
        nng_check_sym(ZT_Node_join ZeroTierOne.h HAVE_ZTCORE)
    endif()
    if (NOT HAVE_ZTCORE)
        message (FATAL_ERROR "Cannot find ZeroTier components")
    endif()
    message(STATUS "Found ZeroTier at ${NNG_LIBZTCORE}")

    set(ZT_SOURCES transport/zerotier/zerotier.c transport/zerotier/zerotier.h)
    set(ZT_HEADERS transport/zerotier/zerotier.h)
endif()

set(NNG_SOURCES ${NNG_SOURCES} ${ZT_SOURCES} PARENT_SCOPE)
set(NNG_HEADERS ${NNG_HEADERS} ${ZT_HEADERS} PARENT_SCOPE)
