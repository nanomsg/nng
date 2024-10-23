#
# Copyright 2024 Staysail Systems, Inc. <info@staysail.tech>
#
# This software is supplied under the terms of the MIT License, a
# copy of which should be located in the distribution where this
# file was obtained (LICENSE.txt).  A copy of the license may also be
# found online at https://opensource.org/licenses/MIT.
#

# NNG Options.  These are user configurable knobs.

include(CMakeDependentOption)

if (CMAKE_CROSSCOMPILING)
    set(NNG_NATIVE_BUILD OFF)
else ()
    set(NNG_NATIVE_BUILD ON)
endif ()

# Global options.
option(BUILD_SHARED_LIBS "Build shared library" ${BUILD_SHARED_LIBS})

# We only build command line tools and tests if we are not in a
# cross-compile situation.  Cross-compiling users who still want to
# build these must enable them explicitly.  Some of these switches
# must be enabled rather early as we use their values later.
option(NNG_TESTS "Build and run tests." ${NNG_NATIVE_BUILD})
option(NNG_TOOLS "Build extra tools." ${NNG_NATIVE_BUILD})
option(NNG_ENABLE_NNGCAT "Enable building nngcat utility." ${NNG_TOOLS})
option(NNG_ENABLE_COVERAGE "Enable coverage reporting." OFF)
# Eliding deprecated functionality can be used to build a slimmed down
# version of the library, or alternatively to test for application
# preparedness for expected feature removals (in the next major release.)
# Applications can also set the NNG_ELIDE_DEPRECATED preprocessor symbol
# before including <nng/nng.h> -- this will prevent declarations from
# being exposed to applications, but it will not affect their ABI
# availability for existing compiled applications.
# Note: Currently this breaks the test suite, so we only do it
# for the public library.
option(NNG_ELIDE_DEPRECATED "Elide deprecated functionality." OFF)

option(NNG_ENABLE_STATS "Enable statistics." ON)
mark_as_advanced(NNG_ENABLE_STATS)

# Protocols.
option (NNG_PROTO_BUS0 "Enable BUSv0 protocol." ON)
mark_as_advanced(NNG_PROTO_BUS0)

option (NNG_PROTO_PAIR0 "Enable PAIRv0 protocol." ON)
mark_as_advanced(NNG_PROTO_PAIR0)

option (NNG_PROTO_PAIR1 "Enable PAIRv1 protocol." ON)
mark_as_advanced(NNG_PROTO_PAIR1)

option (NNG_PROTO_PUSH0 "Enable PUSHv0 protocol." ON)
mark_as_advanced(NNG_PROTO_PUSH0)

option (NNG_PROTO_PULL0 "Enable PULLv0 protocol." ON)
mark_as_advanced(NNG_PROTO_PULL0)

option (NNG_PROTO_PUB0 "Enable PUBv0 protocol." ON)
mark_as_advanced(NNG_PROTO_PUB0)

option (NNG_PROTO_SUB0 "Enable SUBv0 protocol." ON)
mark_as_advanced(NNG_PROTO_SUB0)

option(NNG_PROTO_REQ0 "Enable REQv0 protocol." ON)
mark_as_advanced(NNG_PROTO_REQ0)

option(NNG_PROTO_REP0 "Enable REPv0 protocol." ON)
mark_as_advanced(NNG_PROTO_REP0)

option (NNG_PROTO_RESPONDENT0 "Enable RESPONDENTv0 protocol." ON)
mark_as_advanced(NNG_PROTO_RESPONDENT0)

option (NNG_PROTO_SURVEYOR0 "Enable SURVEYORv0 protocol." ON)
mark_as_advanced(NNG_PROTO_SURVEYOR0)

# TLS support.

# Enabling TLS is required to enable support for the TLS transport
# and WSS.  It does require a 3rd party TLS engine to be selected.
option(NNG_ENABLE_TLS "Enable TLS support." OFF)
if (NNG_ENABLE_TLS)
    set(NNG_SUPP_TLS ON)
endif ()

if (NNG_ENABLE_TLS)
    set(NNG_TLS_ENGINES mbed wolf none)
    # We assume Mbed for now.  (Someday replaced perhaps with Bear.)
    set(NNG_TLS_ENGINE mbed CACHE STRING "TLS engine to use.")
    set_property(CACHE NNG_TLS_ENGINE PROPERTY STRINGS ${NNG_TLS_ENGINES})
else ()
    set(NNG_TLS_ENGINE none)
endif ()

# HTTP API support.
option (NNG_ENABLE_HTTP "Enable HTTP API." ON)
if (NNG_ENABLE_HTTP)
    set(NNG_SUPP_HTTP ON)
endif()
mark_as_advanced(NNG_ENABLE_HTTP)

# Some sites or kernels lack IPv6 support.  This override allows us
# to prevent the use of IPv6 in environments where it isn't supported.
option (NNG_ENABLE_IPV6 "Enable IPv6." ON)
mark_as_advanced(NNG_ENABLE_IPV6)

#
# Transport Options.
#

option (NNG_TRANSPORT_INPROC "Enable inproc transport." ON)
mark_as_advanced(NNG_TRANSPORT_INPROC)

option (NNG_TRANSPORT_IPC "Enable IPC transport." ON)
mark_as_advanced(NNG_TRANSPORT_IPC)

# TCP transport
option (NNG_TRANSPORT_TCP "Enable TCP transport." ON)
mark_as_advanced(NNG_TRANSPORT_TCP)

# TLS transport
option (NNG_TRANSPORT_TLS "Enable TLS transport." ON)
mark_as_advanced(NNG_TRANSPORT_TLS)

# WebSocket
option (NNG_TRANSPORT_WS "Enable WebSocket transport." ON)
mark_as_advanced(NNG_TRANSPORT_WS)

CMAKE_DEPENDENT_OPTION(NNG_TRANSPORT_WSS "Enable WSS transport." ON
        "NNG_ENABLE_TLS" OFF)
mark_as_advanced(NNG_TRANSPORT_WSS)

option (NNG_TRANSPORT_FDC "Enable File Descriptor transport (EXPERIMENTAL)" ON)
mark_as_advanced(NNG_TRANSPORT_FDC)

option (NNG_TRANSPORT_UDP "Enable UDP transport (EXPERIMENTAL)" ON)
mark_as_advanced(NNG_TRANSPORT_UDP)

# ZeroTier
option (NNG_TRANSPORT_ZEROTIER "Enable ZeroTier transport (requires libzerotiercore)." OFF)
mark_as_advanced(NNG_TRANSPORT_ZEROTIER)

if (NNG_TRANSPORT_WS OR NNG_TRANSPORT_WSS)
    # Make sure things we *MUST* have are enabled.
    set(NNG_SUPP_WEBSOCKET ON)
    set(NNG_SUPP_HTTP ON)
    set(NNG_SUPP_BASE64 ON)
    set(NNG_SUPP_SHA1 ON)
endif()
