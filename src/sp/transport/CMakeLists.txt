#
# Copyright 2025 Staysail Systems, Inc. <info@staystail.tech>
#
# This software is supplied under the terms of the MIT License, a
# copy of which should be located in the distribution where this
# file was obtained (LICENSE.txt).  A copy of the license may also be
# found online at https://opensource.org/licenses/MIT.
#

#  Transports.
nng_directory(transport)

add_subdirectory(socket)
add_subdirectory(inproc)
add_subdirectory(ipc)
add_subdirectory(tcp)
add_subdirectory(tls)
add_subdirectory(dtls)
add_subdirectory(udp)
add_subdirectory(ws)

if (NNG_TRANSPORT_OFI)
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(OFI REQUIRED IMPORTED_TARGET libfabric)
    nng_defines(NNG_TRANSPORT_OFI)
    if (NNG_OFI_PROVIDER AND NOT NNG_OFI_PROVIDER STREQUAL "")
        nng_defines(NNG_OFI_DEFAULT_PROVIDER="${NNG_OFI_PROVIDER}")
    endif ()
    add_subdirectory(ofi)
endif ()
