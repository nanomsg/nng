#
# Copyright 2024 Staysail Systems, Inc. <info@staystail.tech>
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
add_subdirectory(ws)
add_subdirectory(zerotier)
add_subdirectory(udp)
