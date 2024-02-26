#
# Copyright 2024 Staysail Systems, Inc. <info@staystail.tech>
#
# This software is supplied under the terms of the MIT License, a
# copy of which should be located in the distribution where this
# file was obtained (LICENSE.txt).  A copy of the license may also be
# found online at https://opensource.org/licenses/MIT.
#

#  Platforms.
nng_directory(platform)

add_subdirectory(posix)
add_subdirectory(windows)

nng_test(platform_test)
nng_test(resolver_test)
nng_test(udp_test)
