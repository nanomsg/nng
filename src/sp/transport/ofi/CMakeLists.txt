#
# Copyright 2026
#
# This software is supplied under the terms of the MIT License, a
# copy of which should be located in the distribution where this
# file was obtained (LICENSE.txt).
#

nng_sources(ofi.c)
target_link_libraries(nng PRIVATE PkgConfig::OFI)
target_link_libraries(nng_testing PRIVATE PkgConfig::OFI)
nng_test(ofi_test)
