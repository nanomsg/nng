#
# Copyright 2021 Staysail Systems, Inc. <info@staysail.tech>
#
# This software is supplied under the terms of the MIT License, a
# copy of which should be located in the distribution where this
# file was obtained (LICENSE.txt).  A copy of the license may also be
# found online at https://opensource.org/licenses/MIT.
#

#  Build performance tests.

nng_directory(perf)

if (NNG_TESTS)
     macro (add_nng_perf NAME)
        add_executable (${NAME} perf.c)
        target_link_libraries (${NAME} nng nng_private)
    endmacro (add_nng_perf)

    add_nng_perf(remote_lat)
    add_nng_perf(local_lat)
    add_nng_perf(local_thr)
    add_nng_perf(remote_thr)
    add_nng_perf(inproc_thr)
    add_nng_perf(inproc_lat)

    add_test (NAME nng.inproc_lat COMMAND inproc_lat 64 10000)
    set_tests_properties (nng.inproc_lat PROPERTIES TIMEOUT 30)

    add_test (NAME nng.inproc_thr COMMAND inproc_thr 1400 10000)
    set_tests_properties (nng.inproc_thr PROPERTIES TIMEOUT 30)

    add_executable (pubdrop pubdrop.c)
    target_link_libraries(pubdrop nng nng_private)
endif ()
