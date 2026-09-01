#
# Copyright 2025 Staysail Systems, Inc. <info@staysail.tech>
# Copyright 2018 Capitar IT Group BV <info@capitar.com>
#
# This software is supplied under the terms of the MIT License, a
# copy of which should be located in the distribution where this
# file was obtained (LICENSE.txt).  A copy of the license may also be
# found online at https://opensource.org/licenses/MIT.
#

# ipc protocol
nng_directory(ipc)

if (NNG_TRANSPORT_IPC)
    nng_sources(ipc.c)
    nng_defines(NNG_TRANSPORT_IPC)
    nng_test(ipc_test)

    # OpenCppCoverage identifies itself as a debugger, which makes acutest run
    # its cases in-process. Exercise that lifecycle in the ordinary Windows
    # test job too.
    if (WIN32 AND NNG_TESTS)
        add_test(NAME ${NNG_TEST_PREFIX}.ipc_no_exec_test
            COMMAND ipc_test --no-exec -t -v)
        set_tests_properties(${NNG_TEST_PREFIX}.ipc_no_exec_test
            PROPERTIES TIMEOUT 180)
    endif()
endif()
