#
#   Copyright (c) 2012 Martin Sustrik  All rights reserved.
#   Copyright (c) 2013 GoPivotal, Inc.  All rights reserved.
#   Copyright (c) 2015-2016 Jack R. Dunaway. All rights reserved.
#   Copyright 2016 Franklin "Snaipe" Mathieu <franklinmathieu@gmail.com>
#   Copyright 2017 Garrett D'Amore <garrett@damore.org>
#   Copyright 2017 Capitar IT Group BV <info@capitar.com>
#
#   Permission is hereby granted, free of charge, to any person obtaining a copy
#   of this software and associated documentation files (the "Software"),
#   to deal in the Software without restriction, including without limitation
#   the rights to use, copy, modify, merge, publish, distribute, sublicense,
#   and/or sell copies of the Software, and to permit persons to whom
#   the Software is furnished to do so, subject to the following conditions:
#
#   The above copyright notice and this permission notice shall be included
#   in all copies or substantial portions of the Software.
#
#   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
#   THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
#   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
#   FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
#   IN THE SOFTWARE.
#

#  Build unit tests.

include_directories(AFTER SYSTEM ${PROJECT_SOURCE_DIR}/src)

if (NNG_TESTS)

    if (THREADS_HAVE_PTHREAD_ARG)
        add_definitions (-pthread)
    endif()

    # convey tests -- verify the test framework works!
    add_executable(convey_test convey_test.c convey.c)
    if (CMAKE_THREAD_LIBS_INIT)
        target_link_libraries (convey_test "${CMAKE_THREAD_LIBS_INIT}")
    endif()
    add_test (NAME convey_test COMMAND convey_test
        -v -d -p ENV_TEST=ON -p ANOTHERNAME -p AGAIN=yes extra)
    set_tests_properties( convey_test PROPERTIES TIMEOUT 2)
    list (APPEND all_tests convey_test) 

    set (TEST_PORT 12100)
    macro (add_nng_test NAME TIMEOUT)
        list (APPEND all_tests ${NAME})
        add_executable (${NAME} ${NAME}.c convey.c)
        target_link_libraries (${NAME} ${PROJECT_NAME}_static)
        target_link_libraries (${NAME} ${NNG_REQUIRED_LIBRARIES})
        target_compile_definitions(${NAME} PUBLIC -DNNG_STATIC_LIB)
        if (CMAKE_THREAD_LIBS_INIT)
            target_link_libraries (${NAME} "${CMAKE_THREAD_LIBS_INIT}")
        endif()

        add_test (NAME ${NAME} COMMAND ${NAME} -v -p TEST_PORT=${TEST_PORT})
        set_tests_properties (${NAME} PROPERTIES TIMEOUT ${TIMEOUT})
        math (EXPR TEST_PORT "${TEST_PORT}+20")
    endmacro (add_nng_test)

    # Compatibility tests are only added if all of the legacy protocols
    # are present.  It's not worth trying to figure out which of these
    # should work and which shouldn't.
    if (NNG_PROTO_BUS0 AND
        NNG_PROTO_PAIR0 AND
        NNG_PROTO_REQ0 AND
        NNG_PROTO_REP0 AND
        NNG_PROTO_PUB0 AND
        NNG_PROTO_SUB0 AND
        NNG_PROTO_PUSH0 AND
        NNG_PROTO_PULL0)

        macro (add_nng_compat_test NAME TIMEOUT)
            list (APPEND all_tests ${NAME})
            add_executable (${NAME} ${NAME}.c)
            target_link_libraries (${NAME} ${PROJECT_NAME}_static)
            target_link_libraries (${NAME} ${NNG_REQUIRED_LIBRARIES})
            target_compile_definitions(${NAME} PUBLIC -DNNG_STATIC_LIB)
            if (CMAKE_THREAD_LIBS_INIT)
                target_link_libraries (${NAME} "${CMAKE_THREAD_LIBS_INIT}")
            endif()

            add_test (NAME ${NAME} COMMAND ${NAME} ${TEST_PORT})
            set_tests_properties (${NAME} PROPERTIES TIMEOUT ${TIMEOUT})
            math (EXPR TEST_PORT "${TEST_PORT}+10")
        endmacro (add_nng_compat_test)
    else ()
        macro (add_nng_compat_test NAME TIMEOUT)
        endmacro (add_nng_compat_test)
        message (STATUS "Compatibility tests disabled (unconfigured legacy protocols)")
    endif ()

    macro (add_nng_cpp_test NAME TIMEOUT)
        if (NOT NNG_ENABLE_COVERAGE)
            enable_language (CXX)
            list (APPEND all_tests ${NAME})
            add_executable (${NAME} ${NAME}.cc)
            target_link_libraries (${NAME} ${PROJECT_NAME}_static)
            target_link_libraries (${NAME} ${NNG_REQUIRED_LIBRARIES})
            target_compile_definitions(${NAME} PUBLIC -DNNG_STATIC_LIB)
            if (CMAKE_THREAD_LIBS_INIT)
                target_link_libraries (${NAME} "${CMAKE_THREAD_LIBS_INIT}")
            endif()

            add_test (NAME ${NAME} COMMAND ${NAME} ${TEST_PORT})
            set_tests_properties (${NAME} PROPERTIES TIMEOUT ${TIMEOUT})
            math (EXPR TEST_PORT "${TEST_PORT}+10")
        endif()
    endmacro (add_nng_cpp_test)


else ()
    macro (add_nng_test NAME TIMEOUT)
    endmacro (add_nng_test)
    macro (add_nng_compat_test NAME TIMEOUT)
    endmacro (add_nng_compat_test)
    macro (add_nng_cpp_test NAME TIMEOUT)
    endmacro (add_nng_cpp_test)
endif ()

add_nng_test(aio 5)
add_nng_test(base64 5)
add_nng_test(bus 5)
add_nng_test(files 5)
add_nng_test(idhash 5)
add_nng_test(inproc 5)
add_nng_test(ipc 5)
add_nng_test(list 5)
add_nng_test(platform 5)
add_nng_test(reqrep 5)
add_nng_test(pipeline 5)
add_nng_test(pollfd 5)
add_nng_test(pubsub 5)
add_nng_test(reconnect 5)
add_nng_test(resolv 10)
add_nng_test(sock 5)
add_nng_test(survey 5)
add_nng_test(synch 5)
add_nng_test(transport 5)
add_nng_test(tls 10)
add_nng_test(tcp 5)
add_nng_test(tcp6 5)
add_nng_test(scalability 20)
add_nng_test(message 5)
add_nng_test(device 5)
add_nng_test(errors 2)
add_nng_test(pair1 5)
add_nng_test(udp 5)
add_nng_test(zt 60)
add_nng_test(multistress 60)

# compatbility tests
# We only support these if ALL the legacy protocols are supported.  This
# is because we don't want to make modifications to partially enable some
# of these tests.  Folks minimizing the library probably don't care too
# much about these anyway.
add_nng_compat_test(compat_block 5)
add_nng_compat_test(compat_bug777 5)
add_nng_compat_test(compat_bus 5)
add_nng_compat_test(compat_cmsg 5)
add_nng_compat_test(compat_msg 5)
add_nng_compat_test(compat_iovec 5)
add_nng_compat_test(compat_device 5)
add_nng_compat_test(compat_pair 5)
add_nng_compat_test(compat_pipeline 5)
add_nng_compat_test(compat_reqrep 5)
add_nng_compat_test(compat_survey 5)
add_nng_compat_test(compat_reqttl 5)
add_nng_compat_test(compat_shutdown 5)

# c++ tests
add_nng_cpp_test(cplusplus_pair 5)
