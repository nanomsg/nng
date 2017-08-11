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
    macro (add_nng_test NAME TIMEOUT)
    endmacro (add_nng_test)
endif ()

add_nng_test(bus 5)
add_nng_test(event 5)
add_nng_test(idhash 5)
add_nng_test(inproc 5)
add_nng_test(ipc 5)
add_nng_test(list 5)
add_nng_test(platform 5)
add_nng_test(reqrep 5)
add_nng_test(pipeline 5)
add_nng_test(pollfd 5)
add_nng_test(pubsub 5)
add_nng_test(resolv 10)
add_nng_test(sock 5)
add_nng_test(survey 5)
add_nng_test(tcp 5)
add_nng_test(scalability 20)
add_nng_test(message 5)

# compatbility tests
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
