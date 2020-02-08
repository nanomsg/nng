#
#   Copyright 2019 Staysail Systems, Inc. <info@staysail.tech>
#   Copyright 2018 Capitar IT Group BV <info@capitar.com>
#   Copyright (c) 2012 Martin Sustrik  All rights reserved.
#   Copyright (c) 2013 GoPivotal, Inc.  All rights reserved.
#   Copyright (c) 2015-2016 Jack R. Dunaway. All rights reserved.
#   Copyright 2016 Franklin "Snaipe" Mathieu <franklinmathieu@gmail.com>
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

# Note that tests which depend on internal (not public) APIs are not
# enabled unless a static library is built.  This is because on some
# systems (e.g. Windows) we do not expose symbols that are not in the
# public API. (When CMake learns more about using mapfiles to suppress
# symbol visibility we will do this even more, to protect the namespace
# of the user.)

include_directories(AFTER SYSTEM ${PROJECT_SOURCE_DIR}/src)

# convey.c needs its own link to pthreads.
if (NOT WIN32)
    find_package(Threads)
    set(THRLIB Threads::Threads)
endif ()

if (NNG_TESTS)

    nng_check_sym(nl_langinfo langinfo.h NNG_HAVE_LANGINFO)
    if (NOT NNG_SANITIZER STREQUAL "none")
        set(TIMEOUT_FACTOR 2)
    else ()
        set(TIMEOUT_FACTOR 1)
    endif ()
    set(NNG_TEST_PORT 13000)
    macro(add_nng_test NAME TIMEOUT)
        add_executable(${NAME} ${NAME}.c convey.c)
        target_link_libraries(${NAME} ${PROJECT_NAME}_testlib ${THRLIB})
        add_test(NAME ${NAME} COMMAND ${NAME} -v -p TEST_PORT=${NNG_TEST_PORT})
        math(EXPR TIMEOUT ${TIMEOUT}*${TIMEOUT_FACTOR})
        set_tests_properties(${NAME} PROPERTIES TIMEOUT ${TIMEOUT})
        math(EXPR NNG_TEST_PORT "${NNG_TEST_PORT}+20")
    endmacro(add_nng_test)

    # Compatibility tests are only added if all of the legacy protocols
    # are present.  It's not worth trying to figure out which of these
    # should work and which shouldn't.
    macro(add_nng_compat_test NAME TIMEOUT)
        add_executable(${NAME} ${NAME}.c compat_testutil.c)
        target_link_libraries(${NAME} ${PROJECT_NAME}_testlib)
        target_include_directories(${NAME} PRIVATE
                ${PROJECT_SOURCE_DIR}/src/compat
                ${PROJECT_SOURCE_DIR}/include)
        add_test(NAME ${NAME} COMMAND ${NAME} ${NNG_TEST_PORT})
        set_tests_properties(${NAME} PROPERTIES TIMEOUT ${TIMEOUT})
        math(EXPR NNG_TEST_PORT "${NNG_TEST_PORT}+20")
    endmacro(add_nng_compat_test)

    macro(add_nng_cpp_test NAME TIMEOUT)
        if (NOT NNG_ENABLE_COVERAGE)
            enable_language(CXX)
            add_executable(${NAME} ${NAME}.cc)
            target_link_libraries(${NAME} ${PROJECT_NAME}_testlib)
            add_test(NAME ${NAME} COMMAND ${NAME} ${TEST_PORT})
            set_tests_properties(${NAME} PROPERTIES TIMEOUT ${TIMEOUT})
            math(EXPR TEST_PORT "${NNG_TEST_PORT}+20")
        endif ()
    endmacro(add_nng_cpp_test)

    macro(add_nng_test1 NAME TIMEOUT COND1)
        if (${COND1})
            add_nng_test(${NAME} ${TIMEOUT})
        else ()
            message(STATUS "Test ${NAME} disabled (unconfigured)")
        endif ()
    endmacro()

    macro(add_nng_test2 NAME TIMEOUT COND1 COND2)
        if (${COND1} AND ${COND2})
            add_nng_test(${NAME} ${TIMEOUT})
        else ()
            message(STATUS "Test ${NAME} disabled (unconfigured)")
        endif ()
    endmacro()

    macro(add_nng_test3 NAME TIMEOUT COND1 COND2 COND3)
        if (${COND1} AND ${COND2} AND ${COND3})
            add_nng_test(${NAME} ${TIMEOUT} ON)
        else ()
            message(STATUS "Test ${NAME} disabled (unconfigured)")
        endif ()
    endmacro()

else ()
    macro(add_nng_test NAME TIMEOUT)
    endmacro(add_nng_test)
    macro(add_nng_compat_test NAME TIMEOUT)
    endmacro(add_nng_compat_test)
    macro(add_nng_cpp_test NAME TIMEOUT)
    endmacro(add_nng_cpp_test)
    macro(add_nng_test1 NAME TIMEOUT COND1)
    endmacro(add_nng_test1)
    macro(add_nng_test2 NAME TIMEOUT COND1 COND2)
    endmacro(add_nng_test2)
    macro(add_nng_test3 NAME TIMEOUT COND1 COND2 COND3)
    endmacro(add_nng_test3)
endif ()

nng_test(aio)
nng_test(bufsz)
nng_test(platform)
nng_test(reconnect)
nng_test(sock)

add_nng_test(device 5)
add_nng_test(errors 2)
add_nng_test(files 5)
add_nng_test1(httpclient 60 NNG_SUPP_HTTP)
add_nng_test1(httpserver 30 NNG_SUPP_HTTP)
add_nng_test(idhash 30)
add_nng_test(inproc 5)
add_nng_test(ipc 5)
add_nng_test(ipcperms 5)
add_nng_test(ipcsupp 10)
add_nng_test(ipcwinsec 5)
add_nng_test(list 5)
add_nng_test(message 5)
add_nng_test(multistress 60)
add_nng_test(nonblock 60)
add_nng_test(options 5)
add_nng_test(pipe 5)
add_nng_test(pollfd 5)
add_nng_test1(resolv 10 NNG_STATIC_LIB)
add_nng_test(scalability 20 ON)
add_nng_test(set_recvmaxsize 2)
add_nng_test1(stats 5 NNG_ENABLE_STATS)
add_nng_test(synch 5)
add_nng_test(tls 60)
add_nng_test(tcpsupp 10)
add_nng_test(tcp 180)
add_nng_test(tcp6 60)
add_nng_test(transport 5)
add_nng_test(udp 5)
add_nng_test(url 5)
add_nng_test(ws 30)
add_nng_test(wss 30)
add_nng_test1(zt 60 NNG_TRANSPORT_ZEROTIER)

add_nng_test(bus 5)
add_nng_test(pipeline 5)
add_nng_test(reqctx 5)
add_nng_test(reqstress 60)

# compatibility tests
# We only support these if ALL the legacy protocols are supported.  This
# is because we don't want to make modifications to partially enable some
# of these tests.  Folks minimizing the library probably don't care too
# much about these anyway.
add_nng_compat_test(compat_block 10)
add_nng_compat_test(compat_bug777 10)
add_nng_compat_test(compat_bus 10)
add_nng_compat_test(compat_cmsg 10)
add_nng_compat_test(compat_msg 10)
add_nng_compat_test(compat_iovec 10)
add_nng_compat_test(compat_device 10)
add_nng_compat_test(compat_pair 10)
add_nng_compat_test(compat_pipeline 10)
add_nng_compat_test(compat_poll 10)
add_nng_compat_test(compat_reqrep 10)
add_nng_compat_test(compat_survey 10)
add_nng_compat_test(compat_reqttl 10)
add_nng_compat_test(compat_shutdown 10)
add_nng_compat_test(compat_surveyttl 10)
add_nng_compat_test(compat_ws 60)

# These are special tests for compat mode, not inherited from the
# legacy libnanomsg suite.
add_nng_test(compat_options 5)

# c++ tests
add_nng_cpp_test(cplusplus_pair 5)
