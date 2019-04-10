#
#   Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
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
endif()

if (NNG_TESTS)

    nng_check_sym(nl_langinfo langinfo.h NNG_HAVE_LANGINFO)
    if (NOT NNG_SANITIZER STREQUAL "none")
        set(TIMEOUT_FACTOR 2)
    else()
        set (TIMEOUT_FACTOR 1)
    endif()
    set (NNG_TEST_PORT 13000)
    macro (add_nng_test NAME TIMEOUT)
        add_executable (${NAME} ${NAME}.c convey.c)
        target_link_libraries (${NAME} ${PROJECT_NAME} ${THRLIB})
        add_test (NAME ${NAME} COMMAND ${NAME} -v -p TEST_PORT=${NNG_TEST_PORT})
        math (EXPR TIMEOUT ${TIMEOUT}*${TIMEOUT_FACTOR})
        set_tests_properties (${NAME} PROPERTIES TIMEOUT ${TIMEOUT})
        math (EXPR NNG_TEST_PORT "${NNG_TEST_PORT}+20")
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
            add_executable (${NAME} ${NAME}.c compat_testutil.c)
            target_link_libraries (${NAME} ${PROJECT_NAME})
            target_include_directories(${NAME} PUBLIC
		${PROJECT_SOURCE_DIR}/src/compat)

            add_test (NAME ${NAME} COMMAND ${NAME} ${NNG_TEST_PORT})
            set_tests_properties (${NAME} PROPERTIES TIMEOUT ${TIMEOUT})
            math (EXPR NNG_TEST_PORT "${NNG_TEST_PORT}+20")
        endmacro (add_nng_compat_test)
    else ()
        macro (add_nng_compat_test NAME TIMEOUT)
        endmacro (add_nng_compat_test)
        message (STATUS "Compatibility tests disabled (unconfigured protocols)")
    endif ()

    macro (add_nng_cpp_test NAME TIMEOUT)
        if (NOT NNG_ENABLE_COVERAGE)
            enable_language (CXX)
            add_executable (${NAME} ${NAME}.cc)
            target_link_libraries (${NAME} ${PROJECT_NAME})
            add_test (NAME ${NAME} COMMAND ${NAME} ${TEST_PORT})
            set_tests_properties (${NAME} PROPERTIES TIMEOUT ${TIMEOUT})
            math (EXPR TEST_PORT "${NNG_TEST_PORT}+20")
        endif()
    endmacro (add_nng_cpp_test)

    macro (add_nng_test1 NAME TIMEOUT COND1)
        if (${COND1})
            add_nng_test(${NAME} ${TIMEOUT})
        else()
            message (STATUS "Test ${NAME} disabled (unconfigured)")
        endif()
    endmacro()

    macro (add_nng_test2 NAME TIMEOUT COND1 COND2)
        if (${COND1} AND ${COND2})
            add_nng_test(${NAME} ${TIMEOUT})
        else()
            message (STATUS "Test ${NAME} disabled (unconfigured)")
        endif()
    endmacro()

    macro (add_nng_test3 NAME TIMEOUT COND1 COND2 COND3)
        if (${COND1} AND ${COND2} AND ${COND3})
            add_nng_test(${NAME} ${TIMEOUT} ON)
        else()
            message (STATUS "Test ${NAME} disabled (unconfigured)")
        endif()
    endmacro()

else ()
    macro (add_nng_test NAME TIMEOUT)
    endmacro (add_nng_test)
    macro (add_nng_compat_test NAME TIMEOUT)
    endmacro (add_nng_compat_test)
    macro (add_nng_cpp_test NAME TIMEOUT)
    endmacro (add_nng_cpp_test)
    macro (add_nng_test1 NAME TIMEOUT COND1)
    endmacro(add_nng_test1)
    macro (add_nng_test2 NAME TIMEOUT COND1 COND2)
    endmacro(add_nng_test2)
    macro (add_nng_test3 NAME TIMEOUT COND1 COND2 COND3)
    endmacro(add_nng_test3)
endif ()

add_nng_test(aio 5)
add_nng_test2(base64 5 NNG_STATIC_LIB NNG_SUPP_BASE64)
add_nng_test1(bufsz 5 NNG_PROTO_PAIR0)
add_nng_test(device 5)
add_nng_test(errors 2)
add_nng_test1(files 5 NNG_STATIC_LIB)
add_nng_test1(httpclient 60 NNG_SUPP_HTTP)
add_nng_test2(httpserver 30 NNG_STATIC_LIB NNG_SUPP_HTTP)
add_nng_test1(idhash 30 NNG_STATIC_LIB)
add_nng_test1(inproc 5 NNG_TRANSPORT_INPROC)
add_nng_test1(ipc 5 NNG_TRANSPORT_IPC)
add_nng_test1(ipcperms 5 NNG_TRANSPORT_IPC)
add_nng_test1(ipcsupp 10 NNG_TRANSPORT_IPC)
add_nng_test1(ipcwinsec 5 NNG_TRANSPORT_IPC)
add_nng_test1(list 5 NNG_STATIC_LIB)
add_nng_test(message 5)
add_nng_test(multistress 60)
add_nng_test(nonblock 60)
add_nng_test(options 5)
add_nng_test(pipe 5)
add_nng_test(platform 5)
add_nng_test(pollfd 5)
add_nng_test(pubsubpollfd 5)
add_nng_test(reconnect 5)
add_nng_test1(resolv 10 NNG_STATIC_LIB)
add_nng_test(scalability 20 ON)
add_nng_test(set_recvmaxsize 2)
add_nng_test2(sha1 5 NNG_STATIC_LIB NNG_SUPP_SHA1)
add_nng_test(sock 5)
add_nng_test1(stats 5 NNG_ENABLE_STATS)
add_nng_test1(synch 5 NNG_STATIC_LIB)
add_nng_test2(tls 60 NNG_STATIC_LIB NNG_TRANSPORT_TLS)
add_nng_test(tcpsupp 10)
add_nng_test1(tcp 180 NNG_TRANSPORT_TCP)
add_nng_test2(tcp6 60 NNG_STATIC_LIB NNG_TRANSPORT_TCP)
add_nng_test1(transport 5 NNG_STATIC_LIB)
add_nng_test1(udp 5 NNG_STATIC_LIB)
add_nng_test(url 5)
add_nng_test1(ws 30 NNG_TRANSPORT_WS)
add_nng_test1(wss 30 NNG_TRANSPORT_WSS)
add_nng_test2(wssfile 30 NNG_STATIC_LIB NNG_TRANSPORT_WSS)
add_nng_test1(wsstream 10 NNG_TRANSPORT_WS)
add_nng_test1(zt 60 NNG_TRANSPORT_ZEROTIER)

add_nng_test1(bus 5 NNG_PROTO_BUS0)
add_nng_test2(pipeline 5 NNG_PROTO_PULL0 NNG_PROTO_PUSH0)
add_nng_test1(pair1 5 NNG_PROTO_PAIR1)
add_nng_test2(pubsub 5 NNG_PROTO_PUB0 NNG_PROTO_SUB0)
add_nng_test2(reqctx 5 NNG_PROTO_REQ0 NNG_PROTO_REP0)
add_nng_test2(reqpoll 5 NNG_PROTO_REQ0 NNG_PROTO_REP0)
add_nng_test2(reqrep 5 NNG_PROTO_REQ0 NNG_PROTO_REP0)
add_nng_test2(reqstress 60 NNG_PROTO_REQ0 NNG_PROTO_REP0)
add_nng_test2(respondpoll 5 NNG_PROTO_SURVEYOR0 NNG_PROTO_RESPONDENT0)
add_nng_test2(survey 5 NNG_PROTO_SURVEYOR0 NNG_PROTO_RESPONDENT0)
add_nng_test2(surveyctx 5 NNG_PROTO_SURVEYOR0 NNG_PROTO_RESPONDENT0)
add_nng_test2(surveypoll 5 NNG_PROTO_SURVEYOR0 NNG_PROTO_RESPONDENT0)

# compatbility tests
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
add_nng_compat_test(compat_tcp 60)
add_nng_compat_test(compat_ws 60)

# These are special tests for compat mode, not inherited from the
# legacy libnanomsg suite.
add_nng_test1(compat_options 5 NNG_PROTO_REP0)

# c++ tests
add_nng_cpp_test(cplusplus_pair 5)
