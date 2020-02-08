#
# Copyright 2020 Staysail Systems, Inc. <info@staysail.tech>
# Copyright 2018 Capitar IT Group BV <info@capitar.com>
# Copyright (c) 2012-2013 Martin Sustrik  All rights reserved.
# Copyright (c) 2013 GoPivotal, Inc.  All rights reserved.
# Copyright (c) 2015-2016 Jack R. Dunaway. All rights reserved.
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

add_library(${PROJECT_NAME}
        nng.c
        ${PROJECT_SOURCE_DIR}/include/nng/nng.h)

if (NNG_TESTS)
    add_library(${PROJECT_NAME}_testlib STATIC
            nng.c
            ${PROJECT_SOURCE_DIR}/tests/testutil.c
            ${PROJECT_SOURCE_DIR}/tests/testutil.h
            ${PROJECT_SOURCE_DIR}/include/nng/nng.h)
endif ()

set(NNG_SRCS

        core/defs.h

        core/aio.c
        core/aio.h
        core/clock.c
        core/clock.h
        core/device.c
        core/device.h
        core/dialer.c
        core/dialer.h
        core/file.c
        core/file.h
        core/idhash.c
        core/idhash.h
        core/init.c
        core/init.h
        core/list.c
        core/list.h
        core/listener.c
        core/listener.h
        core/lmq.c
        core/lmq.h
        core/message.c
        core/message.h
        core/msgqueue.c
        core/msgqueue.h
        core/nng_impl.h
        core/options.c
        core/options.h
        core/pollable.c
        core/pollable.h
        core/panic.c
        core/panic.h
        core/pipe.c
        core/pipe.h
        core/platform.h
        core/protocol.c
        core/protocol.h
        core/reap.c
        core/reap.h
        core/socket.c
        core/socket.h
        core/sockimpl.h
        core/stats.c
        core/stats.h
        core/stream.c
        core/stream.h
        core/strs.c
        core/strs.h
        core/taskq.c
        core/taskq.h
        core/thread.c
        core/thread.h
        core/timer.c
        core/timer.h
        core/transport.c
        core/transport.h
        core/url.c
        core/url.h
        )

if (NNG_PLATFORM_POSIX)
    find_package(Threads REQUIRED)
    list(APPEND NNG_LIBS Threads::Threads)

    set(NNG_SRCS ${NNG_SRCS}
            platform/posix/posix_impl.h
            platform/posix/posix_aio.h
            platform/posix/posix_ipc.h
            platform/posix/posix_config.h
            platform/posix/posix_pollq.h
            platform/posix/posix_tcp.h

            platform/posix/posix_alloc.c
            platform/posix/posix_atomic.c
            platform/posix/posix_clock.c
            platform/posix/posix_debug.c
            platform/posix/posix_file.c
            platform/posix/posix_ipcconn.c
            platform/posix/posix_ipcdial.c
            platform/posix/posix_ipclisten.c
            platform/posix/posix_pipe.c
            platform/posix/posix_resolv_gai.c
            platform/posix/posix_sockaddr.c
            platform/posix/posix_tcpconn.c
            platform/posix/posix_tcpdial.c
            platform/posix/posix_tcplisten.c
            platform/posix/posix_thread.c
            platform/posix/posix_udp.c
            )

    if (NNG_HAVE_PORT_CREATE)
        set(NNG_SRCS ${NNG_SRCS} platform/posix/posix_pollq_port.c)
    elseif (NNG_HAVE_KQUEUE)
        set(NNG_SRCS ${NNG_SRCS} platform/posix/posix_pollq_kqueue.c)
    elseif (NNG_HAVE_EPOLL AND NNG_HAVE_EVENTFD)
        set(NNG_SRCS ${NNG_SRCS} platform/posix/posix_pollq_epoll.c)
    else ()
        set(NNG_SRCS ${NNG_SRCS} platform/posix/posix_pollq_poll.c)
    endif ()

    if (NNG_HAVE_ARC4RANDOM)
        set(NNG_SRCS ${NNG_SRCS} platform/posix/posix_rand_arc4random.c)
    elseif (NNG_HAVE_GETRANDOM)
        set(NNG_SRCS ${NNG_SRCS} platform/posix/posix_rand_getrandom.c)
    else ()
        set(NNG_SRCS ${NNG_SRCS} platform/posix/posix_rand_urandom.c)
    endif ()
endif ()

if (NNG_PLATFORM_WINDOWS)
    set(NNG_SRCS ${NNG_SRCS}
            platform/windows/win_impl.h
            platform/windows/win_ipc.h
            platform/windows/win_tcp.h

            platform/windows/win_clock.c
            platform/windows/win_debug.c
            platform/windows/win_file.c
            platform/windows/win_io.c
            platform/windows/win_ipcconn.c
            platform/windows/win_ipcdial.c
            platform/windows/win_ipclisten.c
            platform/windows/win_pipe.c
            platform/windows/win_rand.c
            platform/windows/win_resolv.c
            platform/windows/win_sockaddr.c
            platform/windows/win_tcp.c
            platform/windows/win_tcpconn.c
            platform/windows/win_tcpdial.c
            platform/windows/win_tcplisten.c
            platform/windows/win_thread.c
            platform/windows/win_udp.c
            )
endif ()


add_subdirectory(compat/nanomsg)

add_subdirectory(protocol/bus0)
add_subdirectory(protocol/pair0)
add_subdirectory(protocol/pair1)
add_subdirectory(protocol/pipeline0)
add_subdirectory(protocol/pubsub0)
add_subdirectory(protocol/reqrep0)
add_subdirectory(protocol/survey0)

add_subdirectory(transport/inproc)
add_subdirectory(transport/ipc)
add_subdirectory(transport/tcp)
add_subdirectory(transport/tls)
add_subdirectory(transport/ws)
add_subdirectory(transport/zerotier)

add_subdirectory(supplemental/base64)
add_subdirectory(supplemental/http)
add_subdirectory(supplemental/sha1)
add_subdirectory(supplemental/tcp)
add_subdirectory(supplemental/tls)
add_subdirectory(supplemental/util)
add_subdirectory(supplemental/websocket)

include_directories(AFTER SYSTEM ${PROJECT_SOURCE_DIR}/src ${NNG_INCS})

add_definitions(${NNG_DEFS})

foreach (_PKG IN ITEMS ${NNG_PKGS})
    find_package(${_PKG} REQUIRED)
endforeach ()

# Library
target_sources(${PROJECT_NAME} PRIVATE ${NNG_SRCS})

if (NNG_TESTS)
    target_sources(${PROJECT_NAME}_testlib PRIVATE ${NNG_SRCS})
    target_link_libraries(${PROJECT_NAME}_testlib PUBLIC ${NNG_LIBS})
    target_compile_definitions(${PROJECT_NAME}_testlib PUBLIC NNG_STATIC_LIB NNG_TEST_LIB)
    target_include_directories(${PROJECT_NAME}_testlib PUBLIC ${PROJECT_SOURCE_DIR}/include)
endif ()

# When building shared libraries we prefer to suppress default symbol
# visibility, so that only the symbols that should be exposed in the
# resulting library are.  This is the default with Windows.
if (BUILD_SHARED_LIBS)
    target_compile_definitions(${PROJECT_NAME} PRIVATE -DNNG_SHARED_LIB)
    if (NNG_HIDDEN_VISIBILITY)
        target_compile_definitions(${PROJECT_NAME} PRIVATE -DNNG_HIDDEN_VISIBILITY)
        set_target_properties(${PROJECT_NAME} PROPERTIES C_VISIBILITY_PRESET hidden)
    endif ()
else ()
    target_compile_definitions(${PROJECT_NAME} PUBLIC -DNNG_STATIC_LIB)
endif ()

set_target_properties(${PROJECT_NAME}
        PROPERTIES SOVERSION ${NNG_ABI_SOVERSION} VERSION "${NNG_ABI_VERSION}")

# Set library outputs same as top-level project binary outputs
set_target_properties(${PROJECT_NAME}
        PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR})
set_target_properties(${PROJECT_NAME}
        PROPERTIES LIBRARY_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR})
set_target_properties(${PROJECT_NAME}
        PROPERTIES ARCHIVE_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR})

set_target_properties(${PROJECT_NAME} ${PROJECT_NAME}
        PROPERTIES FRAMEWORK OFF)

target_link_libraries(${PROJECT_NAME} PRIVATE ${NNG_LIBS})

target_include_directories(${PROJECT_NAME} INTERFACE $<INSTALL_INTERFACE:include>
        $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>)

target_include_directories(${PROJECT_NAME} PRIVATE ${PROJECT_SOURCE_DIR}/include)

install(TARGETS ${PROJECT_NAME}
        EXPORT ${PROJECT_NAME}-target
        FRAMEWORK DESTINATION ${CMAKE_INSTALL_LIBDIR} COMPONENT Library
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR} COMPONENT Library
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR} COMPONENT Library
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR} COMPONENT Tools
        )

install(EXPORT ${PROJECT_NAME}-target
        FILE ${PROJECT_NAME}-targets.cmake
        NAMESPACE nng::
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME}
        COMPONENT Library
        )

export(EXPORT ${PROJECT_NAME}-target
        FILE ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}-targets.cmake
        NAMESPACE nng::)

# Install the header files.
install(DIRECTORY ../include/nng
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
        COMPONENT Headers)

# Promote settings to parent
set(NNG_LIBS ${NNG_LIBS} PARENT_SCOPE)
set(NNG_PKGS ${NNG_PKGS} PARENT_SCOPE)
set(NNG_DEFS ${NNG_DEFS} PARENT_SCOPE)

# These are promoted for testing
set(NNG_SUPP_BASE64 ${NNG_SUPP_BASE64} PARENT_SCOPE)
set(NNG_SUPP_HTTP ${NNG_SUPP_HTTP} PARENT_SCOPE)
set(NNG_SUPP_SHA1 ${NNG_SUPP_SHA1} PARENT_SCOPE)
set(NNG_SUPP_WEBSOCKET ${NNG_SUPP_WEBSOCKET} PARENT_SCOPE)

# Configure files

set(INCLUDE_INSTALL_DIRS "${CMAKE_INSTALL_INCLUDEDIR}/nng")

include(CMakePackageConfigHelpers)
set(version_config "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}-config-version.cmake")
set(project_config "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}-config.cmake")

write_basic_package_version_file("${version_config}"
        VERSION ${NNG_PACKAGE_VERSION}
        COMPATIBILITY SameMajorVersion
        )
configure_package_config_file(${PROJECT_SOURCE_DIR}/cmake/${PROJECT_NAME}-config.cmake.in "${project_config}"
        INSTALL_DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME}"
        PATH_VARS INCLUDE_INSTALL_DIRS)

install(FILES "${project_config}" "${version_config}"
        DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME}"
        COMPONENT Library)
