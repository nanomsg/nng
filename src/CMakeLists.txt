#
#   Copyright (c) 2012-2013 Martin Sustrik  All rights reserved.
#   Copyright (c) 2013 GoPivotal, Inc.  All rights reserved.
#   Copyright (c) 2015-2016 Jack R. Dunaway. All rights reserved.
#   Copyright 2017 Garrett D'Amore <garrett@damore.org>
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

set (NNG_SOURCES
    nng.c
    nng.h

    nng_compat.c
    nng_compat.h

    core/defs.h

    core/aio.c
    core/aio.h
    core/clock.c
    core/clock.h
    core/device.c
    core/device.h
    core/endpt.c
    core/endpt.h
    core/idhash.c
    core/idhash.h
    core/init.c
    core/init.h
    core/list.c
    core/list.h
    core/message.c
    core/message.h
    core/msgqueue.c
    core/msgqueue.h
    core/nng_impl.h
    core/options.c
    core/options.h
    core/panic.c
    core/panic.h
    core/pipe.c
    core/pipe.h
    core/platform.h
    core/protocol.c
    core/protocol.h
    core/random.c
    core/random.h
    core/socket.c
    core/socket.h
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
    )

if (NNG_PLATFORM_POSIX)
    set (NNG_SOURCES ${NNG_SOURCES}
        platform/posix/posix_impl.h
        platform/posix/posix_config.h
        platform/posix/posix_aio.h
        platform/posix/posix_pollq.h

        platform/posix/posix_alloc.c
        platform/posix/posix_clock.c
        platform/posix/posix_debug.c
        platform/posix/posix_epdesc.c
        platform/posix/posix_file.c
        platform/posix/posix_ipc.c
        platform/posix/posix_pipe.c
        platform/posix/posix_pipedesc.c
        platform/posix/posix_pollq_poll.c
        platform/posix/posix_rand.c
        platform/posix/posix_resolv_gai.c
        platform/posix/posix_sockaddr.c
        platform/posix/posix_tcp.c
        platform/posix/posix_thread.c
        platform/posix/posix_udp.c
    )
endif()

if (NNG_PLATFORM_WINDOWS)
    set (NNG_SOURCES ${NNG_SOURCES}
        platform/windows/win_impl.h
        platform/windows/win_clock.c
        platform/windows/win_debug.c
        platform/windows/win_file.c
        platform/windows/win_iocp.c
        platform/windows/win_ipc.c
        platform/windows/win_pipe.c
        platform/windows/win_rand.c
        platform/windows/win_resolv.c
        platform/windows/win_sockaddr.c
        platform/windows/win_tcp.c
        platform/windows/win_thread.c
        platform/windows/win_udp.c
        )
endif()

add_subdirectory(supplemental/base64)
add_subdirectory(supplemental/mbedtls)

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
add_subdirectory(transport/zerotier)

include_directories(AFTER SYSTEM ${PROJECT_SOURCE_DIR}/src
    ${NNG_REQUIRED_INCLUDES})

# Provide same folder structure in IDE as on disk
foreach (f ${NNG_SOURCES})
    # Get the path of the file relative to source directory
    if (IS_ABSOLUTE "${f}")
        file (RELATIVE_PATH f ${CMAKE_CURRENT_SOURCE_DIR} ${f})
    endif ()
    set (SRC_GROUP "${f}")
    set (f "${CMAKE_CURRENT_SOURCE_DIR}/${f}")

    # Remove the filename part
    string (REGEX REPLACE "(.*)(/[^/]*)$" "\\1" SRC_GROUP ${SRC_GROUP})

    # CMake source_group expects \\, not /
    string (REPLACE / \\ SRC_GROUP ${SRC_GROUP})
    source_group ("${SRC_GROUP}" FILES ${f})
endforeach ()

# Static libary
add_library (${PROJECT_NAME}_static STATIC ${NNG_SOURCES})
target_compile_definitions(${PROJECT_NAME}_static PUBLIC -DNNG_STATIC_LIB)

# Shared library
add_library (${PROJECT_NAME} SHARED ${NNG_SOURCES})
target_compile_definitions(${PROJECT_NAME} PRIVATE -DNNG_SHARED_LIB)
#set_target_properties (${PROJECT_NAME} PROPERTIES SOVERSION "${NNG_ABI_VERSION}")

# Set library outputs same as top-level project binary outputs
set_target_properties (${PROJECT_NAME} PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR})
set_target_properties (${PROJECT_NAME} PROPERTIES LIBRARY_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR})
set_target_properties (${PROJECT_NAME} PROPERTIES ARCHIVE_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR})

set_target_properties (${PROJECT_NAME}_static PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR})
set_target_properties (${PROJECT_NAME}_static PROPERTIES LIBRARY_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR})
set_target_properties (${PROJECT_NAME}_static PROPERTIES ARCHIVE_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR})

target_link_libraries (${PROJECT_NAME} ${NNG_REQUIRED_LIBRARIES})
if( THREADS_HAVE_PTHREAD_ARG)
    add_definitions (-pthread)
endif()
if (CMAKE_THREAD_LIBS_INIT)
    target_link_libraries (${PROJECT_NAME} "${CMAKE_THREAD_LIBS_INIT}")
endif()

# pkg-config file
#configure_file (pkgconfig.in ${PROJECT_NAME}.pc @ONLY)
#install (
#    FILES ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}.pc
#    DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)
install (TARGETS ${PROJECT_NAME} ${PROJECT_NAME}_static
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

# Promote settings to parent
set(NNG_REQUIRED_LIBRARIES ${NNG_REQUIRED_LIBRARIES} PARENT_SCOPE)
