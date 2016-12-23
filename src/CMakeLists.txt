#
#   Copyright (c) 2012-2013 Martin Sustrik  All rights reserved.
#   Copyright (c) 2013 GoPivotal, Inc.  All rights reserved.
#   Copyright (c) 2015-2016 Jack R. Dunaway. All rights reserved.
#   Copyright 2016 Garrett D'Amore <garrett@damore.org>
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

    core/defs.h
    core/endpt.c
    core/init.c
    core/init.h
    core/list.c
    core/list.h
    core/message.c
    core/message.h
    core/msgqueue.c
    core/msgqueue.h
    core/nng_impl.h
    core/panic.c
    core/panic.h
    core/pipe.c
    core/pipe.h
    core/platform.c
    core/platform.h
    core/protocol.c
    core/protocol.h
    core/socket.c
    core/socket.h
    core/transport.c
    core/transport.h

    platform/posix/posix_impl.h
    platform/posix/posix_config.h

    platform/posix/posix_alloc.c
    platform/posix/posix_clock.c
    platform/posix/posix_debug.c
    platform/posix/posix_synch.c
    platform/posix/posix_thread.c

    protocol/pair/pair.c

    transport/inproc/inproc.c
)

include_directories(AFTER SYSTEM ${PROJECT_SOURCE_DIR}/src)

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

if (NNG_STATIC_LIB)
    add_library (${PROJECT_NAME} STATIC ${NNG_SOURCES})
else ()
    add_library (${PROJECT_NAME} SHARED ${NNG_SOURCES})
    add_definitions (-DNNG_SHARED_LIB)
    #set_target_properties (${PROJECT_NAME} PROPERTIES SOVERSION "${NNG_ABI_VERSION}")
endif ()

# Set library outputs same as top-level project binary outputs
set_target_properties (${PROJECT_NAME} PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR})
set_target_properties (${PROJECT_NAME} PROPERTIES LIBRARY_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR})
set_target_properties (${PROJECT_NAME} PROPERTIES ARCHIVE_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR})

target_link_libraries (${PROJECT_NAME} ${NNG_REQUIRED_LIBRARIES})
if( THREADS_HAVE_PTHREAD_ARG)
    add_definitions (-pthread)
endif()
if (CMAKE_THREAD_LIBS_INIT)
    target_link_libraries (${PROJECT_NAME} "${CMAKE_THREAD_LIBS_INIT}")
endif()

# pkg-config file
if (NNG_REQUIRED_LIBRARIES)
    foreach (lib ${NNG_REQUIRED_LIBRARIES})
        set (NNG_REQUIRED_LFLAGS "${NNG_REQUIRED_LFLAGS} -l${lib}")
    endforeach()
endif()
#configure_file (pkgconfig.in ${PROJECT_NAME}.pc @ONLY)
#install (
#    FILES ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}.pc
#    DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)
install (TARGETS ${PROJECT_NAME}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
