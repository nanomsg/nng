#
#   Copyright 2024 Staysail Systems, Inc. <info@staysail.tech>
#   Copyright (c) 2012 Martin Sustrik  All rights reserved.
#   Copyright (c) 2013 GoPivotal, Inc.  All rights reserved.
#   Copyright (c) 2015-2016 Jack R. Dunaway. All rights reserved.
#   Copyright 2016 Franklin "Snaipe" Mathieu <franklinmathieu@gmail.com>
#   Copyright 2018 Capitar IT Group BV <info@capitar.com>
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

cmake_minimum_required(VERSION 3.15)

project(nng C)
include(CheckCCompilerFlag)
include(GNUInstallDirs)

set(CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake)

include(NNGHelpers)
include(NNGOptions)

set(CMAKE_C_STANDARD 99)
set(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)
list(FIND CMAKE_PLATFORM_IMPLICIT_LINK_DIRECTORIES "${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR}" isSystemDir)
if ("${isSystemDir}" STREQUAL "-1")
    set(CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR}")
endif ("${isSystemDir}" STREQUAL "-1")

set(NNG_DESCRIPTION "High-Performance Scalability Protocols NextGen")
set(ISSUE_REPORT_MSG "Please consider opening an issue at https://github.com/nanomsg/nng")

# Determine library versions.
file(READ "include/nng/nng.h" nng_ver_h)
string(REGEX MATCH "NNG_MAJOR_VERSION ([0-9]*)" _ ${nng_ver_h})
set(NNG_MAJOR_VERSION ${CMAKE_MATCH_1})
string(REGEX MATCH "NNG_MINOR_VERSION ([0-9]*)" _ ${nng_ver_h})
set(NNG_MINOR_VERSION ${CMAKE_MATCH_1})
string(REGEX MATCH "NNG_PATCH_VERSION ([0-9]*)" _ ${nng_ver_h})
set(NNG_PATCH_VERSION ${CMAKE_MATCH_1})
string(REGEX MATCH "NNG_RELEASE_SUFFIX \"([a-z0-9]*)\"" _ ${nng_ver_h})
if (NOT ("${CMAKE_MATCH_1}" STREQUAL ""))
    set(NNG_PRERELEASE "-${CMAKE_MATCH_1}")
endif ()

set(NNG_ABI_SOVERSION 1)
set(NNG_ABI_VERSION "${NNG_MAJOR_VERSION}.${NNG_MINOR_VERSION}.${NNG_PATCH_VERSION}${NNG_PRERELEASE}")
set(NNG_PACKAGE_VERSION "${NNG_ABI_VERSION}")
message(STATUS "Configuring for NNG version ${NNG_ABI_VERSION}")

# User-defined options.

# This prefix is appended to by subdirectories, so that each test
# gets named based on where it is in the tree.
set(NNG_TEST_PREFIX nng)

# Enable access to private APIs for our own use.
add_definitions(-DNNG_PRIVATE)

if (NOT (BUILD_SHARED_LIBS))
    set(NNG_STATIC_LIB ON)
    message(STATUS "Building static libs.")
endif ()

# These are library targets.  The "nng" library is the main public library.
# The "nng_testing" is a full build of the library for test cases
# only, which is done statically and includes even portions of the code
# that are not part of the public library (things that may have been elided.)
# The "nng_private" library is an interface that allows some internal tools
# to obtain details about how the public library was built, so that we can
# include or not include code based on what's actually present.
add_library(nng)

add_library(nng_testing STATIC EXCLUDE_FROM_ALL)
target_compile_definitions(nng_testing PUBLIC NNG_STATIC_LIB NNG_TEST_LIB NNG_PRIVATE)

add_library(nng_private INTERFACE)
target_compile_definitions(nng_private INTERFACE NNG_PRIVATE)

if (NNG_ELIDE_DEPRECATED)
    target_compile_definitions(nng PRIVATE NNG_ELIDE_DEPRECATED)
endif()
if (NNG_ENABLE_COMPAT)
    target_compile_definitions(nng PRIVATE NNG_ENABLE_COMPAT)
endif()


# We can use rlimit to configure the stack size for systems
# that have too small defaults.  This is not used for Windows,
# which can grow thread stacks sensibly.  (Note that NNG can get
# by with a smallish stack, but application callbacks might require
# larger values if using aio completion callbacks.  TLS libraries may
# require larger stacks however.)
if (NOT WIN32)
    option(NNG_SETSTACKSIZE "Use rlimit for thread stack size" OFF)
    if (NNG_SETSTACKSIZE)
        add_definitions(-DNNG_SETSTACKSIZE)
    endif ()
    mark_as_advanced(NNG_SETSTACKSIZE)
endif ()

nng_defines_if(NNG_ENABLE_STATS NNG_ENABLE_STATS)

# IPv6 enable
nng_defines_if(NNG_ENABLE_IPV6 NNG_ENABLE_IPV6)

set(NNG_RESOLV_CONCURRENCY 4 CACHE STRING "Resolver (DNS) concurrency.")
mark_as_advanced(NNG_RESOLV_CONCURRENCY)
if (NNG_RESOLV_CONCURRENCY)
    add_definitions(-DNNG_RESOLV_CONCURRENCY=${NNG_RESOLV_CONCURRENCY})
endif ()

set(NNG_NUM_TASKQ_THREADS 0 CACHE STRING "Fixed number of task threads, 0 for automatic")
mark_as_advanced(NNG_NUM_TASKQ_THREADS)
if (NNG_NUM_TASKQ_THREADS)
    add_definitions(-DNNG_NUM_TASKQ_THREADS=${NNG_NUM_TASKQ_THREADS})
endif ()

set(NNG_MAX_TASKQ_THREADS 16 CACHE STRING "Upper bound on task threads, 0 for no limit")
mark_as_advanced(NNG_MAX_TASKQ_THREADS)
if (NNG_MAX_TASKQ_THREADS)
    add_definitions(-DNNG_MAX_TASKQ_THREADS=${NNG_MAX_TASKQ_THREADS})
endif ()

# Expire threads. This runs the timeout handling, and having more of them
# reduces contention on the common locks used for aio expiration.
set(NNG_NUM_EXPIRE_THREADS 0 CACHE STRING "Fixed number of expire threads, 0 for automatic")
mark_as_advanced(NNG_NUM_EXPIRE_THREADS)
if (NNG_NUM_EXPIRE_THREADS)
    add_definitions(-DNNG_NUM_EXPIRE_THREADS=${NNG_NUM_EXPIRE_THREADS})
endif ()

set(NNG_MAX_EXPIRE_THREADS 8 CACHE STRING "Upper bound on expire threads, 0 for no limit")
mark_as_advanced(NNG_MAX_EXPIRE_THREADS)
if (NNG_MAX_EXPIRE_THREADS)
    add_definitions(-DNNG_MAX_EXPIRE_THREADS=${NNG_MAX_EXPIRE_THREADS})
endif()

# Poller threads.  These threads run the pollers.  This is mostly used
# on Windows right now, as the POSIX platforms use a single threaded poller.
set(NNG_NUM_POLLER_THREADS 0 CACHE STRING "Fixed number of I/O poller threads, 0 for automatic")
if (NNG_NUM_POLLER_THREADS)
    add_definitions(-DNNG_NUM_POLLER_THREADS=${NNG_NUM_POLLER_THREADS})
endif ()
mark_as_advanced(NNG_NUM_POLLER_THREADS)

set(NNG_MAX_POLLER_THREADS 8 CACHE STRING "Upper bound on I/O poller threads, 0 for no limit")
mark_as_advanced(NNG_MAX_POLLER_THREADS)
if (NNG_MAX_POLLER_THREADS)
    add_definitions(-DNNG_MAX_POLLER_THREADS=${NNG_MAX_POLLER_THREADS})
endif()

#  Platform checks.

if (CMAKE_C_COMPILER_ID STREQUAL "GNU")
    set(NNG_WARN_FLAGS "-Wall -Wextra -fno-omit-frame-pointer")
elseif (CMAKE_C_COMPILER_ID MATCHES "Clang")
    set(NNG_WARN_FLAGS "-Wall -Wextra -fno-omit-frame-pointer")
endif ()

include(CheckSanitizer)
CheckSanitizer()
if (NOT NNG_SANITIZER STREQUAL "none")
    set(NNG_SANITIZER_FLAGS "-fsanitize=${NNG_SANITIZER}")
endif ()

if (NNG_ENABLE_COVERAGE)
    # NB: This only works for GCC and Clang 3.0 and newer.  If your stuff
    # is older than that, you will need to find something newer.  For
    # correct reporting, we always turn off all optimizations.
    if (CMAKE_C_COMPILER_ID STREQUAL "GNU")
        set(NNG_COVERAGE_C_FLAGS "-g -O0 --coverage")
        set(CMAKE_SHARED_LINKER_FLAGS --coverage)
    elseif (CMAKE_C_COMPILER_ID MATCHES "Clang")
        set(NNG_COVERAGE_C_FLAGS "-g -O0 --coverage")
        set(CMAKE_SHARED_LINKER_FLAGS --coverage)
    else ()
        message(FATAL_ERROR "Unable to enable coverage for your compiler.")
    endif ()
endif ()

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${NNG_WARN_FLAGS} ${NNG_COVERAGE_C_FLAGS} ${NNG_SANITIZER_FLAGS}")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${NNG_WARN_FLAGS} ${NNG_COVERAGE_C_FLAGS} ${NNG_SANITIZER_FLAGS}")

# If the compiler is not on Windows, does it support hiding the
# symbols by default?  For shared libraries we would like to do this.
if (NOT WIN32 AND NOT CYGWIN)
    check_c_compiler_flag(-fvisibility=hidden NNG_HIDDEN_VISIBILITY)
    if (NNG_HIDDEN_VISIBILITY)
        add_definitions(-DNNG_HIDDEN_VISIBILITY)
    endif ()
endif ()

if (CMAKE_SYSTEM_NAME MATCHES "Linux")
    add_definitions(-DNNG_PLATFORM_POSIX)
    add_definitions(-DNNG_PLATFORM_LINUX)
    add_definitions(-DNNG_USE_EVENTFD)
    add_definitions(-DNNG_HAVE_ABSTRACT_SOCKETS)
    # Windows subsystem for Linux -- smells like Linux, but it has
    # some differences (SO_REUSEADDR for one).
    if (CMAKE_SYSTEM_VERSION MATCHES "Microsoft")
        add_definitions(-DNNG_PLATFORM_WSL)
    endif ()
    set(NNG_PLATFORM_POSIX ON)

elseif (CMAKE_SYSTEM_NAME MATCHES "Android")
    add_definitions(-DNNG_PLATFORM_POSIX)
    add_definitions(-DNNG_PLATFORM_LINUX)
    add_definitions(-DNNG_PLATFORM_ANDROID)
    add_definitions(-DNNG_USE_EVENTFD)
    set(NNG_PLATFORM_POSIX ON)

elseif (APPLE)
    add_definitions(-DNNG_PLATFORM_POSIX)
    add_definitions(-DNNG_PLATFORM_DARWIN)
    set(NNG_PLATFORM_POSIX ON)

elseif (CMAKE_SYSTEM_NAME MATCHES "FreeBSD")
    add_definitions(-DNNG_PLATFORM_POSIX)
    add_definitions(-DNNG_PLATFORM_FREEBSD)
    set(NNG_PLATFORM_POSIX ON)

elseif (CMAKE_SYSTEM_NAME MATCHES "NetBSD")
    add_definitions(-DNNG_PLATFORM_POSIX)
    add_definitions(-DNNG_PLATFORM_NETBSD)
    set(NNG_PLATFORM_POSIX ON)

elseif (CMAKE_SYSTEM_NAME MATCHES "OpenBSD")
    add_definitions(-DNNG_PLATFORM_POSIX)
    add_definitions(-DNNG_PLATFORM_OPENBSD)
    set(NNG_PLATFORM_POSIX ON)

elseif (CMAKE_SYSTEM_NAME MATCHES "SunOS")
    add_definitions(-DNNG_PLATFORM_POSIX)
    add_definitions(-DNNG_PLATFORM_SUNOS)
    set(NNG_PLATFORM_POSIX ON)

elseif (CMAKE_SYSTEM_NAME MATCHES "Windows")
    add_definitions(-DNNG_PLATFORM_WINDOWS)
    add_definitions(-D_CRT_SECURE_NO_WARNINGS)
    add_definitions(-D_CRT_RAND_S)
    set(NNG_PLATFORM_WINDOWS ON)

    # Target Windows Vista and later
    add_definitions(-D_WIN32_WINNT=0x0600)
    list(APPEND CMAKE_REQUIRED_DEFINITIONS -D_WIN32_WINNT=0x0600)

elseif (CMAKE_SYSTEM_NAME MATCHES "QNX")
    add_definitions(-DNNG_PLATFORM_POSIX)
    add_definitions(-D__EXT_BSD)
    add_definitions(-D_QNX_SOURCE)
    add_definitions(-DNNG_PLATFORM_QNX)
    set(NNG_PLATFORM_POSIX ON)

else ()
    message(AUTHOR_WARNING "WARNING: This platform may not be supported: ${CMAKE_SYSTEM_NAME}")
    message(AUTHOR_WARNING "${ISSUE_REPORT_MSG}")
    # blithely hope for POSIX to work
    add_definitions(-DNNG_PLATFORM_POSIX)
    set(NNG_PLATFORM_POSIX ON)
endif ()

if (NNG_ENABLE_TLS)
    add_definitions(-DNNG_SUPP_TLS)
endif ()

if (NNG_TESTS)
    enable_testing()
    set(all_tests, "")
endif ()

add_subdirectory(src)

if (NNG_TESTS)
    add_subdirectory(tests)
endif ()

#  Build the tools

add_subdirectory(docs/man)

set(CPACK_PACKAGE_NAME ${PROJECT_NAME})
set(CPACK_PACKAGE_VERSION ${NNG_PACKAGE_VERSION})
set(CPACK_PACKAGE_CONTACT "nanomsg@freelists.org")
set(CPACK_PACKAGE_VENDOR "nanomsg.org")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "nanomsg next generation library")
set(CPACK_SOURCE_GENERATOR "TBZ2;TGZ;ZIP")
set(CPACK_SOURCE_IGNORE_FILES "/build/;/.git/;~$;${CPACK_SOURCE_IGNORE_FILES}")
set(CPACK_SOURCE_PACKAGE_FILE_NAME
        "${PROJECT_NAME}-v${NNG_PACKAGE_VERSION}-src")
set(CPACK_RESOURCE_FILE_LICENSE ${CMAKE_CURRENT_SOURCE_DIR}/LICENSE.txt)
set(CPACK_PACKAGE_INSTALL_DIRECTORY "nng")
set(CPACK_PACKAGE_FILE_NAME "${PROJECT_NAME}-v${NNG_PACKAGE_VERSION}")

add_custom_target(dist COMMAND ${CMAKE_MAKE_PROGRAM} package_source)
include(CPack)
