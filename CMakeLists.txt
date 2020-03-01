#
#   Copyright 2020 Staysail Systems, Inc. <info@staysail.tech>
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

cmake_minimum_required(VERSION 3.13)

project(nng C)
include(CheckFunctionExists)
include(CheckSymbolExists)
include(CheckStructHasMember)
include(CheckLibraryExists)
include(CheckCSourceCompiles)
include(CheckCCompilerFlag)
include(CMakeDependentOption)
include(GNUInstallDirs)
include(TestBigEndian)
include(FindUnixCommands)

set(CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake)

if (POLICY CMP0042)
    # Newer cmake on MacOS should use @rpath
    cmake_policy(SET CMP0042 NEW)
endif ()
if (POLICY CMP0079)
    cmake_policy(SET CMP0079 NEW)
endif ()

if (POLICY CMP0028)
    # Double colon targets are only alias or imports.
    cmake_policy(SET CMP0028 NEW)
endif ()

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
message("Configuring for NNG version ${NNG_ABI_VERSION}")

# User-defined options.

option(BUILD_SHARED_LIBS "Build shared library" ${BUILD_SHARED_LIBS})

if (CMAKE_CROSSCOMPILING)
    set(NNG_NATIVE_BUILD OFF)
else ()
    set(NNG_NATIVE_BUILD ON)
endif ()

# We only build command line tools and tests if we are not in a
# cross-compile situation.  Cross-compiling users who still want to
# build these must enable them explicitly.  Some of these switches
# must be enabled rather early as we use their values later.
option(NNG_TESTS "Build and run tests" ${NNG_NATIVE_BUILD})
option(NNG_TOOLS "Build extra tools" ${NNG_NATIVE_BUILD})
option(NNG_ENABLE_NNGCAT "Enable building nngcat utility." ${NNG_TOOLS})
option(NNG_ENABLE_COVERAGE "Enable coverage reporting." OFF)


# Enable access to private APIs for our own use.
add_definitions(-DNNG_PRIVATE)

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

option(NNG_ENABLE_STATS "Enable statistics" ON)
if (NNG_ENABLE_STATS)
    add_definitions(-DNNG_ENABLE_STATS)
endif ()
mark_as_advanced(NNG_ENABLE_STATS)

if (NNG_RESOLV_CONCURRENCY)
    add_definitions(-DNNG_RESOLV_CONCURRENCY=${NNG_RESOLV_CONCURRENCY})
endif ()
mark_as_advanced(NNG_RESOLV_CONCURRENCY)

if (NNG_NUM_TASKQ_THREADS)
    add_definitions(-DNNG_NUM_TASKQ_THREADS=${NNG_NUM_TASKQ_THREADS})
endif ()
mark_as_advanced(NNG_NUM_TASKQ_THREADS)

set(NNG_MAX_TASKQ_THREADS 16 CACHE STRING "Upper bound on taskq threads, 0 for no limit")
mark_as_advanced(NNG_MAX_TASKQ_THREADS)
if (NNG_MAX_TASKQ_THREADS)
    add_definitions(-DNNG_MAX_TASKQ_THREADS=${NNG_MAX_TASKQ_THREADS})
endif ()

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

include(CheckAtomicLib)
CheckAtomicLib()
if (NOT HAVE_C_ATOMICS_WITHOUT_LIB AND HAVE_C_ATOMICS_WITH_LIB)
    list(APPEND NNG_LIBS "atomic")
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

TEST_BIG_ENDIAN(NNG_BIG_ENDIAN)
if (NNG_BIG_ENDIAN)
    add_definitions(-DNNG_BIG_ENDIAN)
else ()
    add_definitions(-DNNG_LITTLE_ENDIAN)
endif ()

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

elseif (CMAKE_SYSTEM_NAME MATCHES "Darwin")
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
endif ()

macro(nng_check_func SYM DEF)
    check_function_exists(${SYM} ${DEF})
    if (${DEF})
        add_definitions(-D${DEF}=1)
    endif ()
endmacro(nng_check_func)

macro(nng_check_sym SYM HDR DEF)
    check_symbol_exists(${SYM} ${HDR} ${DEF})
    if (${DEF})
        add_definitions(-D${DEF}=1)
    endif ()
endmacro(nng_check_sym)

macro(nng_check_lib LIB SYM DEF)
    check_library_exists(${LIB} ${SYM} "" ${DEF})
    if (${DEF})
        add_definitions(-D${DEF}=1)
        list(APPEND NNG_LIBS ${LIB})
    endif ()
endmacro(nng_check_lib)

macro(nng_check_struct_member STR MEM HDR DEF)
    check_struct_has_member("struct ${STR}" ${MEM} ${HDR} ${DEF})
    if (${DEF})
        add_definitions(-D${DEF}=1)
    endif ()
endmacro(nng_check_struct_member)

if (WIN32)
    # Windows is a special snowflake.
    list(APPEND NNG_LIBS ws2_32 mswsock advapi32)
    nng_check_sym(InitializeConditionVariable windows.h NNG_HAVE_CONDVAR)
    nng_check_sym(snprintf stdio.h NNG_HAVE_SNPRINTF)
    if (NOT NNG_HAVE_CONDVAR OR NOT NNG_HAVE_SNPRINTF)
        message(FATAL_ERROR
                "Modern Windows API support is missing. "
                "Versions of Windows prior to Vista are not supported.  "
                "Further, the 32-bit MinGW environment is not supported. "
                "Ensure you have at least Windows Vista or newer, and are "
                "using either Visual Studio 2013 or newer or MinGW-W64.")
    endif ()
else ()
    # Unconditionally declare the following feature test macros.  These are
    # needed for some platforms (glibc and SunOS/illumos) and are harmless
    # on the others.
    add_definitions(-D_GNU_SOURCE)
    add_definitions(-D_REENTRANT)
    add_definitions(-D_THREAD_SAFE)
    add_definitions(-D_POSIX_PTHREAD_SEMANTICS)
    list(APPEND NNG_PKGS Threads)
    find_package(Threads REQUIRED)

    nng_check_func(lockf NNG_HAVE_LOCKF)
    nng_check_func(flock NNG_HAVE_FLOCK)
    nng_check_func(getrandom NNG_HAVE_GETRANDOM)
    nng_check_func(arc4random_buf NNG_HAVE_ARC4RANDOM)

    nng_check_lib(rt clock_gettime NNG_HAVE_CLOCK_GETTIME)
    nng_check_lib(pthread sem_wait NNG_HAVE_SEMAPHORE_PTHREAD)
    nng_check_lib(pthread pthread_atfork NNG_HAVE_PTHREAD_ATFORK_PTHREAD)
    nng_check_lib(nsl gethostbyname NNG_HAVE_LIBNSL)
    nng_check_lib(socket socket NNG_HAVE_LIBSOCKET)

    nng_check_sym(AF_UNIX sys/socket.h NNG_HAVE_UNIX_SOCKETS)
    nng_check_sym(backtrace_symbols_fd execinfo.h NNG_HAVE_BACKTRACE)
    nng_check_struct_member(msghdr msg_control sys/socket.h NNG_HAVE_MSG_CONTROL)
    nng_check_sym(eventfd sys/eventfd.h NNG_HAVE_EVENTFD)
    nng_check_sym(kqueue sys/event.h NNG_HAVE_KQUEUE)
    nng_check_sym(port_create port.h NNG_HAVE_PORT_CREATE)
    nng_check_sym(epoll_create sys/epoll.h NNG_HAVE_EPOLL)
    nng_check_sym(epoll_create1 sys/epoll.h NNG_HAVE_EPOLL_CREATE1)
    nng_check_sym(getpeereid unistd.h NNG_HAVE_GETPEEREID)
    nng_check_sym(SO_PEERCRED sys/socket.h NNG_HAVE_SOPEERCRED)
    nng_check_struct_member(sockpeercred uid sys/socket.h NNG_HAVE_SOCKPEERCRED)
    nng_check_sym(LOCAL_PEERCRED sys/un.h NNG_HAVE_LOCALPEERCRED)
    nng_check_sym(getpeerucred ucred.h NNG_HAVE_GETPEERUCRED)
    nng_check_sym(atomic_flag_test_and_set stdatomic.h NNG_HAVE_STDATOMIC)

endif ()

nng_check_sym(strlcpy string.h NNG_HAVE_STRLCPY)
nng_check_sym(strnlen string.h NNG_HAVE_STRNLEN)
nng_check_sym(strcasecmp string.h NNG_HAVE_STRCASECMP)
nng_check_sym(strncasecmp string.h NNG_HAVE_STRNCASECMP)

# Set a static symbol.  We do this for testing, so that tests can
# be skipped if they would rely on symbols that might not be exported.
# For example, idhash depends on private symbols, so don't test it
# when using a shared library on Windows because the symbols won't
# resolve.
if (NOT (BUILD_SHARED_LIBS))
    set(NNG_STATIC_LIB ON)
    message(STATUS "Building static libs")
endif ()

# In order to facilitate testing, we want to add a library that includes
# our common test code.  We do this before iterating everywhere else so
# that we can locate our tests inside the directories where we want.
if (NNG_TESTS)
    enable_testing()
    set(all_tests, "")
endif ()

macro(nng_test NAME)
    if (NNG_TESTS)
        add_executable(${NAME} ${NAME}.c ${ARGN})
        target_link_libraries(${NAME} ${PROJECT_NAME}_testlib)
        target_include_directories(${NAME} PRIVATE
                ${PROJECT_SOURCE_DIR}/tests
                ${PROJECT_SOURCE_DIR}/src
                ${PROJECT_SOURCE_DIR}/include)
        add_test(NAME ${NAME} COMMAND ${NAME} -t)
        set_tests_properties(${NAME} PROPERTIES TIMEOUT 180)
    endif ()
endmacro()

function(nng_sources_testlib)
    if (NNG_TESTS)
        foreach (f ${ARGN})
            target_sources(${PROJECT_NAME}_testlib PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/${f})
        endforeach ()
    endif ()
endfunction()

function(nng_headers_testlib)
    if (NNG_TESTS)
        foreach (f ${ARGN})
            target_sources(${PROJECT_NAME}_testlib PRIVATE ${PROJECT_SOURCE_DIR}/include/${f})
        endforeach ()
    endif ()
endfunction()

function(nng_defines_testlib)
    if (NNG_TESTS)
        target_compile_definitions(${PROJECT_NAME}_testlib PRIVATE ${ARGN})
    endif ()
endfunction()

function(nng_sources)
    foreach (f ${ARGN})
        target_sources(${PROJECT_NAME} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/${f})
    endforeach ()
    nng_sources_testlib(${ARGN})
endfunction()

function(nng_headers)
    foreach (f ${ARGN})
        target_sources(${PROJECT_NAME} PRIVATE ${PROJECT_SOURCE_DIR}/include/${f})
    endforeach ()
    nng_headers_testlib(${ARGN})
endfunction()

function(nng_defines)
    target_compile_definitions(${PROJECT_NAME} PRIVATE ${ARGN})
    nng_defines_testlib(${ARGN})
endfunction()

# nng_sources_if adds the sources unconditionally to the test library,
# but conditionally to the production library.  This allows us to get
# full test coverage while allowing a minimized delivery.
function(nng_sources_if COND)
    if (${COND})
        foreach (f ${ARGN})
            target_sources(${PROJECT_NAME} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/${f})
        endforeach ()
    endif ()
    nng_sources_testlib(${ARGN})
endfunction()

function(nng_headers_if COND)
    if (COND)
        foreach (f ${ARGN})
            target_sources(${PROJECT_NAME} PRIVATE ${PROJECT_SOURCE_DIR}/include/${f})
        endforeach ()
    endif ()
    nng_headers_testlib(${ARGN})
endfunction()

function(nng_defines_if COND)
    if (${COND})
        # Revisit this one
        target_compile_definitions(${PROJECT_NAME} PUBLIC ${ARGN})
    endif ()
    nng_defines_testlib(${ARGN})
endfunction()

add_subdirectory(src)

foreach (_PKG IN ITEMS ${NNG_PKGS})
    find_package(${_PKG} REQUIRED)
endforeach ()
add_definitions(${NNG_DEFS})

if (NNG_TESTS)
    add_subdirectory(tests)
    add_subdirectory(perf)
endif ()

#  Build the tools

if (NNG_ENABLE_NNGCAT)
    add_subdirectory(tools/nngcat)
endif ()

option(NNG_ENABLE_TLS "Enable TLS protocol" OFF)
if (NNG_ENABLE_TLS)
    add_definitions(-DNNG_SUPP_TLS)
    set(NNG_SUPP_TLS ON)
endif ()

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
