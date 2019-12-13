# Copyright 2019 Hugo Lindström <hugolm84@gmail.com>
#
# This software is supplied under the terms of the MIT License, a
# copy of which should be located in the distribution where this
# file was obtained (LICENSE.txt).  A copy of the license may also be
# found online at https://opensource.org/licenses/MIT.

# Usage:
#find_package (ClangTidy 9.0)
#if (CLANG_TIDY)
#    set_target_properties (${PROJECT_NAME}
#        PROPERTIES
#            C_CLANG_TIDY "${CLANG_TIDY_COMMAND}"
#            CXX_CLANG_TIDY "${CLANG_TIDY_COMMAND}"
#    )
#endif ()

option (CLANG_TIDY "Use ClangTidy for static code analysis" OFF)
option (CLANG_TIDY_FIX "Automatically attempt to fix clang-tidy suggestions and errors" OFF)

if (NOT CLANG_TIDY)
    return()
endif()

find_program (CLANG_TIDY_BIN
    NAMES
        "clang-tidy-${ClangTidy_FIND_VERSION}"
        "clang-tidy-${ClangTidy_FIND_VERSION_MAJOR}"
        "clang-tidy"
)

execute_process (COMMAND ${CLANG_TIDY_BIN} "--version" OUTPUT_VARIABLE CMD_OUTPUT)

if (NOT ${CMD_OUTPUT} MATCHES "${ClangTidy_FIND_VERSION}")
    if(ClangTidy_FIND_VERSION_EXACT)
        message (FATAL_ERROR "Could not find clang-tidy (${ClangTidy_FIND_VERSION})")
    endif()
    if(NOT ${CMD_OUTPUT} MATCHES "${ClangTidy_FIND_VERSION_MAJOR}.[0-9]")
        message (FATAL_ERROR "Could not find clang-tidy (${ClangTidy_FIND_VERSION_MAJOR})")
    endif()
endif()

set (ClangTidy_FOUND TRUE)
set (CMAKE_EXPORT_COMPILE_COMMANDS ON)
set (CLANG_TIDY_COMMAND "${CLANG_TIDY_BIN}")

message (STATUS "Clang-Tidy         : ${CLANG_TIDY}")
message (STATUS "    Binary         : ${CLANG_TIDY_BIN}")

if (CLANG_TIDY_FIX)
    set(CLANG_TIDY_COMMAND  ${CLANG_TIDY_COMMAND} "-fix" "-fix-errors")
endif()

if (C_CLANG_TIDY_EXTRA_FLAGS)
    set (CLANG_TIDY_COMMAND "${CLANG_TIDY_COMMAND}" "${C_CLANG_TIDY_EXTRA_FLAGS}")
endif()

if (CXX_CLANG_TIDY_EXTRA_FLAGS)
    set (CLANG_TIDY_COMMAND "${CLANG_TIDY_COMMAND}" "${CXX_CLANG_TIDY_EXTRA_FLAGS}")
endif()

message (STATUS "    Command        : ${CLANG_TIDY_COMMAND}")