# Copyright 2019 Hugo Lindström <hugolm84@gmail.com>
#
# This software is supplied under the terms of the MIT License, a
# copy of which should be located in the distribution where this
# file was obtained (LICENSE.txt).  A copy of the license may also be
# found online at https://opensource.org/licenses/MIT.

# Usage:
#find_package(ClangFormat 9.0 EXACT)
#if(ClangFormat_FOUND)
#   add_custom_target(format
#       COMMAND ${CLANG_FORMAT_BIN}
#        -i
#        -style=file
#        ${FORMAT_SOURCE_FILES}
#       VERBATIM
#       COMMENT "Auto formatting all source files..."
#   )
#endif()

if (${CMAKE_VERSION} VERSION_GREATER_EQUAL "3.10.0")
    include_guard(GLOBAL)
endif()

option (CLANG_FORMAT "Use clang-format to format all source files via custom target `format`" ON)

if (NOT CLANG_FORMAT)
    return()
endif()

find_program (CLANG_FORMAT_BIN
    NAMES
        "clang-format-${ClangFormat_FIND_VERSION}"
        "clang-format-${ClangFormat_FIND_VERSION_MAJOR}"
        "clang-format"
    HINTS
        $ENV{ProgramW6432}/LLVM/bin
        $ENV{ProgramFiles}/LLVM/bin
)

execute_process (COMMAND ${CLANG_FORMAT} "--version" OUTPUT_VARIABLE CMD_OUTPUT)

if (NOT ${CMD_OUTPUT} MATCHES "${ClangFormat_FIND_VERSION}")
    if (ClangFormat_FIND_VERSION_EXACT)
        message (FATAL_ERROR "Could not find clang-format (${ClangFormat_FIND_VERSION})")
    endif()
    if (NOT ${CMD_OUTPUT} MATCHES "${ClangFormat_FIND_VERSION_MAJOR}.[0-9]")
        message (FATAL_ERROR "Could not find clang-format (${ClangFormat_FIND_VERSION_MAJOR})")
    endif()
endif()

set (ClangFormat_FOUND TRUE)
message (STATUS "Clang-Format       : ${CLANG_FORMAT}")
message (STATUS "    Binary         : ${CLANG_FORMAT_BIN}")
