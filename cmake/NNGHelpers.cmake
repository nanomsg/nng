#
# Copyright 2020 Staysail Systems, Inc. <info@staysail.tech>
#
# This software is supplied under the terms of the MIT License, a
# copy of which should be located in the distribution where this
# file was obtained (LICENSE.txt).  A copy of the license may also be
# found online at https://opensource.org/licenses/MIT.
#

# Some NNG helper functions.

include(CheckFunctionExists)
include(CheckSymbolExists)
include(CheckStructHasMember)
include(CheckLibraryExists)
include(CheckCSourceCompiles)

# nng_sources adds library sources using files in the current directory.
function(nng_sources)
    foreach (f ${ARGN})
        target_sources(nng PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/${f})
        target_sources(nng_testing PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/${f})
    endforeach ()
endfunction()

# nng_headers adds library sources as public headers taken rooted at the include/ directory.
function(nng_headers)
    foreach (f ${ARGN})
        target_sources(nng PRIVATE ${PROJECT_SOURCE_DIR}/include/${f})
        target_sources(nng_testing PRIVATE ${PROJECT_SOURCE_DIR}/include/${f})
    endforeach ()
endfunction()

# nng_defines adds defines unconditionally.
# The public library keeps these defines private, but the test library exposes these definitions
# as some of our test cases would like to know details about how the library was compiled
# as that may modify the tests themselves.
function(nng_defines)
    target_compile_definitions(nng PRIVATE ${ARGN})
    target_compile_definitions(nng_testing PUBLIC ${ARGN})
    target_compile_definitions(nng_private INTERFACE ${ARGN})
endfunction()

# nng_link_libraries adds link dependencies to the libraries.
function(nng_link_libraries)
    target_link_libraries(nng PRIVATE ${ARGN})
    target_link_libraries(nng_testing PRIVATE ${ARGN})
endfunction()

# nng_include_directories adds include directories.
function(nng_include_directories)
    target_include_directories(nng PRIVATE ${ARGN})
    target_include_directories(nng_testing PRIVATE ${ARGN})
endfunction()


# nng_sources_if adds the sources unconditionally to the test library,
# but conditionally to the production library.  This allows us to get
# full test coverage while allowing a minimized delivery.
function(nng_sources_if COND)
    foreach (f ${ARGN})
        if (${COND})
            target_sources(nng PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/${f})
        endif ()
        target_sources(nng_testing PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/${f})
    endforeach ()
endfunction()

function(nng_headers_if COND)
    foreach (f ${ARGN})
        if (COND)
            target_sources(nng PRIVATE ${PROJECT_SOURCE_DIR}/include/${f})
        endif ()
        target_sources(nng_testing PRIVATE ${PROJECT_SOURCE_DIR}/include/${f})
    endforeach ()
endfunction()

function(nng_defines_if COND)
    if (${COND})
        target_compile_definitions(nng PRIVATE ${ARGN})
        target_compile_definitions(nng_private INTERFACE ${ARGN})
    endif ()
    target_compile_definitions(nng_testing PUBLIC ${ARGN})
endfunction()

function(nng_link_libraries_if COND)
    if (${COND})
        target_link_libraries(nng PRIVATE ${ARGN})
    endif ()
    target_link_libraries(nng_testing PRIVATE ${ARGN})
endfunction()

function(nng_test NAME)
    if (NNG_TESTS)
        add_executable(${NAME} ${NAME}.c ${ARGN})
        target_link_libraries(${NAME} nng_testing)
        target_include_directories(${NAME} PRIVATE
                ${PROJECT_SOURCE_DIR}/tests
                ${PROJECT_SOURCE_DIR}/src
                ${PROJECT_SOURCE_DIR}/include)
        add_test(NAME ${NNG_TEST_PREFIX}.${NAME} COMMAND ${NAME} -t -v)
        set_tests_properties(${NNG_TEST_PREFIX}.${NAME} PROPERTIES TIMEOUT 180)
    endif ()
endfunction()

function(nng_test_if COND NAME)
    if (${COND} AND NNG_TESTS)
        add_executable(${NAME} ${NAME}.c ${ARGN})
        target_link_libraries(${NAME} nng_testing)
        target_include_directories(${NAME} PRIVATE
                ${PROJECT_SOURCE_DIR}/tests
                ${PROJECT_SOURCE_DIR}/src
                ${PROJECT_SOURCE_DIR}/include)
        add_test(NAME ${NNG_TEST_PREFIX}.${NAME} COMMAND ${NAME} -t -v)
        set_tests_properties(${NNG_TEST_PREFIX}.${NAME} PROPERTIES TIMEOUT 180)
    endif ()
endfunction()

function(nng_check_func SYM DEF)
    check_function_exists(${SYM} ${DEF})
    if (${DEF})
        target_compile_definitions(nng PRIVATE ${DEF}=1)
        target_compile_definitions(nng_testing PUBLIC ${DEF}=1)
        target_compile_definitions(nng_private INTERFACE ${DEF}=1)
    endif ()
endfunction(nng_check_func)

function(nng_check_sym SYM HDR DEF)
    check_symbol_exists(${SYM} ${HDR} ${DEF})
    if (${DEF})
        target_compile_definitions(nng PRIVATE ${DEF}=1)
        target_compile_definitions(nng_testing PUBLIC ${DEF}=1)
        target_compile_definitions(nng_private INTERFACE ${DEF}=1)
    endif ()
endfunction(nng_check_sym)

function(nng_check_lib LIB SYM DEF)
    check_library_exists(${LIB} ${SYM} "" ${DEF})
    if (${DEF})
        target_compile_definitions(nng PRIVATE ${DEF}=1)
        target_compile_definitions(nng_testing PUBLIC ${DEF}=1)
        target_compile_definitions(nng_private INTERFACE ${DEF}=1)
        target_link_libraries(nng PRIVATE ${LIB})
        target_link_libraries(nng_testing PRIVATE ${LIB})
    endif ()
endfunction(nng_check_lib)

function(nng_check_struct_member STR MEM HDR DEF)
    check_struct_has_member("struct ${STR}" ${MEM} ${HDR} ${DEF})
    if (${DEF})
        target_compile_definitions(nng PRIVATE ${DEF}=1)
        target_compile_definitions(nng_testing PUBLIC ${DEF}=1)
        target_compile_definitions(nng_private INTERFACE ${DEF}=1)
    endif ()
endfunction(nng_check_struct_member)

macro(nng_directory DIR)
    set(NNG_TEST_PREFIX ${NNG_TEST_PREFIX}.${DIR})
endmacro(nng_directory)