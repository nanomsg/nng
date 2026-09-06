#
# Prepare a separate GCOV data tree for every CTest test.  The tests set
# GCOV_PREFIX themselves; this places the matching .gcno metadata beside the
# relocated .gcda data so that gcov-compatible reporting tools can read it.
#

if (NOT DEFINED NNG_BUILD_DIR)
    message(FATAL_ERROR "NNG_BUILD_DIR must name the CMake build directory")
endif ()

find_program(NNG_CTEST_COMMAND ctest)
if (NOT NNG_CTEST_COMMAND)
    message(FATAL_ERROR "ctest was not found")
endif ()

execute_process(
    COMMAND ${NNG_CTEST_COMMAND} --test-dir ${NNG_BUILD_DIR} -N
    RESULT_VARIABLE NNG_CTEST_RESULT
    OUTPUT_VARIABLE NNG_CTEST_OUTPUT
)
if (NOT NNG_CTEST_RESULT EQUAL 0)
    message(FATAL_ERROR "Unable to list tests in ${NNG_BUILD_DIR}")
endif ()

string(REGEX MATCHALL "Test #[0-9]+: [^\r\n]+" NNG_CTEST_ENTRIES
        "${NNG_CTEST_OUTPUT}")
file(GLOB_RECURSE NNG_GCNO_FILES RELATIVE ${NNG_BUILD_DIR}
        ${NNG_BUILD_DIR}/*.gcno)

foreach (NNG_CTEST_ENTRY ${NNG_CTEST_ENTRIES})
    string(REGEX REPLACE "^Test #[0-9]+: " "" NNG_TEST_NAME
            "${NNG_CTEST_ENTRY}")
    foreach (NNG_GCNO_FILE ${NNG_GCNO_FILES})
        if (NOT NNG_GCNO_FILE MATCHES "^coverage/")
            get_filename_component(NNG_GCNO_DIR ${NNG_GCNO_FILE} DIRECTORY)
            set(NNG_GCNO_DESTINATION
                    ${NNG_BUILD_DIR}/coverage/${NNG_TEST_NAME}/${NNG_GCNO_DIR})
            file(MAKE_DIRECTORY ${NNG_GCNO_DESTINATION})
            file(COPY ${NNG_BUILD_DIR}/${NNG_GCNO_FILE}
                    DESTINATION ${NNG_GCNO_DESTINATION})
        endif ()
    endforeach ()
endforeach ()
