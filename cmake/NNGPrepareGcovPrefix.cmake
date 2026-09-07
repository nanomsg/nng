#
# Place the compiler-generated .gcno metadata beside each relocated .gcda
# file.  The test environment supplies a unique GCOV_PREFIX, so this must run
# after CTest has generated the data files.
#

if (NOT DEFINED NNG_BUILD_DIR)
    message(FATAL_ERROR "NNG_BUILD_DIR must name the CMake build directory")
endif ()

file(GLOB_RECURSE NNG_GCNO_FILES RELATIVE "${NNG_BUILD_DIR}"
        "${NNG_BUILD_DIR}/*.gcno")
file(GLOB_RECURSE NNG_GCDA_FILES RELATIVE "${NNG_BUILD_DIR}"
        "${NNG_BUILD_DIR}/coverage/*.gcda")
if (NOT NNG_GCDA_FILES)
    message(FATAL_ERROR "No relocated .gcda files found in ${NNG_BUILD_DIR}")
endif ()

foreach (NNG_GCDA_FILE ${NNG_GCDA_FILES})
    string(REGEX REPLACE "\\.gcda$" ".gcno" NNG_GCNO_NAME
            "${NNG_GCDA_FILE}")
    string(LENGTH "${NNG_GCNO_NAME}" NNG_GCNO_NAME_LENGTH)
    set(NNG_GCNO_FOUND FALSE)

    foreach (NNG_GCNO_FILE ${NNG_GCNO_FILES})
        if (NOT NNG_GCNO_FILE MATCHES "^coverage/")
            string(LENGTH "${NNG_GCNO_FILE}" NNG_GCNO_FILE_LENGTH)
            math(EXPR NNG_GCNO_START
                    "${NNG_GCNO_NAME_LENGTH} - ${NNG_GCNO_FILE_LENGTH}")
            if (NNG_GCNO_START GREATER_EQUAL 0)
                string(SUBSTRING "${NNG_GCNO_NAME}" ${NNG_GCNO_START}
                        ${NNG_GCNO_FILE_LENGTH} NNG_GCNO_SUFFIX)
                if (NNG_GCNO_SUFFIX STREQUAL NNG_GCNO_FILE)
                    get_filename_component(NNG_GCDA_DIR
                            "${NNG_BUILD_DIR}/${NNG_GCDA_FILE}" DIRECTORY)
                    file(COPY "${NNG_BUILD_DIR}/${NNG_GCNO_FILE}"
                            DESTINATION "${NNG_GCDA_DIR}")
                    set(NNG_GCNO_FOUND TRUE)
                    break()
                endif ()
            endif ()
        endif ()
    endforeach ()

    if (NOT NNG_GCNO_FOUND)
        message(FATAL_ERROR "No .gcno file matches ${NNG_GCDA_FILE}")
    endif ()
endforeach ()
