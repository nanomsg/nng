#
# Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
# Copyright 2018 Capitar IT Group BV <info@capitar.com>
#
# This software is supplied under the terms of the MIT License, a
# copy of which should be located in the distribution where this
# file was obtained (LICENSE.txt).  A copy of the license may also be
# found online at https://opensource.org/licenses/MIT.
#

if (NNG_ENABLE_NNGCAT)
    add_executable (nngcat nngcat.c)
    target_include_directories (nngcat PUBLIC ${PROJECT_SOURCE_DIR}/src)
    target_link_libraries (nngcat ${PROJECT_NAME})
    install (TARGETS nngcat RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
        COMPONENT Tools)

    if (NNG_TESTS AND NNG_PLATFORM_POSIX AND BASH)
    macro(add_nngcat_test NAME TIMEOUT)
        add_test (NAME ${NAME} COMMAND ${BASH} ${CMAKE_CURRENT_SOURCE_DIR}/${NAME}_test.sh $<TARGET_FILE:nngcat>)
        set_tests_properties (${NAME} PROPERTIES TIMEOUT ${TIMEOUT})
    endmacro()
    add_nngcat_test (nngcat_async 10)
    add_nngcat_test (nngcat_ambiguous 2)
    add_nngcat_test (nngcat_need_proto 2)
    add_nngcat_test (nngcat_dup_proto 2)
    add_nngcat_test (nngcat_help 2)
    add_nngcat_test (nngcat_incompat 2)
    add_nngcat_test (nngcat_pubsub 20)
    add_nngcat_test (nngcat_recvmaxsz 20)
    add_nngcat_test (nngcat_unlimited 20)
    add_nngcat_test (nngcat_stdin_pipe 20)
    endif()
endif()
