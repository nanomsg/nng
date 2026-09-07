#
# Copyright 2021 Staysail Systems, Inc. <info@staysail.tech>
# Copyright 2018 Capitar IT Group BV <info@capitar.com>
#
# This software is supplied under the terms of the MIT License, a
# copy of which should be located in the distribution where this
# file was obtained (LICENSE.txt).  A copy of the license may also be
# found online at https://opensource.org/licenses/MIT.
#

nng_directory(nngcat)

if (NNG_ENABLE_NNGCAT)
    add_executable(nngcat nngcat.c)
    target_include_directories(nngcat PUBLIC ${PROJECT_SOURCE_DIR}/src)
    target_link_libraries(nngcat nng nng_private)
    install(TARGETS nngcat RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
            COMPONENT Tools)

    if (NNG_TESTS AND CMAKE_SYSTEM_NAME MATCHES "Linux")
        include(FindUnixCommands)
    endif ()
    # TODO: This should be refactored to use a test driver.
    # We only run the tests on Linux for now, because the Darwin CI/CD is too brittle.
    if (NNG_TESTS AND BASH AND CMAKE_SYSTEM_NAME MATCHES "Linux")
        macro(add_nngcat_test NAME TIMEOUT)
            add_test(NAME nng.${NAME} COMMAND ${BASH} ${CMAKE_CURRENT_SOURCE_DIR}/${NAME}_test.sh $<TARGET_FILE:nngcat>)
            set_tests_properties(nng.${NAME} PROPERTIES TIMEOUT ${TIMEOUT})
        endmacro()
        add_nngcat_test(nngcat_async 10)
        add_nngcat_test(nngcat_ambiguous 10)
        add_nngcat_test(nngcat_need_proto 10)
        add_nngcat_test(nngcat_dup_proto 10)
        add_nngcat_test(nngcat_help 10)
        add_nngcat_test(nngcat_incompat 10)
        add_nngcat_test(nngcat_pubsub 20)
        add_nngcat_test(nngcat_recvmaxsz 20)
        add_nngcat_test(nngcat_unlimited 20)
        add_nngcat_test(nngcat_stdin_pipe 20)
    endif ()
endif ()
