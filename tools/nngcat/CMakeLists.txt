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
    install (TARGETS nngcat RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()
