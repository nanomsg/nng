#
# Copyright 2020 Staysail Systems, Inc. <info@staysail.tech>
# Copyright 2018 Capitar IT Group BV <info@capitar.com>
#
# This software is supplied under the terms of the MIT License, a
# copy of which should be located in the distribution where this
# file was obtained (LICENSE.txt).  A copy of the license may also be
# found online at https://opensource.org/licenses/MIT.
#

nng_sources(nng.c)
nng_headers(nng/nng.h)


target_include_directories(nng PRIVATE ${PROJECT_SOURCE_DIR}/src)
target_include_directories(nng_testing PRIVATE ${PROJECT_SOURCE_DIR}/src)

add_subdirectory(core)

add_subdirectory(platform/windows)
add_subdirectory(platform/posix)
add_subdirectory(compat/nanomsg)

add_subdirectory(protocol/bus0)
add_subdirectory(protocol/pair0)
add_subdirectory(protocol/pair1)
add_subdirectory(protocol/pipeline0)
add_subdirectory(protocol/pubsub0)
add_subdirectory(protocol/reqrep0)
add_subdirectory(protocol/survey0)

add_subdirectory(transport/inproc)
add_subdirectory(transport/ipc)
add_subdirectory(transport/tcp)
add_subdirectory(transport/tls)
add_subdirectory(transport/ws)
add_subdirectory(transport/zerotier)

add_subdirectory(supplemental/base64)
add_subdirectory(supplemental/http)
add_subdirectory(supplemental/sha1)
add_subdirectory(supplemental/tcp)
add_subdirectory(supplemental/tls)
add_subdirectory(supplemental/util)
add_subdirectory(supplemental/websocket)

# When building shared libraries we prefer to suppress default symbol
# visibility, so that only the symbols that should be exposed in the
# resulting library are.  This is the default with Windows.
if (BUILD_SHARED_LIBS)
    target_compile_definitions(nng PRIVATE NNG_SHARED_LIB)
    if (NNG_HIDDEN_VISIBILITY)
        target_compile_definitions(nng PRIVATE NNG_HIDDEN_VISIBILITY)
        set_target_properties(nng PROPERTIES C_VISIBILITY_PRESET hidden)
    endif ()
else ()
    target_compile_definitions(nng PUBLIC NNG_STATIC_LIB)
endif ()

set_target_properties(nng PROPERTIES SOVERSION ${NNG_ABI_SOVERSION} VERSION "${NNG_ABI_VERSION}")

set_target_properties(nng PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR})
set_target_properties(nng PROPERTIES LIBRARY_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR})
set_target_properties(nng PROPERTIES ARCHIVE_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR})
set_target_properties(nng PROPERTIES FRAMEWORK OFF)

target_include_directories(nng INTERFACE $<INSTALL_INTERFACE:include>
        $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>)

target_include_directories(nng PRIVATE ${PROJECT_SOURCE_DIR}/include)
target_include_directories(nng_testing PUBLIC ${PROJECT_SOURCE_DIR}/include)

install(TARGETS ${PROJECT_NAME}
        EXPORT ${PROJECT_NAME}-target
        FRAMEWORK DESTINATION ${CMAKE_INSTALL_LIBDIR} COMPONENT Library
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR} COMPONENT Library
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR} COMPONENT Library
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR} COMPONENT Tools
        )

install(EXPORT ${PROJECT_NAME}-target
        FILE ${PROJECT_NAME}-targets.cmake
        NAMESPACE nng::
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME}
        COMPONENT Library
        )

export(EXPORT ${PROJECT_NAME}-target
        FILE ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}-targets.cmake
        NAMESPACE nng::)

# Install the header files.
install(DIRECTORY ../include/nng
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
        COMPONENT Headers)

# These are promoted for testing
set(NNG_SUPP_BASE64 ${NNG_SUPP_BASE64} PARENT_SCOPE)
set(NNG_SUPP_HTTP ${NNG_SUPP_HTTP} PARENT_SCOPE)
set(NNG_SUPP_SHA1 ${NNG_SUPP_SHA1} PARENT_SCOPE)
set(NNG_SUPP_WEBSOCKET ${NNG_SUPP_WEBSOCKET} PARENT_SCOPE)

# Configure files

set(INCLUDE_INSTALL_DIRS "${CMAKE_INSTALL_INCLUDEDIR}/nng")

include(CMakePackageConfigHelpers)
set(version_config "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}-config-version.cmake")
set(project_config "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}-config.cmake")

write_basic_package_version_file("${version_config}"
        VERSION ${NNG_PACKAGE_VERSION}
        COMPATIBILITY SameMajorVersion
        )
configure_package_config_file(${PROJECT_SOURCE_DIR}/cmake/${PROJECT_NAME}-config.cmake.in "${project_config}"
        INSTALL_DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME}"
        PATH_VARS INCLUDE_INSTALL_DIRS)

install(FILES "${project_config}" "${version_config}"
        DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME}"
        COMPONENT Library)
