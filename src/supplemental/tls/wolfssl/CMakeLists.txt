#
# Copyright 2020 Staysail Systems, Inc. <info@staysail.tech>
#
# This software is supplied under the terms of the MIT License, a
# copy of which should be located in the distribution where this
# file was obtained (LICENSE.txt).  A copy of the license may also be
# found online at https://opensource.org/licenses/MIT.
#

# Enabling wolfSSL requires that the extern/nng-wolfssl submodule
# be populated.  Note also that this action changes the licensing
# restrictions around the resulting library!

if (NNG_TLS_ENGINE STREQUAL "wolf")
    add_subdirectory(${PROJECT_SOURCE_DIR}/extern/nng-wolfssl nng-wolfssl)
    target_include_directories(nng-wolfssl PRIVATE )
    target_link_libraries(nng PRIVATE nng-wolfssl)
    if (TARGET nng_testlib)
        target_link_libraries(nng_testlib PRIVATE nng-wolfssl)
    endif ()

    nng_defines(NNG_TLS_ENGINE_INIT=nng_tls_engine_init_wolf)
    nng_defines(NNG_TLS_ENGINE_FINI=nng_tls_engine_fini_wolf)
    nng_defines(NNG_SUPP_TLS)

endif ()
