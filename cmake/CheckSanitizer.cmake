#
# Copyright 2019 Staysail Systems, Inc. <info@staysail.tech>
# Copyright 2017 Capitar IT Group BV <info@capitar.com>
#
# This software is supplied under the terms of the MIT License, a
# copy of which should be located in the distribution where this
# file was obtained (LICENSE.txt).  A copy of the license may also be
# found online at https://opensource.org/licenses/MIT.
#

macro (CheckSanitizer)

    if (CMAKE_C_COMPILER_ID STREQUAL "GNU")
        set(NNG_SAN_LIST none address leak memory thread undefined)
    elseif (CMAKE_C_COMPILER_ID STREQUAL "Clang")
        set(NNG_SAN_LIST none address leak memory thread undefined)
    elseif (CMAKE_C_COMPILER_ID STREQUAL "AppleClang")
        set(NNG_SAN_LIST none address thread undefined) 
    else ()
        set(NNG_SAN_LIST none)
    endif ()
    set (NNG_SANITIZER none CACHE STRING "Sanitizer to use (clang or gcc).")
    set_property(CACHE NNG_SANITIZER PROPERTY STRINGS ${NNG_SAN_LIST})
    mark_as_advanced (NNG_SANITIZER)

    if (NOT NNG_SANITIZER STREQUAL "none")
        set (NNG_C_FLAG_SANITIZER "-fsanitize=${NNG_SANITIZER}")
        message(STATUS "Enabling sanitizer: ${NNG_C_FLAG_SANITIZER}")
    endif()
endmacro ()
