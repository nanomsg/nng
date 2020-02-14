#
# Copyright 2020 Kenneth Haase <kh@beingmeta.com>
#
# This software is supplied under the terms of the MIT License, a
# copy of which should be located in the distribution where this
# file was obtained (LICENSE.txt).  A copy of the license may also be
# found online at https://opensource.org/licenses/MIT.
#

# atomic builtins are required for threading support.

INCLUDE(CheckIncludeFiles)
INCLUDE(CheckCSourceCompiles)
INCLUDE(CheckLibraryExists)

# Sometimes linking against libatomic is required for atomic ops, if
# the platform doesn't support lock-free atomics.

function(check_c_atomics_without_lib varname)
  CHECK_C_SOURCE_COMPILES("
#include <stdatomic.h>
int main() {
  _Atomic long long x;
  atomic_store(&x,3);
  long long y = atomic_load(&x);
  atomic_fetch_add(&x,12);
  long long z = atomic_load(&x);
  
  return x;
}
" ${varname})
endfunction(check_c_atomics_without_lib)

function(check_c_atomics_with_lib varname)
  SET(SAVED_CMAKE_REQUIRED_LIBRARIES ${CMAKE_REQUIRED_LIBRARIES})
  list(APPEND CMAKE_REQUIRED_LIBRARIES "atomic")
  CHECK_C_SOURCE_COMPILES("
#include <stdatomic.h>
int main() {
  _Atomic long long x;
  atomic_store(&x,3);
  long long y = atomic_load(&x);
  atomic_fetch_add(&x,12);
  long long z = atomic_load(&x);
  
  return x;
}
" ${varname})
  SET(CMAKE_REQUIRED_LIBRARIES "${SAVED_CMAKE_REQUIRED_LIBRARIES}")
endfunction(check_c_atomics_with_lib)

macro (CheckAtomicLib)
  # First check if atomics work without the library.
  if(MSVC)
    set(HAVE_C_ATOMICS_WITHOUT_LIB True)
  else()
    check_c_atomics_without_lib(HAVE_C_ATOMICS_WITHOUT_LIB)
    if(NOT HAVE_C_ATOMICS_WITHOUT_LIB)
      check_library_exists(atomic __atomic_fetch_add_8 "" HAVE_LIBATOMIC)
      if( HAVE_LIBATOMIC )
	check_c_atomics_with_lib(HAVE_C_ATOMICS_WITH_LIB)
	if (NOT HAVE_C_ATOMICS_WITH_LIB)
	  message(FATAL_ERROR "Host compiler must support atomic types!")
	endif()
      else()
	message(FATAL_ERROR "Host compiler appears to require libatomic, but cannot find it.")
      endif()
    endif()
  endif()
endmacro (CheckAtomicLib)
