# atomic builtins are required for threading support.

INCLUDE(CheckCSourceCompiles)
INCLUDE(CheckLibraryExists)

# Sometimes linking against libatomic is required for atomic ops, if
# the platform doesn't support lock-free atomics.

function(check_working_c_atomics varname)
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
endfunction(check_working_c_atomics)

function(check_working_c_atomics_with_lib varname)
  SET(OLD_CMAKE_REQUIRED_LIBRARIES ${CMAKE_REQUIRED_LIBRARIES})
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
  SET(CMAKE_REQUIRED_LIBRARIES "${OLD_CMAKE_REQUIRED_LIBRARIES}")
endfunction(check_working_c_atomics_with_lib)

macro (CheckAtomic)
  # First check if atomics work without the library.
  check_working_c_atomics(HAVE_C_ATOMICS_WITHOUT_LIB)
  if(NOT HAVE_C_ATOMICS_WITHOUT_LIB)
    check_library_exists(atomic __atomic_fetch_add_4 "" HAVE_LIBATOMIC)
    if( HAVE_LIBATOMIC )
      check_working_c_atomics_with_lib(HAVE_C_ATOMICS_WITH_LIB)
      if (NOT HAVE_C_ATOMICS_WITH_LIB)
	message(FATAL_ERROR "Host compiler must support atomic types!")
      endif()
    else()
      message(FATAL_ERROR "Host compiler appears to require libatomic, but cannot find it.")
    endif()
  endif()
endmacro ()
