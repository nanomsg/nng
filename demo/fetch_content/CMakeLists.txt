# This software is supplied under the terms of the MIT License, a
# copy of which should be located in the distribution where this
# file was obtained (LICENSE.txt).  A copy of the license may also be
# found online at https://opensource.org/licenses/MIT.

cmake_minimum_required (VERSION 3.11)

include(FetchContent)

FetchContent_Declare(
	nng
	GIT_REPOSITORY https://github.com/dksmiffs/nng.git
	GIT_TAG        cb1597d86c4527178b71598c510889db0741fa09
	FIND_PACKAGE_ARGS
)

FetchContent_MakeAvailable(nng)

project(fetch_content)

find_package(nng)

add_executable(version version.c)
target_link_libraries(version PRIVATE nng::nng)
