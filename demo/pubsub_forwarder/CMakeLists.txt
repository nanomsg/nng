# This software is supplied under the terms of the MIT License, a
# copy of which should be located in the distribution where this
# file was obtained (LICENSE.txt).  A copy of the license may also be
# found online at https://opensource.org/licenses/MIT.

cmake_minimum_required(VERSION 3.10)
project(pubsub_forwarder C)

# Find the nng library
find_package(nng REQUIRED)

# Add the executable target
add_executable(pubsub_forwarder pubsub_forwarder.c)

target_compile_options(pubsub_forwarder PRIVATE -Wall -Wextra -Wpedantic -Werror -O2)

# Link against the nng library
target_link_libraries(pubsub_forwarder PRIVATE nng)
