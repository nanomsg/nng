#!/bin/bash

#
# common build & test steps for CircleCI jobs
#
cmake --version
ninja --version

mkdir build
cd build
cmake -G Ninja -DCMAKE_BUILD_TYPE=${BUILD_TYPE:-Debug} -DNNG_ENABLE_COVERAGE=${COVERAGE:-OFF} -DBUILD_SHARED_LIBS=${SHARED_LIBS:=ON} ..
