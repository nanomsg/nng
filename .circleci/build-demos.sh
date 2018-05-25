#!/bin/bash

#
# build the demos to make sure they all build cleanly
#

for dir in demo/*; do
	demo=$(dirname $dir)
	mkdir build-demo-${demo}
	( cd build-demo-${demo};
	cmake -G Ninja ../demo/${demo};
	ninja )
done
