#!/bin/bash

# Copyright 2017 Garrett D'Amore <garrett@damore.org>
# Copyright 2017 Capitar IT Group BV <info@capitar.com>
#
# This software is supplied under the terms of the MIT License, a
# copy of which should be located in the distribution where this
# file was obtained (LICENSE.txt).  A copy of the license may also be
# found online at https://opensource.org/licenses/MIT.

if [ "${COVERAGE}" != ON ]
then
	echo "Code coverage not enabled."
	exit 0
fi

GCOV=${GCOV:-gcov}

# capture all coverage info
lcov --gcov-tool ${GCOV} --directory . --capture --output-file coverage.info || exit 1

# filter out system information (C++ templates & inlines)
lcov --remove coverage.info '/usr/*' --output-file coverage.info || exit 1

# filter out the *test* program data
lcov --remove coverage.info '*/tests/*' --output-file coverage.info || exit 1

# emit debug stats.
lcov --list coverage.info

rm coverage.info

echo 0
