#!/bin/bash

if [ "${COVERAGE}" != ON ]
then
	echo "Code coverage not enabled."
	exit 0
fi

# capture all coverage info
lcov --directory . --capture --output-file coverage.info || exit 1

# filter out system information (C++ templates & inlines)
lcov --remove coverage.info '/usr/*' --output-file coverage.info || exit 1

# filter out the *test* program data
lcov --remove coverage.info '*/tests/*' --output-file coverage.info || exit 1

# emit debug stats.
lcov --list coverage.info

rm coverage.info

echo 0
