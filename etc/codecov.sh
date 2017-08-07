#!/bin/bash

if [ "${COVERAGE}" != ON ]
then
	echo "Code coverage not enabled."
	exit 0
fi

bash <(curl -s https://codecov.io/bash) || echo "Codecov did not collect coverage"
echo 0
