#!/bin/bash

#
# Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
# Copyright 2018 Capitar IT Group BV <info@capitar.com>
#
# This software is supplied under the terms of the MIT License, a
# copy of which should be located in the distribution where this
# file was obtained (LICENSE.txt).  A copy of the license may also be
# found online at https://opensource.org/licenses/MIT.
#

NNGCAT=${NNGCAT:=$1}
NNGCAT=${NNGCAT:-./nngcat}
CMD="${NNGCAT} --re --dial=tcp://127.0.0.1:27272"

echo -n "Verify ambiguous options fail: "
if ${CMD} >/dev/null 2>&1
then
	echo "Failed: ambigous accepted"
	exit 1
fi
x=$(${CMD} 2>&1)
if [[ ${x} =~ "ambiguous" ]]
then
	echo "pass"
	exit 0
fi

echo "Failed: error did not match"
exit 1
