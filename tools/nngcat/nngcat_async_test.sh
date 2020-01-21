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
ADDR="ipc:///tmp/nngcat_async_test"

echo -n "Verify async connect: "

${NNGCAT} --async -d 1 --connect ${ADDR} --req0 -D "ping" &


answer=$( ${NNGCAT} --rep0 --recv-timeout=3 --listen ${ADDR} -D "pong" --ascii 2>/dev/null )

if [[ ${answer} == "ping" ]]
then
	echo "pass"
	exit 0
fi

echo "Failed: req did not match"
echo "RES: $answer"
exit 1
