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
ADDR="ipc:///tmp/nngcat_pub_sub_test"
OUTPUT=/tmp/nngcat_pubsub_test.$$.out

echo -n "Verify pub sub: "

trap "rm $OUTPUT" 0

${NNGCAT} --listen ${ADDR} --count=3 --recv-timeout=20 --sub0 --subscribe=one --subscribe=two --quoted > $OUTPUT 2>/dev/null &
sleep 1
# for speed of execution, run these in the background, they should be ignored
${NNGCAT} -d 1 --connect ${ADDR} --pub0 --data "xyz" &
${NNGCAT} -d 1 --connect ${ADDR} --pub0 -D "none swam" &
# these we care about, due to ordering (checksum) so run them serially
${NNGCAT} -d 1 --connect ${ADDR} --pub0 -D "one flew"
${NNGCAT} -d 1 --connect ${ADDR} --pub0 --data "twofer test"
${NNGCAT} -d 1 --connect ${ADDR} --pub0 --data "one more"

wait $bgid 2>/dev/null

sum=$(cksum ${OUTPUT})
sum=${sum%% *}
if [[ ${sum} == 3929078614 ]]
then
	echo "pass"
	exit 0
fi
echo "FAIL: Checksum failed (Wanted 3929078614 got ${sum})"
echo "OUTPUT:"
cat ${OUTPUT}

exit 1
