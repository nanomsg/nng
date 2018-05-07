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

echo -n "Verify unlimited receive size: "

NNGCAT=${NNGCAT:-./nngcat}
ADDR="ipc:///tmp/nngcat_unlimited_test"
INPUT=/tmp/nngcat_unlimited_test.$$.in
OUTPUT=/tmp/nngcat_unlimited_test.$$.out
trap "rm $OUTPUT $INPUT" 0

# 4 MB
dd if=/dev/urandom of=${INPUT} bs=1024 count=4096 >/dev/null 2>&1
goodsum=$(cksum ${INPUT})
goodsum=${goodsum%% *}

${NNGCAT} --listen ${ADDR} --count=1 --recv-maxsz=0 --pull0 --raw > $OUTPUT 2>/dev/null &
sleep 1
# for speed of execution, run these in the background, they should be ignored
${NNGCAT} --connect ${ADDR} --push0 --file ${INPUT}
wait $bgid 2>/dev/null

sum=$(cksum ${OUTPUT})
sum=${sum%% *}

if [[ ${sum} == ${goodsum} ]]
then
	echo "pass"
	exit 0
fi
echo "FAIL: Checksum failed (Wanted ${goodsum} got ${sum})"
echo "OUTPUT:"
ls -la ${OUTPUT}

exit 1
