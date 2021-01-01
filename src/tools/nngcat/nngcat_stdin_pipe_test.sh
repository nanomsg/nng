#!/bin/bash

#
# Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
# Copyright 2018 Capitar IT Group BV <info@capitar.com>
# Copyright 2020 Lager Data, Inc. <support@lagerdata.com>
#
# This software is supplied under the terms of the MIT License, a
# copy of which should be located in the distribution where this
# file was obtained (LICENSE.txt).  A copy of the license may also be
# found online at https://opensource.org/licenses/MIT.
#

NNGCAT=${NNGCAT:=$1}
NNGCAT=${NNGCAT:-./nngcat}
ADDR="ipc:///tmp/nngcat_stdin_pipe_test"
OUTPUT=/tmp/nngcat_stdin_pipe_test.$$.out

echo -n "Verify reading from stdin pipe: "

trap "rm $OUTPUT" 0

${NNGCAT} --listen ${ADDR} --count=1 --recv-timeout=3 --recv-maxsz=0 --pull0 --raw > $OUTPUT 2>/dev/null &
bgid=$!

sleep 1
# for speed of execution, run these in the background, they should be ignored
echo "hello world" | ${NNGCAT} --connect ${ADDR} --delay=1 --push0 --file -
wait "$bgid" 2>/dev/null

sum=$(cksum ${OUTPUT})
sum=${sum%% *}

# This matches "hello world\n" since echo adds a trailing newline
if [[ ${sum} == 3733384285 ]]
then
	echo "pass"
	exit 0
fi
echo "FAIL: Checksum failed (Wanted 3733384285 got ${sum})"
echo "OUTPUT:"
ls -la ${OUTPUT}

exit 1
