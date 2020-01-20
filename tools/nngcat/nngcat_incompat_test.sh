#!/bin/sh

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

echo "Verify incompatible options: "

# Just bind something to this so other ones connect
${NNGCAT} --pull0 --ascii -X /tmp/bogusipc &
pid=$!

trap "kill $pid && wait $pid 2>/dev/null" 0

echo -n "    --subscribe doesn't work with non-sub"
if ${NNGCAT} --req0 -x /tmp/bogusipc --subscribe=oops >/dev/null 2>&1
then
	echo "fail"
	exit 1
fi
echo "pass"

echo -n "    --interval doesn't work with recv only: "
if ${NNGCAT} --interval 1 --pull -x /tmp/bogusipc >/dev/null 2>&1
then
	echo "fail"
	exit 1
fi
echo "pass"

echo -n "    --pair1 doesn't work with --compat: "
if ${NNGCAT} --compat --pair1 -x /tmp/bogusipc >/dev/null 2>&1
then
	echo "fail"
	exit 1
fi
echo "pass"

echo -n "    --count doesn't work with --compat: "
if ${NNGCAT} --compat --count=1 --pair0 -x /tmp/bogusipc >/dev/null 2>&1
then
	echo "fail"
	exit 1
fi
echo "pass"

echo -n "    --count fails with non-integer: "
if ${NNGCAT} --count=xyz --pair0 -x /tmp/bogusipc >/dev/null 2>&1
then
	echo "fail"
	exit 1
fi
echo "pass"

echo -n "    --file fails with non-existing file: "
if ${NNGCAT} --async --file=/nosuchfilehere --push0 -x /tmp/bogusipc >/dev/null 2>&1
then
	echo "fail"
	exit 1
fi
echo "pass"

echo "PASS."
exit 0
