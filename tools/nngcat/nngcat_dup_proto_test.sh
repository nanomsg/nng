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

echo -n "Verify only a single protocol is allowed: "
if ${NNGCAT} --pub0 --sub0 --dial=tcp://127.0.0.1:8989 >/dev/null 2>&1
then
	echo "Failed: duplicate protocols accepted"
	exit 1
fi
echo "pass"
exit 0
