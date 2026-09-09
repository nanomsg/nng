#!/usr/bin/env bash

#
# Copyright 2026 Staysail Systems, Inc. <info@staysail.tech>
#
# This software is supplied under the terms of the MIT License, a
# copy of which should be located in the distribution where this
# file was obtained (LICENSE.txt).  A copy of the license may also be
# found online at https://opensource.org/licenses/MIT.
#

set -euo pipefail

NNGCAT=${NNGCAT:=$1}
NNGCAT=${NNGCAT:-./nngcat}
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
WORK=$(mktemp -d)
PORT=$((30000 + ($$ % 20000)))

cleanup() {
	rm -rf "${WORK}"
}
trap cleanup EXIT

fail() {
	echo "Failed: $1"
	for output in "${WORK}"/*.out "${WORK}"/*.err
	do
		if [[ -s ${output} ]]
		then
			echo "${output}:"
			cat "${output}"
		fi
	done
	exit 1
}

echo -n "Verify TLS passphrase and PSK: "

${NNGCAT} --rep0 --listen "tls+tcp://127.0.0.1:${PORT}" \
	--cert "${SCRIPT_DIR}/nngcat_tls_cert.pem" \
	--key "${SCRIPT_DIR}/nngcat_tls_key.pem" \
	--pass secret --data pong --quoted --count 1 >"${WORK}/cert-server.out" \
	2>"${WORK}/cert-server.err" &
server=$!
sleep 1
if ! result=$(${NNGCAT} --req0 --dial "tls+tcp://127.0.0.1:${PORT}" \
	--insecure --data ping --quoted 2>"${WORK}/cert-client.err")
then
	fail "encrypted-key client could not connect"
fi
if ! wait ${server}
then
	fail "encrypted-key server failed"
fi
if [[ ${result} != '"pong"' ]] || [[ $(cat "${WORK}/cert-server.out") != '"ping"' ]]
then
	fail "encrypted-key exchange did not match"
fi

PORT=$((PORT + 1))
${NNGCAT} --rep0 --listen "tls+tcp://127.0.0.1:${PORT}" \
	--psk-identity nngcat --psk 00112233445566778899aabbccddeeff \
	--data pong --quoted --count 1 >"${WORK}/psk-server.out" \
	2>"${WORK}/psk-server.err" &
server=$!
sleep 1
if ! result=$(${NNGCAT} --req0 --dial "tls+tcp://127.0.0.1:${PORT}" \
	--psk-identity nngcat --psk 00112233445566778899aabbccddeeff \
	--data ping --quoted 2>"${WORK}/psk-client.err")
then
	fail "PSK client could not connect"
fi
if ! wait ${server}
then
	fail "PSK server failed"
fi
if [[ ${result} != '"pong"' ]] || [[ $(cat "${WORK}/psk-server.out") != '"ping"' ]]
then
	fail "PSK exchange did not match"
fi

echo "pass"
