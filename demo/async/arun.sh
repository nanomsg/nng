#!/usr/bin/env bash
########################################################################
### Start asynchronous clients that can
### wait for asynchronous server to start
########################################################################

### Usage:  ./arun.sh [client#]
### - client# => do not start server until just before this client

### Socket file; client count
ADDR=ipc:///tmp/async_demo
COUNT=10

### Client # to match when server should be started; clear server PID
SERVER_ORDINAL=$1
unset SERVER_PID

### Create CLIENT_PID as an array
typeset -a CLIENT_PID
i=0
while (( i < COUNT ))
do
	i=$(( i + 1 ))

	### Start server before the matching client
	if [ "$SERVER_ORDINAL" == "$i" ] ; then
		./server $ADDR &
		SERVER_PID=$!
		echo Started server before client $i
		trap "kill $SERVER_PID" 0
	fi

	### Start start client with NONBLOCK envvar set
	### so client will wait for socket to be open on nng_dial
	rnd=$(( RANDOM % 1000 + 500 ))
	echo "Starting client $i: server will reply after $rnd msec"
	NONBLOCK= ./client $ADDR $rnd &
	### Add this client's PID to client PID array
	eval CLIENT_PID[$i]=$!
done

### Start server if not yet started
[ "$SERVER_PID" ] || \
{
	./server $ADDR &
	SERVER_PID=$!
	echo Starting server after last client - SERVER_PID=$SERVER_PID
	trap "kill $SERVER_PID" 0
}

### Wait for clients to complete
i=0
while (( i < COUNT ))
do
	i=$(( i + 1 ))
	wait ${CLIENT_PID[$i]}
done
### Kill server
kill $SERVER_PID
