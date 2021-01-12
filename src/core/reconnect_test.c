//
// Copyright 2020 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <string.h>

#include <nuts.h>

void
test_dial_before_listen(void)
{
	nng_socket s1;
	nng_socket s2;
	char       *addr;

	NUTS_OPEN(s1);
	NUTS_OPEN(s2);

	NUTS_ADDR(addr, "inproc");

	NUTS_PASS(nng_socket_set_ms(s2, NNG_OPT_RECONNMINT, 10));
	NUTS_PASS(nng_socket_set_ms(s2, NNG_OPT_RECONNMAXT, 10));

	NUTS_PASS(nng_dial(s2, addr, NULL, NNG_FLAG_NONBLOCK));
	NUTS_SLEEP(100);
	NUTS_PASS(nng_listen(s1, addr, NULL, 0));

	NUTS_SEND(s1, "hello");
	NUTS_RECV(s2, "hello");

	NUTS_CLOSE(s1);
	NUTS_CLOSE(s2);
}

void
test_reconnect(void)
{
	nng_socket   s1;
	nng_socket   s2;
	nng_listener l;
	char         *addr;

	NUTS_OPEN(s1);
	NUTS_OPEN(s2);

	NUTS_ADDR(addr, "inproc");

	NUTS_PASS(nng_socket_set_ms(s2, NNG_OPT_RECONNMINT, 10));
	NUTS_PASS(nng_socket_set_ms(s2, NNG_OPT_RECONNMAXT, 10));

	NUTS_PASS(nng_dial(s2, addr, NULL, NNG_FLAG_NONBLOCK));
	NUTS_SLEEP(100);
	NUTS_PASS(nng_listen(s1, addr, &l, 0));

	NUTS_SEND(s1, "hello");
	NUTS_RECV(s2, "hello");

	// Close the listener
	NUTS_PASS(nng_listener_close(l));

	// We need to wait 100 ms, or so, to allow the receiver to
	// the disconnect.
	NUTS_SLEEP(100);

	NUTS_PASS(nng_listen(s1, addr, &l, 0));
	NUTS_SEND(s1, "again");
	NUTS_RECV(s2, "again");

	NUTS_CLOSE(s1);
	NUTS_CLOSE(s2);
}

void
test_reconnect_pipe(void)
{
	nng_socket   s1;
	nng_socket   s2;
	nng_listener l;
	nng_msg *    msg;
	char *       addr;

	NUTS_OPEN(s1);
	NUTS_OPEN(s2);

	NUTS_ADDR(addr, "inproc");

	NUTS_PASS(nng_socket_set_ms(s1, NNG_OPT_RECONNMINT, 10));
	NUTS_PASS(nng_socket_set_ms(s1, NNG_OPT_RECONNMAXT, 10));

	NUTS_PASS(nng_dial(s1, addr, NULL, NNG_FLAG_NONBLOCK));
	NUTS_SLEEP(100);
	NUTS_PASS(nng_listen(s2, addr, &l, 0));

	NUTS_SEND(s2, "hello");

	NUTS_PASS(nng_recvmsg(s1, &msg, 0));
	NUTS_TRUE(msg != NULL);
	NUTS_TRUE(nng_msg_len(msg) == 6);
	NUTS_MATCH(nng_msg_body(msg), "hello");
	nng_pipe_close(nng_msg_get_pipe(msg));
	nng_msg_free(msg);

	// We have to wait a bit, because while we closed the pipe on the
	// receiver, the receiver might not have got the update.  If we
	// send too soon, then the message gets routed to the sender pipe
	// that is about to close.
	NUTS_SLEEP(100);

	// Reconnect should happen more or less immediately.
	NUTS_SEND(s2, "again");
	NUTS_RECV(s1, "again");

	NUTS_CLOSE(s1);
	NUTS_CLOSE(s2);
}

void
test_reconnect_back_off_zero(void)
{
	nng_socket s1;
	nng_socket s2;
	uint64_t   start;
	char *     addr;

	NUTS_OPEN(s1);
	NUTS_OPEN(s2);

	NUTS_ADDR(addr, "inproc");

	// redial every 10 ms.
	NUTS_PASS(nng_socket_set_ms(s1, NNG_OPT_RECONNMAXT, 0));
	NUTS_PASS(nng_socket_set_ms(s1, NNG_OPT_RECONNMINT, 10));
	NUTS_PASS(nng_dial(s1, addr, NULL, NNG_FLAG_NONBLOCK));

	// Start up the dialer first.  It should keep retrying every 10 ms.

	// Wait 500 milliseconds. This gives a chance for an exponential
	// back-off to increase to a longer time.  It should by this point
	// be well over 100 and probably closer to 200 ms.
	NUTS_SLEEP(500);

	NUTS_CLOCK(start);
	NUTS_PASS(nng_listen(s2, addr, NULL, 0));

	NUTS_SEND(s1, "hello");
	NUTS_RECV(s2, "hello");

	NUTS_BEFORE(start + 100);

	NUTS_CLOSE(s1);
	NUTS_CLOSE(s2);
}

NUTS_TESTS = {
	{ "dial before listen", test_dial_before_listen },
	{ "reconnect", test_reconnect },
	{ "reconnect back-off zero", test_reconnect_back_off_zero },
	{ "reconnect pipe", test_reconnect_pipe },
	{ NULL, NULL },
};