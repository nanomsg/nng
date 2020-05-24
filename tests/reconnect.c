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

#include <nng/nng.h>
#include <nng/protocol/pipeline0/pull.h>
#include <nng/protocol/pipeline0/push.h>
#include <nng/supplemental/util/platform.h>

#include "acutest.h"
#include "testutil.h"

void
test_dial_before_listen(void)
{
	nng_socket push;
	nng_socket pull;
	char       addr[64];

	testutil_scratch_addr("inproc", sizeof(addr), addr);

	TEST_NNG_PASS(nng_push0_open(&push));
	TEST_NNG_PASS(nng_pull0_open(&pull));

	TEST_NNG_PASS(nng_setopt_ms(pull, NNG_OPT_RECONNMINT, 10));
	TEST_NNG_PASS(nng_setopt_ms(pull, NNG_OPT_RECONNMAXT, 10));

	TEST_NNG_PASS(nng_dial(pull, addr, NULL, NNG_FLAG_NONBLOCK));
	testutil_sleep(100);
	TEST_NNG_PASS(nng_listen(push, addr, NULL, 0));

	TEST_NNG_SEND_STR(push, "hello");
	TEST_NNG_RECV_STR(pull, "hello");

	TEST_NNG_PASS(nng_close(push));
	TEST_NNG_PASS(nng_close(pull));
}

void
test_reconnect(void)
{
	nng_socket   push;
	nng_socket   pull;
	nng_listener l;
	char         addr[64];

	testutil_scratch_addr("inproc", sizeof(addr), addr);

	TEST_NNG_PASS(nng_push0_open(&push));
	TEST_NNG_PASS(nng_pull0_open(&pull));

	TEST_NNG_PASS(nng_setopt_ms(pull, NNG_OPT_RECONNMINT, 10));
	TEST_NNG_PASS(nng_setopt_ms(pull, NNG_OPT_RECONNMAXT, 10));

	TEST_NNG_PASS(nng_dial(pull, addr, NULL, NNG_FLAG_NONBLOCK));
	testutil_sleep(100);
	TEST_NNG_PASS(nng_listen(push, addr, &l, 0));

	TEST_NNG_SEND_STR(push, "hello");
	TEST_NNG_RECV_STR(pull, "hello");

	// Close the listener
	TEST_NNG_PASS(nng_listener_close(l));

	TEST_NNG_PASS(nng_listen(push, addr, &l, 0));
	TEST_NNG_SEND_STR(push, "again");
	TEST_NNG_RECV_STR(pull, "again");

	TEST_NNG_PASS(nng_close(push));
	TEST_NNG_PASS(nng_close(pull));
}

void
test_reconnect_pipe(void)
{
	nng_socket   push;
	nng_socket   pull;
	nng_listener l;
	nng_msg *    msg;
	char         addr[64];

	testutil_scratch_addr("inproc", sizeof(addr), addr);

	TEST_NNG_PASS(nng_push0_open(&push));
	TEST_NNG_PASS(nng_pull0_open(&pull));

	TEST_NNG_PASS(nng_setopt_ms(pull, NNG_OPT_RECONNMINT, 10));
	TEST_NNG_PASS(nng_setopt_ms(pull, NNG_OPT_RECONNMAXT, 10));

	TEST_NNG_PASS(nng_dial(pull, addr, NULL, NNG_FLAG_NONBLOCK));
	testutil_sleep(100);
	TEST_NNG_PASS(nng_listen(push, addr, &l, 0));

	TEST_NNG_SEND_STR(push, "hello");

	TEST_NNG_PASS(nng_recvmsg(pull, &msg, 0));
	TEST_CHECK(msg != NULL);
	TEST_CHECK(nng_msg_len(msg) == 6);
	TEST_CHECK(strcmp(nng_msg_body(msg), "hello") == 0);
	nng_pipe_close(nng_msg_get_pipe(msg));
	nng_msg_free(msg);

	// We have to wait a bit, because while we closed the pipe on the
	// receiver, the receiver might not have got the update.  If we
	// send too soon, then the message gets routed to the sender pipe
	// that is about to close.
	testutil_sleep(100);

	// Reconnect should happen more ore less immediately.
	TEST_NNG_SEND_STR(push, "again");
	TEST_NNG_RECV_STR(pull, "again");

	TEST_NNG_PASS(nng_close(push));
	TEST_NNG_PASS(nng_close(pull));
}

void
test_reconnect_back_off_zero(void)
{
	nng_socket push;
	nng_socket pull;
	nng_time   start;
	char       addr[64];
	testutil_scratch_addr("inproc", sizeof(addr), addr);

	TEST_NNG_PASS(nng_push0_open(&push));
	TEST_NNG_PASS(nng_pull0_open(&pull));

	// redial every 10 ms.
	TEST_NNG_PASS(nng_setopt_ms(push, NNG_OPT_RECONNMAXT, 0));
	TEST_NNG_PASS(nng_setopt_ms(push, NNG_OPT_RECONNMINT, 10));
	TEST_NNG_PASS(nng_dial(push, addr, NULL, NNG_FLAG_NONBLOCK));

	// Start up the dialer first.  It should keep retrying every 10 ms.

	// Wait 500 milliseconds. This gives a chance for an exponential
	// back-off to increase to a longer time.  It should by this point
	// be well over 100 and probably closer to 200 ms.
	nng_msleep(500);

	start = nng_clock();
	TEST_NNG_PASS(nng_listen(pull, addr, NULL, 0));

	TEST_NNG_SEND_STR(push, "hello");
	TEST_NNG_RECV_STR(pull, "hello");

	TEST_CHECK(nng_clock() - start < 100);

	TEST_NNG_PASS(nng_close(push));
	TEST_NNG_PASS(nng_close(pull));
}

TEST_LIST = {
	{ "dial before listen", test_dial_before_listen },
	{ "reconnect", test_reconnect },
	{ "reconnect back-off zero", test_reconnect_back_off_zero },
	{ "reconnect pipe", test_reconnect_pipe },
	{ NULL, NULL },
};