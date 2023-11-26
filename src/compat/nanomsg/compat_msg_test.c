//
// Copyright 2023 Staysail Systems, Inc. <info@staysail.tech>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <nng/compat/nanomsg/nn.h>
#include <nng/compat/nanomsg/pair.h>
#include <nng/compat/nanomsg/tcp.h>

#include "nuts_compat.h"

#include <nuts.h>

void
test_msg_alloc(void)
{
	char *msg;
	msg = nn_allocmsg(1, 0);
	NUTS_TRUE(msg != NULL);
	NUTS_NN_PASS(nn_freemsg(msg));
}

void
test_msg_zero_length(void)
{
	char *msg;
	msg = nn_allocmsg(0, 0); // empty message is invalid
	NUTS_TRUE(msg == NULL);
	NUTS_TRUE(nn_errno() == EINVAL);
}

void
test_msg_overflow(void)
{
	char *msg;
	msg = nn_allocmsg((size_t)-1, 0); // this will overflow
	NUTS_TRUE(msg == NULL);
	NUTS_TRUE(nn_errno() == EINVAL);
}

void
test_msg_bad_type(void)
{
	char *msg;
	msg = nn_allocmsg(0, 1); // we only support message type 0
	NUTS_TRUE(msg == NULL);
	NUTS_TRUE(nn_errno() == EINVAL);
}

void
test_msg_realloc(void)
{
	char *msg0;
	char *msg1;
	char *msg2;
	char *msg3;

	msg0 = nn_allocmsg(5, 0);
	NUTS_TRUE(msg0 != NULL);

	memcpy(msg0, "this", 5);

	msg1 = nn_reallocmsg(msg0, 65536);
	NUTS_TRUE(msg1 != NULL);
	NUTS_TRUE(msg1 != msg0);
	NUTS_MATCH(msg1, "this");

	msg1[65000] = 'A';

	msg2 = nn_reallocmsg(msg1, 5);
	NUTS_TRUE(msg2 == msg1);

	// test for overflow
	msg3 = nn_reallocmsg(msg2, (size_t)-1);
	NUTS_TRUE(msg3 == NULL);
	NUTS_TRUE(nn_errno() == EINVAL);

	nn_freemsg(msg2);
}

TEST_LIST = {
	{ "alloc msg", test_msg_alloc },
	{ "zero length", test_msg_zero_length },
	{ "invalid type", test_msg_bad_type },
	{ "overflow", test_msg_overflow },
	{ "reallocate msg", test_msg_realloc },
	{ NULL, NULL },
};
