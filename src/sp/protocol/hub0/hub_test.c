//
// Copyright 2022 Cogent Embedded, Inc.
// Copyright 2021 Staysail Systems, Inc. <info@staysail.tech>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <nuts.h>

#include <nng/protocol/hub0/hub.h>

#define SECOND 1000

void
test_hub_identity(void)
{
	nng_socket s;
	int        p;
	char      *n;

	NUTS_PASS(nng_hub_open(&s));
	NUTS_PASS(nng_socket_get_int(s, NNG_OPT_PROTO, &p));
	NUTS_TRUE(p == NNG_HUB0_SELF);
	NUTS_PASS(nng_socket_get_int(s, NNG_OPT_PEER, &p));
	NUTS_TRUE(p == NNG_HUB0_PEER);
	NUTS_PASS(nng_socket_get_string(s, NNG_OPT_PROTONAME, &n));
	NUTS_MATCH(n, NNG_HUB0_SELF_NAME);
	nng_strfree(n);
	NUTS_PASS(nng_socket_get_string(s, NNG_OPT_PEERNAME, &n));
	NUTS_MATCH(n, NNG_HUB0_PEER_NAME);
	nng_strfree(n);
	NUTS_CLOSE(s);
}

static void
test_hub_star(void)
{
	nng_socket s1, s2, s3;

	NUTS_PASS(nng_hub_open(&s1));
	NUTS_PASS(nng_hub_open(&s2));
	NUTS_PASS(nng_hub_open(&s3));

	NUTS_PASS(nng_socket_set_ms(s1, NNG_OPT_RECVTIMEO, SECOND));
	NUTS_PASS(nng_socket_set_ms(s2, NNG_OPT_RECVTIMEO, SECOND));
	NUTS_PASS(nng_socket_set_ms(s3, NNG_OPT_RECVTIMEO, SECOND));

	NUTS_MARRY(s1, s2);
	NUTS_MARRY(s1, s3);

	NUTS_SEND(s1, "one");
	NUTS_RECV(s2, "one");
	NUTS_RECV(s3, "one");

	NUTS_SEND(s2, "two");
	NUTS_SEND(s1, "one");
	NUTS_RECV(s1, "two");
	NUTS_RECV(s2, "one");
	NUTS_RECV(s3, "one");

	NUTS_CLOSE(s1);
	NUTS_CLOSE(s2);
	NUTS_CLOSE(s3);
}

static void
test_hub_compatible_pair(void)
{
	nng_socket s1, s2;
	char      *addr;

	NUTS_ADDR(addr, "inproc");
	NUTS_PASS(nng_hub_open(&s1));
	NUTS_PASS(nng_pair0_open(&s2));

	NUTS_PASS(nng_listen(s1, addr, NULL, 0));
	NUTS_PASS(nng_dial(s2, addr, NULL, NNG_FLAG_NONBLOCK));

	NUTS_MARRY(s2, s1);

	NUTS_CLOSE(s1);
	NUTS_CLOSE(s2);
}

static void
test_hub_no_context(void)
{
	nng_socket s;
	nng_ctx    ctx;

	NUTS_PASS(nng_hub_open(&s));
	NUTS_FAIL(nng_ctx_open(&ctx, s), NNG_ENOTSUP);
	NUTS_CLOSE(s);
}

static void
test_hub_recv_cancel(void)
{
	nng_socket s1;
	nng_aio   *aio;

	NUTS_PASS(nng_hub_open(&s1));
	NUTS_PASS(nng_aio_alloc(&aio, NULL, NULL));

	nng_aio_set_timeout(aio, SECOND);
	nng_recv_aio(s1, aio);
	nng_aio_abort(aio, NNG_ECANCELED);

	nng_aio_wait(aio);
	NUTS_FAIL(nng_aio_result(aio), NNG_ECANCELED);
	NUTS_CLOSE(s1);
	nng_aio_free(aio);
}

static void
test_hub_close_recv_abort(void)
{
	nng_socket s1;
	nng_aio   *aio;

	NUTS_PASS(nng_hub_open(&s1));
	NUTS_PASS(nng_aio_alloc(&aio, NULL, NULL));

	nng_aio_set_timeout(aio, SECOND);
	nng_recv_aio(s1, aio);
	NUTS_CLOSE(s1);

	nng_aio_wait(aio);
	NUTS_FAIL(nng_aio_result(aio), NNG_ECLOSED);
	nng_aio_free(aio);
}

static void
test_hub_aio_stopped(void)
{
	nng_socket s1;
	nng_aio   *aio;
	nng_msg   *msg;

	NUTS_PASS(nng_hub_open(&s1));
	NUTS_PASS(nng_msg_alloc(&msg, 0));
	NUTS_PASS(nng_aio_alloc(&aio, NULL, NULL));
	nng_aio_stop(aio);

	nng_recv_aio(s1, aio);
	nng_aio_wait(aio);
	NUTS_FAIL(nng_aio_result(aio), NNG_ECANCELED);

	nng_aio_set_msg(aio, msg);
	nng_send_aio(s1, aio);
	nng_aio_wait(aio);
	NUTS_FAIL(nng_aio_result(aio), NNG_ECANCELED);

	nng_aio_free(aio);
	nng_msg_free(msg);
	NUTS_CLOSE(s1);
}

static void
test_hub_send_no_pipes(void)
{
	nng_socket s1;

	NUTS_PASS(nng_hub_open(&s1));
	NUTS_SEND(s1, "DROP1");
	NUTS_SEND(s1, "DROP2");
	NUTS_CLOSE(s1);
}

static void
test_hub_poll_readable(void)
{
	int        fd;
	nng_socket s1, s2;

	NUTS_PASS(nng_hub_open(&s1));
	NUTS_PASS(nng_hub_open(&s2));
	NUTS_PASS(nng_socket_set_ms(s1, NNG_OPT_RECVTIMEO, 1000));
	NUTS_PASS(nng_socket_set_ms(s2, NNG_OPT_SENDTIMEO, 1000));
	NUTS_PASS(nng_socket_get_int(s1, NNG_OPT_RECVFD, &fd));
	NUTS_TRUE(fd >= 0);

	// Not readable if not connected!
	NUTS_TRUE(nuts_poll_fd(fd) == false);

	// Even after connect (no message yet)
	NUTS_MARRY(s2, s1);
	NUTS_TRUE(nuts_poll_fd(fd) == false);

	// But once we send messages, it is.
	// We have to send a request, in order to send a reply.
	NUTS_SEND(s2, "abc");
	NUTS_SLEEP(100);
	NUTS_TRUE(nuts_poll_fd(fd));

	// and receiving makes it no longer ready
	NUTS_RECV(s1, "abc");
	NUTS_TRUE(nuts_poll_fd(fd) == false);

	NUTS_CLOSE(s2);
	NUTS_CLOSE(s1);
}

static void
test_hub_poll_writable(void)
{
  int        fd;
  nng_socket s1, s2;

  NUTS_PASS(nng_hub_open(&s1));
  NUTS_PASS(nng_hub_open(&s2));
  NUTS_PASS(nng_socket_set_ms(s1, NNG_OPT_RECVTIMEO, 1000));
  NUTS_PASS(nng_socket_set_ms(s2, NNG_OPT_SENDTIMEO, 1000));
  NUTS_PASS(nng_socket_set_int(s1, NNG_OPT_SENDBUF, 1));
  NUTS_PASS(nng_socket_set_int(s2, NNG_OPT_RECVBUF, 1));
  NUTS_PASS(nng_socket_get_int(s1, NNG_OPT_SENDFD, &fd));
  NUTS_TRUE(fd >= 0);

  // Not writable if not connected!
  NUTS_TRUE(nuts_poll_fd(fd) == false);

  NUTS_MARRY(s2, s1);
  NUTS_TRUE(nuts_poll_fd(fd));

  NUTS_SEND(s1, "001"); // first one in the receiver queue
  NUTS_SEND(s1, "002"); // second one in the receiver
  NUTS_SEND(s1, "003");
  NUTS_SEND(s1, "004");
  NUTS_TRUE(nuts_poll_fd(fd) == false);

  // and receiving makes it ready
  NUTS_RECV(s2, "001");
  NUTS_SLEEP(100); // time for the sender to complete
  NUTS_TRUE(nuts_poll_fd(fd));

  NUTS_CLOSE(s2);
  NUTS_CLOSE(s1);
}

static void
test_hub_recv_buf_option(void)
{
	nng_socket  s;
	int         v;
	bool        b;
	size_t      sz;
	const char *opt = NNG_OPT_RECVBUF;

	NUTS_PASS(nng_hub_open(&s));

	NUTS_PASS(nng_socket_set_int(s, opt, 1));
	NUTS_FAIL(nng_socket_set_int(s, opt, 0), NNG_EINVAL);
	NUTS_FAIL(nng_socket_set_int(s, opt, -1), NNG_EINVAL);
	NUTS_FAIL(nng_socket_set_int(s, opt, 1000000), NNG_EINVAL);
	NUTS_PASS(nng_socket_set_int(s, opt, 3));
	NUTS_PASS(nng_socket_get_int(s, opt, &v));
	NUTS_TRUE(v == 3);
	v  = 0;
	sz = sizeof(v);
	NUTS_PASS(nng_socket_get(s, opt, &v, &sz));
	NUTS_TRUE(v == 3);
	NUTS_TRUE(sz == sizeof(v));

	NUTS_FAIL(nng_socket_set(s, opt, "", 1), NNG_EINVAL);
	sz = 1;
	NUTS_FAIL(nng_socket_get(s, opt, &v, &sz), NNG_EINVAL);
	NUTS_FAIL(nng_socket_set_bool(s, opt, true), NNG_EBADTYPE);
	NUTS_FAIL(nng_socket_get_bool(s, opt, &b), NNG_EBADTYPE);

	NUTS_CLOSE(s);
}

static void
test_hub_send_buf_option(void)
{
	nng_socket  s1;
	nng_socket  s2;
	int         v;
	bool        b;
	size_t      sz;
	const char *opt = NNG_OPT_SENDBUF;

	NUTS_PASS(nng_hub_open(&s1));
	NUTS_PASS(nng_hub_open(&s2));
	NUTS_MARRY(s1, s2);

	NUTS_PASS(nng_socket_set_int(s1, opt, 1));
	NUTS_FAIL(nng_socket_set_int(s1, opt, 0), NNG_EINVAL);
	NUTS_FAIL(nng_socket_set_int(s1, opt, -1), NNG_EINVAL);
	NUTS_FAIL(nng_socket_set_int(s1, opt, 1000000), NNG_EINVAL);
	NUTS_PASS(nng_socket_set_int(s1, opt, 3));
	NUTS_PASS(nng_socket_get_int(s1, opt, &v));
	NUTS_TRUE(v == 3);
	v  = 0;
	sz = sizeof(v);
	NUTS_PASS(nng_socket_get(s1, opt, &v, &sz));
	NUTS_TRUE(v == 3);
	NUTS_TRUE(sz == sizeof(v));

	NUTS_FAIL(nng_socket_set(s1, opt, "", 1), NNG_EINVAL);
	sz = 1;
	NUTS_FAIL(nng_socket_get(s1, opt, &v, &sz), NNG_EINVAL);
	NUTS_FAIL(nng_socket_set_bool(s1, opt, true), NNG_EBADTYPE);
	NUTS_FAIL(nng_socket_get_bool(s1, opt, &b), NNG_EBADTYPE);

	NUTS_CLOSE(s1);
	NUTS_CLOSE(s2);
}

#define SENDS 10

static void
test_hub_tx_drop(void)
{
	nng_socket   hub1, hub2;
	nng_aio    **aio_array;
	const char   text[] = "abc";


	NUTS_PASS(nng_hub_open(&hub1));
	NUTS_PASS(nng_hub_open(&hub2));

	NUTS_PASS(nng_socket_set_int(hub1, NNG_OPT_SENDBUF, 1));

	NUTS_PASS(nng_socket_set_int(hub2, NNG_OPT_RECVBUF, SENDS + 1));
	NUTS_PASS(nng_socket_set_ms(hub2, NNG_OPT_RECVTIMEO, 10000));

	NUTS_MARRY(hub1, hub2);

	aio_array = calloc(SENDS, sizeof(*aio_array));

	for(unsigned i = 0u; i < SENDS; i++) {
		nng_msg *msg;
		void* buf;

		NUTS_PASS(nng_aio_alloc(&aio_array[i], NULL, NULL));
		NUTS_PASS(nng_msg_alloc(&msg, sizeof(text)));
		buf = nng_msg_body(msg);
		memcpy(buf, text, sizeof(text));
		nng_aio_set_msg(aio_array[i], msg);
	}

	for(unsigned i = 0u; i < SENDS; i++) {
		nng_send_aio(hub1, aio_array[i]);
	}

	for(unsigned i = 0u; i < SENDS; i++) {
		NUTS_RECV(hub2, text);
	}

	for(unsigned i = 0u; i < SENDS; i++) {
		nng_aio_wait(aio_array[i]);
		nng_aio_stop(aio_array[i]);
		nng_aio_free(aio_array[i]);
	}

	NUTS_CLOSE(hub1);
	NUTS_CLOSE(hub2);
	free(aio_array);
}


static void
test_hub_rx_drop(void)
{
	nng_socket   hub1, hub2;
	nng_aio    **aio_array;
	const char   text[] = "abc";

	NUTS_PASS(nng_hub_open(&hub1));
	NUTS_PASS(nng_hub_open(&hub2));

	NUTS_PASS(nng_socket_set_int(hub1, NNG_OPT_SENDBUF, SENDS + 1));

	NUTS_PASS(nng_socket_set_int(hub2, NNG_OPT_RECVBUF, 1));
	NUTS_PASS(nng_socket_set_ms(hub2, NNG_OPT_RECVTIMEO, 10000));

	NUTS_MARRY(hub1, hub2);

	aio_array = calloc(SENDS, sizeof(*aio_array));

	for(unsigned i = 0u; i < SENDS; i++) {
		nng_msg *msg;
		void* buf;

		NUTS_PASS(nng_aio_alloc(&aio_array[i], NULL, NULL));
		NUTS_PASS(nng_msg_alloc(&msg, sizeof(text)));
		buf = nng_msg_body(msg);
		memcpy(buf, text, sizeof(text));
		nng_aio_set_msg(aio_array[i], msg);
	}

	for(unsigned i = 0u; i < SENDS; i++) {
		nng_send_aio(hub1, aio_array[i]);
	}

	NUTS_SLEEP(100);

	for(unsigned i = 0u; i < SENDS; i++) {
		NUTS_RECV(hub2, text);
	}

	for(unsigned i = 0u; i < SENDS; i++) {
		nng_aio_wait(aio_array[i]);
		nng_aio_stop(aio_array[i]);
		nng_aio_free(aio_array[i]);
	}

	NUTS_CLOSE(hub1);
	NUTS_CLOSE(hub2);
	free(aio_array);
}


static void
test_hub_restart(void)
{
	nng_socket   hub1, hub2;
	const char   text[] = "abc";

	for (int i = 0; i < 1000; i++) {
		NUTS_PASS(nng_hub_open(&hub1));
		NUTS_PASS(nng_hub_open(&hub2));

		NUTS_MARRY(hub1, hub2);

		for(unsigned i = 0u; i < SENDS; i++) {
			NUTS_SEND(hub1, text);
			NUTS_RECV(hub2, text);
		}

		NUTS_CLOSE(hub1);
		NUTS_CLOSE(hub2);
	}
}

TEST_LIST = {
	{ "hub identity", test_hub_identity },
	{ "hub star", test_hub_star },
	{ "hub compatible pair", test_hub_compatible_pair },
	{ "hub no context", test_hub_no_context },
	{ "hub poll read", test_hub_poll_readable },
	{ "hub poll write", test_hub_poll_writable },
	{ "hub send no pipes", test_hub_send_no_pipes },
	{ "hub recv cancel", test_hub_recv_cancel },
	{ "hub close recv abort", test_hub_close_recv_abort },
	{ "hub aio stopped", test_hub_aio_stopped },
	{ "hub recv buf option", test_hub_recv_buf_option },
	{ "hub send buf option", test_hub_send_buf_option },
	{ "hub tx drop", test_hub_tx_drop },
	{ "hub rx drop", test_hub_rx_drop },
	{ "hub restart", test_hub_restart },
	{ NULL, NULL },
};
