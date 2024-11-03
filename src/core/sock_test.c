//
// Copyright 2020 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <nuts.h>

void
test_recv_timeout(void)
{
	nng_socket s1;
	uint64_t   now;
	nng_msg   *msg = NULL;

	NUTS_OPEN(s1);
	NUTS_PASS(nng_socket_set_ms(s1, NNG_OPT_RECVTIMEO, 10));
	NUTS_CLOCK(now);
	NUTS_FAIL(nng_recvmsg(s1, &msg, 0), NNG_ETIMEDOUT);
	NUTS_TRUE(msg == NULL);
	NUTS_BEFORE(now + 500);
	NUTS_AFTER(now + 9);
	NUTS_CLOSE(s1);
}

void
test_recv_nonblock(void)
{
	nng_socket s1;
	uint64_t   now;
	nng_msg   *msg = NULL;

	NUTS_OPEN(s1);
	NUTS_PASS(nng_socket_set_ms(s1, NNG_OPT_RECVTIMEO, 10));
	NUTS_CLOCK(now);
	NUTS_FAIL(nng_recvmsg(s1, &msg, NNG_FLAG_NONBLOCK), NNG_EAGAIN);
	NUTS_TRUE(msg == NULL);
	NUTS_BEFORE(now + 500);
	NUTS_CLOSE(s1);
}

void
test_send_timeout(void)
{
	nng_socket s1;
	uint64_t   now;
	nng_msg   *msg;

	NUTS_OPEN(s1);
	NUTS_PASS(nng_msg_alloc(&msg, 0));
	NUTS_PASS(nng_socket_set_ms(s1, NNG_OPT_SENDTIMEO, 100));
	NUTS_CLOCK(now);
	NUTS_FAIL(nng_sendmsg(s1, msg, 0), NNG_ETIMEDOUT);
	NUTS_BEFORE(now + 500);
	NUTS_AFTER(now + 9);
	nng_msg_free(msg);
	NUTS_CLOSE(s1);
}

void
test_send_nonblock(void)
{
	nng_socket s1;
	uint64_t   now;
	nng_msg   *msg;

	NUTS_OPEN(s1);
	NUTS_PASS(nng_msg_alloc(&msg, 0));
	NUTS_PASS(nng_socket_set_ms(s1, NNG_OPT_SENDTIMEO, 500));
	NUTS_CLOCK(now);
	NUTS_FAIL(nng_sendmsg(s1, msg, NNG_FLAG_NONBLOCK), NNG_EAGAIN);
	NUTS_BEFORE(now + 100);
	nng_msg_free(msg);
	NUTS_CLOSE(s1);
}

void
test_socket_base(void)
{
	nng_socket s1 = NNG_SOCKET_INITIALIZER;

	NUTS_TRUE(nng_socket_id(s1) < 0);
	NUTS_PASS(nng_pair1_open(&s1));
	NUTS_TRUE(nng_socket_id(s1) > 0);

	// Cannot set bogus options
	NUTS_FAIL(nng_socket_set_bool(s1, "BAD_OPT", false), NNG_ENOTSUP);

	NUTS_CLOSE(s1);
}

void
test_socket_name(void)
{
	nng_socket s1;
	char      *str;
	long       id;
	char      *end;
	char      *name;

	NUTS_OPEN(s1);
	NUTS_PASS(nng_socket_get_string(s1, NNG_OPT_SOCKNAME, &name));
	NUTS_TRUE(strlen(name) > 0);
	NUTS_TRUE(strlen(name) < 64);
	id = strtol(name, &end, 10);
	NUTS_TRUE(id == (long) s1.id);
	NUTS_TRUE(end != NULL && *end == '\0');
	nng_strfree(name);

	NUTS_PASS(nng_socket_set_string(s1, NNG_OPT_SOCKNAME, "hello"));
	NUTS_PASS(nng_socket_get_string(s1, NNG_OPT_SOCKNAME, &name));
	NUTS_MATCH(name, "hello");
	nng_strfree(name);

	char buf[128];
	memset(buf, 'A', 128);
	buf[127] = 0;

	// strings must not be too long
	NUTS_FAIL(
	    nng_socket_set_string(s1, NNG_OPT_SOCKNAME, buf), NNG_EINVAL);

	NUTS_PASS(nng_socket_get_string(s1, NNG_OPT_SOCKNAME, &str));
	NUTS_ASSERT(str != NULL);
	NUTS_TRUE(strlen(str) == 5);
	NUTS_MATCH(str, "hello");
	nng_strfree(str);

	NUTS_CLOSE(s1);
}

void
test_socket_name_oversize(void)
{
	nng_socket s1;
	char       buf[256]; // 64 is max
	size_t     sz = sizeof(buf);
	char      *name;

	memset(buf, 'A', sz);
	NUTS_OPEN(s1);

	buf[sz - 1] = '\0';
	NUTS_FAIL(
	    nng_socket_set_string(s1, NNG_OPT_SOCKNAME, buf), NNG_EINVAL);

	strcpy(buf, "hello");
	NUTS_PASS(nng_socket_set_string(s1, NNG_OPT_SOCKNAME, buf));
	NUTS_PASS(nng_socket_get_string(s1, NNG_OPT_SOCKNAME, &name));
	NUTS_MATCH(name, "hello");
	nng_strfree(name);
	NUTS_CLOSE(s1);
}

void
test_send_recv(void)
{
	nng_socket   s1;
	nng_socket   s2;
	int          len;
	size_t       sz;
	nng_duration to = 3000; // 3 seconds
	char        *buf;
	char        *a = "inproc://t1";

	NUTS_OPEN(s1);
	NUTS_OPEN(s2);

	NUTS_PASS(nng_socket_set_int(s1, NNG_OPT_RECVBUF, 1));
	NUTS_PASS(nng_socket_get_int(s1, NNG_OPT_RECVBUF, &len));
	NUTS_TRUE(len == 1);

	NUTS_PASS(nng_socket_set_int(s1, NNG_OPT_SENDBUF, 1));
	NUTS_PASS(nng_socket_set_int(s2, NNG_OPT_SENDBUF, 1));

	NUTS_PASS(nng_socket_set_ms(s1, NNG_OPT_SENDTIMEO, to));
	NUTS_PASS(nng_socket_set_ms(s1, NNG_OPT_RECVTIMEO, to));
	NUTS_PASS(nng_socket_set_ms(s2, NNG_OPT_SENDTIMEO, to));
	NUTS_PASS(nng_socket_set_ms(s2, NNG_OPT_RECVTIMEO, to));

	NUTS_PASS(nng_listen(s1, a, NULL, 0));
	NUTS_PASS(nng_dial(s2, a, NULL, 0));

	NUTS_PASS(nng_send(s1, "abc", 4, 0));
	NUTS_PASS(nng_recv(s2, &buf, &sz, NNG_FLAG_ALLOC));
	NUTS_TRUE(buf != NULL);
	NUTS_TRUE(sz == 4);
	NUTS_TRUE(memcmp(buf, "abc", 4) == 0);
	nng_free(buf, sz);

	NUTS_CLOSE(s1);
	NUTS_CLOSE(s2);
}

void
test_send_recv_zero_length(void)
{
	nng_socket   s1;
	nng_socket   s2;
	int          len;
	size_t       sz;
	nng_duration to = 3000; // 3 seconds
	char        *buf;
	char        *a = "inproc://send-recv-zero-length";

	NUTS_OPEN(s1);
	NUTS_OPEN(s2);

	NUTS_PASS(nng_socket_set_int(s1, NNG_OPT_RECVBUF, 1));
	NUTS_PASS(nng_socket_get_int(s1, NNG_OPT_RECVBUF, &len));
	NUTS_TRUE(len == 1);

	NUTS_PASS(nng_socket_set_int(s1, NNG_OPT_SENDBUF, 1));
	NUTS_PASS(nng_socket_set_int(s2, NNG_OPT_SENDBUF, 1));

	NUTS_PASS(nng_socket_set_ms(s1, NNG_OPT_SENDTIMEO, to));
	NUTS_PASS(nng_socket_set_ms(s1, NNG_OPT_RECVTIMEO, to));
	NUTS_PASS(nng_socket_set_ms(s2, NNG_OPT_SENDTIMEO, to));
	NUTS_PASS(nng_socket_set_ms(s2, NNG_OPT_RECVTIMEO, to));

	NUTS_PASS(nng_listen(s1, a, NULL, 0));
	NUTS_PASS(nng_dial(s2, a, NULL, 0));

	NUTS_PASS(nng_send(s1, "", 0, 0));
	NUTS_PASS(nng_recv(s2, &buf, &sz, NNG_FLAG_ALLOC));
	NUTS_TRUE(buf == NULL);
	NUTS_TRUE(sz == 0);
	nng_free(buf, sz);

	NUTS_CLOSE(s1);
	NUTS_CLOSE(s2);
}

void
test_connection_refused(void)
{
	nng_socket s1;

	NUTS_OPEN(s1);
	NUTS_FAIL(nng_dial(s1, "inproc://no", NULL, 0), NNG_ECONNREFUSED);
	NUTS_CLOSE(s1);
}

void
test_late_connection(void)
{
	char      *buf;
	size_t     sz;
	nng_socket s1;
	nng_socket s2;
	char      *a = "inproc://asy";

	NUTS_OPEN(s1);
	NUTS_OPEN(s2);

	NUTS_PASS(nng_socket_set_ms(s1, NNG_OPT_RECONNMINT, 10));
	NUTS_PASS(nng_socket_set_ms(s1, NNG_OPT_RECONNMAXT, 10));

	NUTS_PASS(nng_dial(s1, a, NULL, NNG_FLAG_NONBLOCK));
	NUTS_PASS(nng_listen(s2, a, NULL, 0));
	nng_msleep(100);
	NUTS_PASS(nng_send(s1, "abc", 4, 0));
	NUTS_PASS(nng_recv(s2, &buf, &sz, NNG_FLAG_ALLOC));
	NUTS_TRUE(sz == 4);
	NUTS_TRUE(memcmp(buf, "abc", 4) == 0);
	nng_free(buf, sz);

	NUTS_CLOSE(s1);
	NUTS_CLOSE(s2);
}

void
test_address_busy(void)
{
	char        *a = "inproc://eaddrinuse";
	nng_listener l = NNG_LISTENER_INITIALIZER;
	nng_dialer   d = NNG_DIALER_INITIALIZER;
	nng_socket   s1;
	nng_socket   s2;

	NUTS_OPEN(s1);
	NUTS_OPEN(s2);

	NUTS_TRUE(nng_listener_id(l) < 0);
	NUTS_PASS(nng_listen(s1, a, &l, 0));
	NUTS_TRUE(nng_listener_id(l) > 0);

	// Cannot start another one.
	NUTS_FAIL(nng_listen(s1, a, NULL, 0), NNG_EADDRINUSE);

	// We can't restart it -- it's already running
	NUTS_FAIL(nng_listener_start(l, 0), NNG_ESTATE);

	// We can connect to it.
	NUTS_TRUE(nng_dialer_id(d) < 0);
	NUTS_PASS(nng_dial(s2, a, &d, 0));
	NUTS_TRUE(nng_dialer_id(d) > 0);

	NUTS_CLOSE(s1);
	NUTS_CLOSE(s2);
}

void
test_endpoint_types(void)
{
	nng_socket   s1;
	nng_dialer   d = NNG_DIALER_INITIALIZER;
	nng_listener l = NNG_LISTENER_INITIALIZER;
	nng_dialer   d2;
	nng_listener l2;
	char        *a = "inproc://mumble...";

	NUTS_OPEN(s1);

	NUTS_TRUE(nng_dialer_id(d) < 0);
	NUTS_PASS(nng_dialer_create(&d, s1, a));
	NUTS_TRUE(nng_dialer_id(d) > 0);

	// Forge a listener
	l2.id = nng_dialer_id(d);
	NUTS_FAIL(nng_listener_close(l2), NNG_ENOENT);
	NUTS_PASS(nng_dialer_close(d));

	NUTS_TRUE(nng_listener_id(l) < 0);
	NUTS_PASS(nng_listener_create(&l, s1, a));
	NUTS_TRUE(nng_listener_id(l) > 0);

	// Forge a dialer
	d2.id = nng_listener_id(l);
	NUTS_FAIL(nng_dialer_close(d2), NNG_ENOENT);
	NUTS_PASS(nng_listener_close(l));

	NUTS_CLOSE(s1);
}

void
test_bad_url(void)
{
	nng_socket s1;

	NUTS_OPEN(s1);
	NUTS_FAIL(nng_dial(s1, "bogus://1", NULL, 0), NNG_ENOTSUP);
	NUTS_FAIL(nng_listen(s1, "bogus://2", NULL, 0), NNG_ENOTSUP);
	NUTS_CLOSE(s1);
}

void
test_url_option(void)
{
	nng_socket   s1;
	char        *url;
	nng_listener l;
	nng_dialer   d;

	NUTS_OPEN(s1);

	// Listener
	NUTS_PASS(nng_listener_create(&l, s1, "inproc://url1"));
	NUTS_PASS(nng_listener_get_string(l, NNG_OPT_URL, &url));
	NUTS_MATCH(url, "inproc://url1");
	NUTS_FAIL(nng_listener_set_string(l, NNG_OPT_URL, url), NNG_EREADONLY);
	nng_strfree(url);

	// Dialer
	NUTS_PASS(nng_dialer_create(&d, s1, "inproc://url2"));
	NUTS_PASS(nng_dialer_get_string(d, NNG_OPT_URL, &url));
	NUTS_MATCH(url, "inproc://url2");
	NUTS_FAIL(nng_dialer_set_string(d, NNG_OPT_URL, url), NNG_EREADONLY);
	nng_strfree(url);

	NUTS_CLOSE(s1);
}

void
test_listener_options(void)
{
	nng_socket   s1;
	nng_listener l;
	size_t       sz;

	NUTS_OPEN(s1);

	NUTS_PASS(nng_listener_create(&l, s1, "inproc://listener_opts"));
	NUTS_PASS(nng_listener_set_size(l, NNG_OPT_RECVMAXSZ, 678));
	NUTS_PASS(nng_listener_get_size(l, NNG_OPT_RECVMAXSZ, &sz));
	NUTS_TRUE(sz == 678);

	// Cannot set invalid options
	NUTS_FAIL(nng_listener_set_size(l, "BAD_OPT", 1), NNG_ENOTSUP);
	NUTS_FAIL(
	    nng_listener_set_bool(l, NNG_OPT_RECVMAXSZ, true), NNG_EBADTYPE);

	// Cannot set inappropriate options
	NUTS_FAIL(
	    nng_listener_set_string(l, NNG_OPT_SOCKNAME, "1"), NNG_ENOTSUP);

	NUTS_FAIL(nng_listener_set_ms(l, NNG_OPT_RECONNMINT, 1), NNG_ENOTSUP);
	NUTS_FAIL(nng_listener_set_string(l, NNG_OPT_SOCKNAME, "bogus"),
	    NNG_ENOTSUP);

	// Read only options
	NUTS_FAIL(nng_listener_set_string(l, NNG_OPT_URL, "inproc://junk"),
	    NNG_EREADONLY);

	NUTS_CLOSE(s1);
}

void
test_dialer_options(void)
{
	nng_socket s1;
	nng_dialer d;
	size_t     sz;

	NUTS_OPEN(s1);

	NUTS_PASS(nng_dialer_create(&d, s1, "inproc://dialer_opts"));
	NUTS_PASS(nng_dialer_set_size(d, NNG_OPT_RECVMAXSZ, 678));
	NUTS_PASS(nng_dialer_get_size(d, NNG_OPT_RECVMAXSZ, &sz));
	NUTS_TRUE(sz == 678);

	// Cannot set invalid options
	NUTS_FAIL(nng_dialer_set_size(d, "BAD_OPT", 1), NNG_ENOTSUP);
	NUTS_FAIL(
	    nng_dialer_set_bool(d, NNG_OPT_RECVMAXSZ, true), NNG_EBADTYPE);

	// Cannot set inappropriate options
	NUTS_FAIL(
	    nng_dialer_set_string(d, NNG_OPT_SOCKNAME, "1"), NNG_ENOTSUP);
	NUTS_FAIL(nng_dialer_set_ms(d, NNG_OPT_SENDTIMEO, 1), NNG_ENOTSUP);
	NUTS_FAIL(
	    nng_dialer_set_string(d, NNG_OPT_SOCKNAME, "bogus"), NNG_ENOTSUP);

	// Read only options
	NUTS_FAIL(nng_dialer_set_string(d, NNG_OPT_URL, "inproc://junk"),
	    NNG_EREADONLY);

	NUTS_CLOSE(s1);
}

void
test_endpoint_absent_options(void)
{
	size_t       s;
	nng_duration t;
	nng_dialer   d;
	nng_listener l;
	d.id = 1999;
	l.id = 1999;

	NUTS_FAIL(nng_dialer_set_size(d, NNG_OPT_RECVMAXSZ, 10), NNG_ENOENT);
	NUTS_FAIL(nng_listener_set_size(l, NNG_OPT_RECVMAXSZ, 10), NNG_ENOENT);

	NUTS_FAIL(nng_dialer_get_size(d, NNG_OPT_RECVMAXSZ, &s), NNG_ENOENT);
	NUTS_FAIL(nng_listener_get_size(l, NNG_OPT_RECVMAXSZ, &s), NNG_ENOENT);

	NUTS_FAIL(nng_dialer_get_ms(d, NNG_OPT_RECVTIMEO, &t), NNG_ENOENT);
	NUTS_FAIL(nng_listener_get_ms(l, NNG_OPT_SENDTIMEO, &t), NNG_ENOENT);
}

void
test_timeout_options(void)
{
	nng_socket   s1;
	nng_duration to;

	char *cases[] = {
		NNG_OPT_RECVTIMEO,
		NNG_OPT_SENDTIMEO,
		NNG_OPT_RECONNMAXT,
		NNG_OPT_RECONNMINT,
		NULL,
	};

	NUTS_OPEN(s1);
	for (int i = 0; cases[i] != NULL; i++) {
		bool b;
		TEST_CASE(cases[i]);

		// Type mismatches
		NUTS_FAIL(nng_socket_get_bool(s1, cases[i], &b), NNG_EBADTYPE);

		// Can set a valid duration
		NUTS_PASS(nng_socket_set_ms(s1, cases[i], 1234));
		NUTS_PASS(nng_socket_get_ms(s1, cases[i], &to));
		NUTS_TRUE(to == 1234);

		// Can't set a negative duration
		NUTS_FAIL(nng_socket_set_ms(s1, cases[i], -5), NNG_EINVAL);
	}
	NUTS_CLOSE(s1);
}

void
test_size_options(void)
{
	nng_socket s1;
	size_t     val;
	char      *opt;

	char *cases[] = {
		NNG_OPT_RECVMAXSZ,
		NULL,
	};

	NUTS_OPEN(s1);
	for (int i = 0; (opt = cases[i]) != NULL; i++) {
		TEST_CASE(opt);

		// Can set a valid duration
		NUTS_PASS(nng_socket_set_size(s1, opt, 1234));
		NUTS_PASS(nng_socket_get_size(s1, opt, &val));
		NUTS_TRUE(val == 1234);

		// We limit the limit to 4GB. Clear it if you want to
		// ship more than 4GB at a time.
#if defined(_WIN64) || defined(_LP64)
		val = 0x10000u;
		val <<= 30u;
		NUTS_FAIL(nng_socket_set_size(s1, opt, val), NNG_EINVAL);
		NUTS_PASS(nng_socket_get_size(s1, opt, &val));
		NUTS_TRUE(val == 1234);
#endif
	}
	NUTS_CLOSE(s1);
}

NUTS_TESTS = {
	{ "recv timeout", test_recv_timeout },
	{ "recv non-block", test_recv_nonblock },
	{ "send timeout", test_send_timeout },
	{ "send non-block", test_send_nonblock },
	{ "socket base", test_socket_base },
	{ "socket name", test_socket_name },
	{ "socket name oversize", test_socket_name_oversize },
	{ "send recv", test_send_recv },
	{ "send recv zero length", test_send_recv_zero_length },
	{ "connection refused", test_connection_refused },
	{ "late connection", test_late_connection },
	{ "address busy", test_address_busy },
	{ "bad url", test_bad_url },
	{ "url option", test_url_option },
	{ "listener options", test_listener_options },
	{ "dialer options", test_dialer_options },
	{ "timeout options", test_timeout_options },
	{ "size options", test_size_options },
	{ "endpoint absent options", test_endpoint_absent_options },
	{ "endpoint types", test_endpoint_types },

	{ NULL, NULL },
};
