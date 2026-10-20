// Copyright 2026 Staysail Systems, Inc. <info@staysail.tech>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "../../../core/nng_impl.h"
#include "../../../core/sockimpl.h"
#include "../../../testing/nuts.h"

#define ADMISSION_TIMEOUT 5000
#define HELLO_SIZE 16384

extern nni_pipe *nni_dtls_test_pending_pipe(void *);

static nng_tls_config *
admission_config(nng_tls_mode mode, nng_tls_version version)
{
	nng_tls_config *cfg;
	NUTS_PASS(nng_tls_config_alloc(&cfg, mode));
	NUTS_PASS(nng_tls_config_version(cfg, version, version));
	if (mode == NNG_TLS_MODE_SERVER) {
		NUTS_PASS(nng_tls_config_own_cert(
		    cfg, nuts_server_crt, nuts_server_key, NULL));
	} else {
		NUTS_PASS(nng_tls_config_ca_chain(cfg, nuts_server_crt, NULL));
		NUTS_PASS(nng_tls_config_server_name(cfg, "localhost"));
	}
	return (cfg);
}

static nng_udp *
admission_udp(void)
{
	nng_sockaddr bind = { .s_in = {
		                  .sa_family = NNG_AF_INET,
		                  .sa_port   = 0,
		                  .sa_addr   = nuts_be32(0x7f000001),
		              } };
	nng_udp     *udp;
	NUTS_PASS(nng_udp_open(&udp, &bind));
	return (udp);
}

static void
admission_send(nng_udp *udp, const nng_sockaddr *to, void *buf, size_t len)
{
	nng_aio *aio;
	nng_iov  iov = { .iov_buf = buf, .iov_len = len };
	NUTS_PASS(nng_aio_alloc(&aio, NULL, NULL));
	nng_aio_set_timeout(aio, ADMISSION_TIMEOUT);
	NUTS_PASS(nng_aio_set_iov(aio, 1, &iov));
	NUTS_PASS(nng_aio_set_input(aio, 0, (void *) to));
	nng_udp_send(udp, aio);
	nng_aio_wait(aio);
	NUTS_PASS(nng_aio_result(aio));
	nng_aio_free(aio);
}

static nng_err
admission_recv(nng_udp *udp, nng_sockaddr *from, void *buf, size_t *len,
    nng_duration timeout)
{
	nng_aio *aio;
	nng_iov  iov = { .iov_buf = buf, .iov_len = *len };
	NUTS_PASS(nng_aio_alloc(&aio, NULL, NULL));
	nng_aio_set_timeout(aio, timeout);
	NUTS_PASS(nng_aio_set_iov(aio, 1, &iov));
	NUTS_PASS(nng_aio_set_input(aio, 0, from));
	nng_udp_recv(udp, aio);
	nng_aio_wait(aio);
	nng_err rv = nng_aio_result(aio);
	*len       = nng_aio_count(aio);
	nng_aio_free(aio);
	return (rv);
}

static nng_listener
admission_listen(nng_socket *sock, nng_tls_version version, size_t max,
    size_t rate, nng_duration expire, nng_sockaddr *addr)
{
	nng_listener    l;
	const nng_url  *url;
	nng_tls_config *cfg = admission_config(NNG_TLS_MODE_SERVER, version);
	NUTS_OPEN(*sock);
	NUTS_PASS(
	    nng_socket_set_ms(*sock, NNG_OPT_SENDTIMEO, ADMISSION_TIMEOUT));
	NUTS_PASS(
	    nng_socket_set_ms(*sock, NNG_OPT_RECVTIMEO, ADMISSION_TIMEOUT));
	NUTS_PASS(nng_listener_create(&l, *sock, "dtls4://127.0.0.1:0"));
	NUTS_PASS(nng_listener_set_tls(l, cfg));
	nng_tls_config_free(cfg);
	NUTS_PASS(nng_listener_set_size(l, NNG_OPT_UDP_MAX_PEERS, max));
	NUTS_PASS(nng_listener_set_size(l, NNG_OPT_DTLS_CONN_RATE, rate));
	NUTS_PASS(nng_listener_set_ms(l, NNG_OPT_UDP_CONN_EXPIRE, expire));
	NUTS_PASS(nng_listener_start(l, 0));
	NUTS_PASS(nng_listener_get_url(l, &url));
	memset(addr, 0, sizeof(*addr));
	addr->s_in.sa_family = NNG_AF_INET;
	addr->s_in.sa_addr   = nuts_be32(0x7f000001);
	addr->s_in.sa_port   = nuts_be16((uint16_t) nng_url_port(url));
	return (l);
}

static nng_socket
admission_dial(nng_udp *proxy, nng_tls_version version, uint8_t *hello,
    size_t *len, nng_sockaddr *client_addr)
{
	nng_socket      client;
	nng_sockaddr    addr;
	nng_dialer      d;
	char            url[80];
	nng_tls_config *cfg = admission_config(NNG_TLS_MODE_CLIENT, version);
	NUTS_PASS(nng_udp_sockname(proxy, &addr));
	snprintf(url, sizeof(url), "dtls4://127.0.0.1:%u",
	    (unsigned) nuts_be16(addr.s_in.sa_port));
	NUTS_OPEN(client);
	NUTS_PASS(
	    nng_socket_set_ms(client, NNG_OPT_SENDTIMEO, ADMISSION_TIMEOUT));
	NUTS_PASS(
	    nng_socket_set_ms(client, NNG_OPT_RECVTIMEO, ADMISSION_TIMEOUT));
	NUTS_PASS(nng_dialer_create(&d, client, url));
	NUTS_PASS(nng_dialer_set_tls(d, cfg));
	nng_tls_config_free(cfg);
	NUTS_PASS(nng_dialer_start(d, NNG_FLAG_NONBLOCK));
	NUTS_PASS(
	    admission_recv(proxy, client_addr, hello, len, ADMISSION_TIMEOUT));
	NUTS_ASSERT(*len > 25 && hello[0] == 22 && hello[13] == 1);
	return (client);
}

// Recognize a real cookie challenge, not a full ServerHello/certificate
// flight.
static bool
admission_challenge(const uint8_t *buf, size_t len, nng_tls_version version)
{
	static const uint8_t hrr_random[32] = {
		0xcf,
		0x21,
		0xad,
		0x74,
		0xe5,
		0x9a,
		0x61,
		0x11,
		0xbe,
		0x1d,
		0x8c,
		0x02,
		0x1e,
		0x65,
		0xb8,
		0x91,
		0xc2,
		0xa2,
		0x11,
		0x16,
		0x7a,
		0xbb,
		0x8c,
		0x5e,
		0x07,
		0x9e,
		0x09,
		0xe2,
		0xc8,
		0xa8,
		0x33,
		0x9c,
	};
	if (len < 28 || buf[0] != 22) {
		return (false);
	}
	if (version == NNG_TLS_1_2) {
		return (buf[13] == 3 && buf[27] != 0 &&
		    (size_t) buf[27] <= len - 28);
	}
	if (len < 65 || buf[13] != 2 ||
	    memcmp(buf + 27, hrr_random, sizeof(hrr_random)) != 0) {
		return (false);
	}
	size_t pos = 60 + buf[59] + 3; // session ID, cipher, compression
	if (pos > len - 2) {
		return (false);
	}
	uint16_t extlen;
	NNI_GET16(buf + pos, extlen);
	pos += 2;
	if (extlen > len - pos) {
		return (false);
	}
	size_t end = pos + extlen;
	while (end - pos >= 4) {
		uint16_t type, size;
		NNI_GET16(buf + pos, type);
		NNI_GET16(buf + pos + 2, size);
		pos += 4;
		if (size > end - pos) {
			return (false);
		}
		if (type == 44) {
			return (
			    size > 2); // cookie extension with nonempty cookie
		}
		pos += size;
	}
	return (false);
}

static void
admission_cookie(nng_tls_version version)
{
	nng_socket   server, client;
	nng_sockaddr server_addr, client_addr, from;
	nng_udp     *first    = admission_udp();
	nng_udp     *second   = admission_udp();
	uint8_t     *hello    = nng_alloc(HELLO_SIZE);
	uint8_t     *response = nng_alloc(HELLO_SIZE);
	NUTS_ASSERT(hello != NULL && response != NULL);
	size_t len = HELLO_SIZE;
	client     = admission_dial(first, version, hello, &len, &client_addr);
	admission_listen(
	    &server, version, 4, 0, ADMISSION_TIMEOUT, &server_addr);
	admission_send(first, &server_addr, hello, len);
	size_t reply_len = HELLO_SIZE;
	NUTS_PASS(admission_recv(
	    first, &from, response, &reply_len, ADMISSION_TIMEOUT));
	NUTS_ASSERT(admission_challenge(response, reply_len, version));
	NUTS_TRUE(reply_len <= len);
	// Return the challenge to the genuine client to obtain its cookie
	// reply.
	admission_send(first, &client_addr, response, reply_len);
	len = HELLO_SIZE;
	NUTS_PASS(
	    admission_recv(first, &from, hello, &len, ADMISSION_TIMEOUT));
	NUTS_ASSERT(nng_sockaddr_equal(&from, &client_addr));
	// The same cookie-bearing ClientHello from a different UDP source must
	// not trigger the expensive server flight. Silent discard is allowed.
	admission_send(second, &server_addr, hello, len);
	reply_len  = HELLO_SIZE;
	nng_err rv = admission_recv(second, &from, response, &reply_len, 250);
	NUTS_TRUE(rv == NNG_ETIMEDOUT ||
	    (rv == NNG_OK &&
	        (response[0] == 21 ||
	            admission_challenge(response, reply_len, version))));
	NUTS_CLOSE(client);
	NUTS_CLOSE(server);
	nng_udp_close(second);
	nng_udp_close(first);
	nng_free(response, HELLO_SIZE);
	nng_free(hello, HELLO_SIZE);
}

static void
admission_fragmented(nng_tls_version version)
{
	nng_socket   server, capture;
	nng_sockaddr server_addr, from;
	nng_udp     *source   = admission_udp();
	uint8_t     *hello    = nng_alloc(HELLO_SIZE);
	uint8_t     *fragment = nng_alloc(HELLO_SIZE);
	NUTS_ASSERT(hello != NULL && fragment != NULL);
	size_t len = HELLO_SIZE;
	capture    = admission_dial(source, version, hello, &len, &from);
	NUTS_CLOSE(capture);
	// Split a real, unfragmented ClientHello into two DTLS handshake
	// fragments. Only the first fragment may create a pending peer.
	uint32_t total = ((uint32_t) hello[14] << 16) |
	    ((uint32_t) hello[15] << 8) | hello[16];
	NUTS_ASSERT(total == len - 25 && total > 1);
	admission_listen(
	    &server, version, 2, 0, ADMISSION_TIMEOUT, &server_addr);
	uint16_t first = (uint16_t) (total / 2);
	memcpy(fragment, hello, 25 + first);
	uint16_t record = 12 + first;
	NNI_PUT16(fragment + 11, record);
	fragment[22] = 0;
	NNI_PUT16(fragment + 23, first);
	admission_send(source, &server_addr, fragment, 25 + first);

	uint16_t last = (uint16_t) (total - first);
	memcpy(fragment, hello, 25);
	memcpy(fragment + 25, hello + 25 + first, last);
	fragment[10]++; // next record sequence number, same handshake sequence
	record = 12 + last;
	NNI_PUT16(fragment + 11, record);
	fragment[19] = fragment[22] = 0;
	NNI_PUT16(fragment + 20, first);
	NNI_PUT16(fragment + 23, last);
	admission_send(source, &server_addr, fragment, 25 + last);
#if defined(NNG_TLS_ENGINE_WOLFSSL) || defined(NNG_TLS_ENGINE_MBEDTLS)
	// wolfSSL and older Mbed TLS versions discard fragmented initial
	// ClientHellos before cookie validation. Test an unfragmented retry
	// when the engine needs one.
	size_t  reply_len = HELLO_SIZE;
	nng_err rv = admission_recv(source, &from, fragment, &reply_len, 200);
	if (rv == NNG_OK) {
		NUTS_TRUE(admission_challenge(fragment, reply_len, version));
		goto done;
	}
	NUTS_FAIL(rv, NNG_ETIMEDOUT);
	hello[10] += 2;
	admission_send(source, &server_addr, hello, len);
#endif
	len = HELLO_SIZE;
	NUTS_PASS(
	    admission_recv(source, &from, hello, &len, ADMISSION_TIMEOUT));
	NUTS_TRUE(admission_challenge(hello, len, version));
#if defined(NNG_TLS_ENGINE_WOLFSSL) || defined(NNG_TLS_ENGINE_MBEDTLS)
done:
#endif
	NUTS_CLOSE(server);
	nng_udp_close(source);
	nng_free(fragment, HELLO_SIZE);
	nng_free(hello, HELLO_SIZE);
}

static void
test_admission_fragmented12(void)
{
	admission_fragmented(NNG_TLS_1_2);
}

static void
test_admission_fragmented13(void)
{
#ifdef NNG_SUPP_DTLS_1_3
	admission_fragmented(NNG_TLS_1_3);
#else
	NUTS_SKIP("engine has no DTLS 1.3 support");
#endif
}

static void
test_admission_cookie12(void)
{
	admission_cookie(NNG_TLS_1_2);
}

static void
test_admission_cookie13(void)
{
#ifdef NNG_SUPP_DTLS_1_3
	admission_cookie(NNG_TLS_1_3);
#else
	NUTS_SKIP("engine has no DTLS 1.3 support");
#endif
}

#ifdef NNG_ENABLE_STATS
static uint64_t
admission_stat(nng_listener l, const char *name)
{
	nng_stat       *stats;
	const nng_stat *ep, *stat;
	NUTS_PASS(nng_stats_get(&stats));
	NUTS_ASSERT((ep = nng_stat_find_listener(stats, l)) != NULL);
	NUTS_ASSERT((stat = nng_stat_find(ep, name)) != NULL);
	uint64_t value = nng_stat_value(stat);
	nng_stats_free(stats);
	return (value);
}

static void
admission_wait(nng_listener l, const char *name, uint64_t value)
{
	nng_time until = nng_clock() + ADMISSION_TIMEOUT;
	while (admission_stat(l, name) != value && nng_clock() < until) {
		nng_msleep(1);
	}
	NUTS_TRUE(admission_stat(l, name) == value);
}

static void
test_admission_garbage(void)
{
	nng_socket      server, client;
	nng_listener    l;
	nng_dialer      d;
	nng_sockaddr    server_addr, from;
	const nng_url  *url;
	nng_tls_config *cfg =
	    admission_config(NNG_TLS_MODE_CLIENT, NNG_TLS_1_2);
	l = admission_listen(
	    &server, NNG_TLS_1_2, 4, 0, ADMISSION_TIMEOUT, &server_addr);
	NUTS_OPEN(client);
	NUTS_PASS(
	    nng_socket_set_ms(client, NNG_OPT_SENDTIMEO, ADMISSION_TIMEOUT));
	NUTS_PASS(
	    nng_socket_set_ms(client, NNG_OPT_RECVTIMEO, ADMISSION_TIMEOUT));
	NUTS_PASS(nng_listener_get_url(l, &url));
	NUTS_PASS(nng_dialer_create_url(&d, client, url));
	NUTS_PASS(nng_dialer_set_tls(d, cfg));
	NUTS_PASS(nng_dialer_start(d, 0));
	nng_tls_config_free(cfg);
	admission_wait(l, "peer_pending", 0);
	NUTS_TRUE(admission_stat(l, "peer_alloc") == 1);
	nng_udp *sources[36];
	for (unsigned i = 0; i < NNI_NUM_ELEMENTS(sources); i++) {
		uint8_t junk[26] = { 22, 0xfe, 0xfd, 0, 0 };
		junk[12]         = 13;
		junk[13]         = 1;
		junk[16] = junk[24] = 1;
		size_t len          = sizeof(junk);
		switch (i % 9) {
		case 0:
			len = 0;
			break;
		case 1:
			junk[0] = 23;
			break;
		case 2:
			junk[0] = 21;
			break;
		case 3:
			junk[1] = 3;
			break;
		case 4:
			junk[4] = 1;
			break;
		case 5:
			junk[12] = 100;
			break;
		case 6:
			junk[21] = 1;
			break;
		case 7:
			junk[24] = 2;
			break;
		case 8:
			junk[14] = junk[15] = junk[16] = 0xff;
			break;
		}
		sources[i] = admission_udp();
		admission_send(sources[i], &server_addr, junk, len);
	}
	admission_wait(l, "peer_invalid", NNI_NUM_ELEMENTS(sources));
	NUTS_TRUE(admission_stat(l, "peer_alloc") == 1);
	NUTS_TRUE(admission_stat(l, "peer_pending") == 0);
	NUTS_SEND(client, "unaffected");
	NUTS_RECV(server, "unaffected");
	NUTS_SEND(server, "reply");
	NUTS_RECV(client, "reply");
	for (unsigned i = 0; i < NNI_NUM_ELEMENTS(sources); i++) {
		uint8_t buf[256];
		size_t  len = sizeof(buf);
		NUTS_FAIL(admission_recv(sources[i], &from, buf, &len, 10),
		    NNG_ETIMEDOUT);
		nng_udp_close(sources[i]);
	}
	NUTS_CLOSE(client);
	NUTS_CLOSE(server);
}

// Fill every pending slot with genuine ClientHellos from distinct sources.
// Further admissions must be bounded without interrupting an established peer.
static void
admission_flood(nng_tls_version version)
{
	nng_socket   server, client, capture;
	nng_sockaddr server_addr, from;
	nng_listener l =
	    admission_listen(&server, version, 4, 0, 2000, &server_addr);
	nng_tls_config *cfg = admission_config(NNG_TLS_MODE_CLIENT, version);
	const nng_url  *url;
	nng_dialer      d;
	NUTS_OPEN(client);
	NUTS_PASS(
	    nng_socket_set_ms(client, NNG_OPT_SENDTIMEO, ADMISSION_TIMEOUT));
	NUTS_PASS(
	    nng_socket_set_ms(client, NNG_OPT_RECVTIMEO, ADMISSION_TIMEOUT));
	NUTS_PASS(nng_listener_get_url(l, &url));
	NUTS_PASS(nng_dialer_create_url(&d, client, url));
	NUTS_PASS(nng_dialer_set_tls(d, cfg));
	nng_tls_config_free(cfg);
	NUTS_PASS(nng_dialer_start(d, 0));
	admission_wait(l, "peer_pending", 0);

	nng_udp *sources[32];
	for (unsigned i = 0; i < NNI_NUM_ELEMENTS(sources); i++) {
		sources[i] = admission_udp();
	}
	uint8_t *hello = nng_alloc(HELLO_SIZE);
	NUTS_ASSERT(hello != NULL);
	size_t len = HELLO_SIZE;
	capture    = admission_dial(sources[0], version, hello, &len, &from);
	NUTS_CLOSE(capture);
	for (unsigned i = 0; i < 4; i++) {
		admission_send(sources[i], &server_addr, hello, len);
	}
	admission_wait(l, "peer_pending", 4);
	for (unsigned round = 0; round < 2; round++) {
		for (unsigned i = 4; i < NNI_NUM_ELEMENTS(sources); i++) {
			admission_send(sources[i], &server_addr, hello, len);
		}
		admission_wait(l, "peer_reject", (round + 1) * 28);
		NUTS_TRUE(admission_stat(l, "peer_pending") == 4);
		NUTS_TRUE(admission_stat(l, "peer_alloc") == 5);
		NUTS_SEND(client, "during flood");
		NUTS_RECV(server, "during flood");
		NUTS_SEND(server, "still connected");
		NUTS_RECV(client, "still connected");
	}
	// Once abandoned handshakes expire, a previously rejected source gets
	// a fresh cookie challenge, while the established connection survives.
	admission_wait(l, "peer_pending", 0);
	admission_send(sources[4], &server_addr, hello, len);
	admission_wait(l, "peer_alloc", 6);
	size_t reply_len = HELLO_SIZE;
	NUTS_PASS(admission_recv(
	    sources[4], &from, hello, &reply_len, ADMISSION_TIMEOUT));
	NUTS_TRUE(admission_challenge(hello, reply_len, version));
	NUTS_SEND(client, "after flood");
	NUTS_RECV(server, "after flood");
	NUTS_CLOSE(client);
	NUTS_CLOSE(server);
	for (unsigned i = 0; i < NNI_NUM_ELEMENTS(sources); i++) {
		nng_udp_close(sources[i]);
	}
	nng_free(hello, HELLO_SIZE);
}

static void
test_admission_flood12(void)
{
	admission_flood(NNG_TLS_1_2);
}

static void
test_admission_flood13(void)
{
#ifdef NNG_SUPP_DTLS_1_3
	admission_flood(NNG_TLS_1_3);
#else
	NUTS_SKIP("engine has no DTLS 1.3 support");
#endif
}

static void
test_admission_cleanup(void)
{
	nng_socket   server, capture;
	nng_listener l;
	nng_sockaddr server_addr, from;
	nng_udp     *source = admission_udp();
	nng_udp     *other  = admission_udp();
	uint8_t     *hello  = nng_alloc(HELLO_SIZE);
	NUTS_ASSERT(hello != NULL);
	size_t len = HELLO_SIZE;
	capture    = admission_dial(source, NNG_TLS_1_2, hello, &len, &from);
	NUTS_CLOSE(capture);
	l = admission_listen(
	    &server, NNG_TLS_1_2, 1, 0, ADMISSION_TIMEOUT, &server_addr);
	admission_send(source, &server_addr, hello, len);
	admission_wait(l, "peer_pending", 1);
	nni_listener *listener;
	NUTS_PASS(nni_listener_find(&listener, (uint32_t) nng_listener_id(l)));
	nni_pipe *held = nni_dtls_test_pending_pipe(listener->l_data);
	NUTS_ASSERT(held != NULL);
	nni_pipe_close(held);
	// Wait until stop has removed the address-map entry. Our outstanding
	// reference still owns the buffers and TLS object, so admission is
	// full.
	nng_time until = nng_clock() + ADMISSION_TIMEOUT;
	for (;;) {
		nni_pipe *check = nni_dtls_test_pending_pipe(listener->l_data);
		if (check == NULL) {
			break;
		}
		nni_pipe_rele(check);
		NUTS_ASSERT(nng_clock() < until);
		nng_msleep(1);
	}
	admission_send(other, &server_addr, hello, len);
	admission_wait(l, "peer_reject", 1);
	NUTS_TRUE(admission_stat(l, "peer_pending") == 1);
	NUTS_TRUE(admission_stat(l, "peer_alloc") == 1);
	nni_pipe_rele(held);
	admission_wait(l, "peer_pending", 0);
	admission_send(other, &server_addr, hello, len);
	admission_wait(l, "peer_alloc", 2);
	NUTS_TRUE(admission_stat(l, "peer_pending") == 1);
	nni_listener_rele(listener);
	NUTS_CLOSE(
	    server); // also exercise shutdown with an incomplete handshake
	nng_udp_close(other);
	nng_udp_close(source);
	nng_free(hello, HELLO_SIZE);
}

static nni_atomic_int admission_fail_buffer;
static void *(*admission_malloc_fn)(size_t);

static void *
admission_malloc(size_t size)
{
	if (size == HELLO_SIZE && nni_atomic_get(&admission_fail_buffer) > 0 &&
	    nni_atomic_dec_nv(&admission_fail_buffer) == 0) {
		return (NULL);
	}
	return (admission_malloc_fn(size));
}

static void
test_admission_setup_failure(void)
{
	nng_init_params original = {
		.malloc_fn = nni_malloc_fn,
		.calloc_fn = nni_calloc_fn,
		.free_fn   = nni_free_fn,
	};
	nng_init_params params = original;
	params.malloc_fn       = admission_malloc;
	admission_malloc_fn    = original.malloc_fn;
	nng_fini();
	nni_atomic_init(&admission_fail_buffer);
	NUTS_PASS(nng_init(&params));
	nng_socket   server, capture;
	nng_sockaddr server_addr, from;
	nng_udp     *source = admission_udp();
	uint8_t     *hello  = nng_alloc(HELLO_SIZE);
	uint8_t     *reply  = nng_alloc(HELLO_SIZE);
	NUTS_ASSERT(hello != NULL && reply != NULL);
	size_t len = HELLO_SIZE;
	capture    = admission_dial(source, NNG_TLS_1_2, hello, &len, &from);
	NUTS_CLOSE(capture);
	nng_listener l =
	    admission_listen(&server, NNG_TLS_1_2, 1, 0, 1000, &server_addr);
	for (int fail = 1; fail <= 2; fail++) {
		// Fail each of the two transport buffer allocations in turn.
		// Cleanup must release the slot even though TLS and
		// address-map registration have not been initialized yet.
		nni_atomic_set(&admission_fail_buffer, fail);
		admission_send(source, &server_addr, hello, len);
		admission_wait(l, "peer_alloc", 2 * fail - 1);
		admission_wait(l, "peer_pending", 0);
		NUTS_TRUE(nni_atomic_get(&admission_fail_buffer) == 0);
		admission_send(source, &server_addr, hello, len);
		admission_wait(l, "peer_alloc", 2 * fail);
		size_t reply_len = HELLO_SIZE;
		NUTS_PASS(admission_recv(
		    source, &from, reply, &reply_len, ADMISSION_TIMEOUT));
		NUTS_TRUE(admission_challenge(reply, reply_len, NNG_TLS_1_2));
		admission_wait(l, "peer_pending", 0);
	}
	NUTS_CLOSE(server);
	nng_udp_close(source);
	nng_free(reply, HELLO_SIZE);
	nng_free(hello, HELLO_SIZE);
	nng_fini();
	NUTS_PASS(nng_init(&original));
}

static void
test_admission_rate(void)
{
	nng_socket   server, client;
	nng_sockaddr server_addr;
	nng_listener l =
	    admission_listen(&server, NNG_TLS_1_2, 0, 1, 2000, &server_addr);
	// A plausible initial fragment with an invalid ClientHello body makes
	// TLS fail immediately. Repeated failures must still consume rate
	// tokens.
	uint8_t hello[26] = { 22, 0xfe, 0xfd, 0, 0 };
	hello[12]         = 13;
	hello[13]         = 1;
	hello[16] = hello[24] = 1;
	nng_udp *sources[32];
	nng_time start = nng_clock();
	for (unsigned i = 0; i < NNI_NUM_ELEMENTS(sources); i++) {
		sources[i] = admission_udp();
		admission_send(sources[i], &server_addr, hello, sizeof(hello));
	}
	nng_time until = nng_clock() + ADMISSION_TIMEOUT;
	uint64_t allocations, rejected;
	do {
		allocations = admission_stat(l, "peer_alloc");
		rejected    = admission_stat(l, "peer_rate");
		if (allocations + rejected == NNI_NUM_ELEMENTS(sources)) {
			break;
		}
		nng_msleep(1);
	} while (nng_clock() < until);
	NUTS_TRUE(allocations + rejected == NNI_NUM_ELEMENTS(sources));
	NUTS_TRUE(rejected != 0);
	NUTS_TRUE(allocations <= 1 + (nng_clock() - start) / 1000);
	admission_wait(l, "peer_pending", 0);
	// Normal DTLS retransmission must recover after the bucket refills.
	const nng_url  *url;
	nng_dialer      d;
	nng_tls_config *cfg =
	    admission_config(NNG_TLS_MODE_CLIENT, NNG_TLS_1_2);
	NUTS_OPEN(client);
	NUTS_PASS(
	    nng_socket_set_ms(client, NNG_OPT_SENDTIMEO, ADMISSION_TIMEOUT));
	NUTS_PASS(nng_listener_get_url(l, &url));
	NUTS_PASS(nng_dialer_create_url(&d, client, url));
	NUTS_PASS(nng_dialer_set_tls(d, cfg));
	// Its listener deadline starts only after a rate token is available.
	NUTS_PASS(nng_dialer_start(d, 0));
	NUTS_SEND(client, "recovered");
	NUTS_RECV(server, "recovered");
	NUTS_CLOSE(client);
	NUTS_CLOSE(server);
	nng_tls_config_free(cfg);
	for (unsigned i = 0; i < NNI_NUM_ELEMENTS(sources); i++) {
		nng_udp_close(sources[i]);
	}
}
#else
static void
test_admission_setup_failure(void)
{
	NUTS_SKIP("statistics disabled");
}
static void
test_admission_flood12(void)
{
	NUTS_SKIP("statistics disabled");
}
static void
test_admission_flood13(void)
{
	NUTS_SKIP("statistics disabled");
}
static void
test_admission_garbage(void)
{
	NUTS_SKIP("statistics disabled");
}
static void
test_admission_cleanup(void)
{
	NUTS_SKIP("statistics disabled");
}
static void
test_admission_rate(void)
{
	NUTS_SKIP("statistics disabled");
}
#endif

static void
test_admission_options(void)
{
	nng_socket   s;
	nng_listener l;
	size_t       rate;
	NUTS_OPEN(s);
	NUTS_PASS(nng_listener_create(&l, s, "dtls4://127.0.0.1:0"));
	NUTS_PASS(nng_listener_get_size(l, NNG_OPT_DTLS_CONN_RATE, &rate));
	NUTS_TRUE(rate == 128);
	NUTS_FAIL(nng_listener_set_bool(l, NNG_OPT_DTLS_CONN_RATE, true),
	    NNG_EBADTYPE);
	NUTS_PASS(nng_listener_set_size(l, NNG_OPT_DTLS_CONN_RATE, 0));
	NUTS_PASS(nng_listener_get_size(l, NNG_OPT_DTLS_CONN_RATE, &rate));
	NUTS_TRUE(rate == 0);
	NUTS_PASS(nng_listener_set_size(l, NNG_OPT_DTLS_CONN_RATE, 7));
	NUTS_PASS(nng_listener_get_size(l, NNG_OPT_DTLS_CONN_RATE, &rate));
	NUTS_TRUE(rate == 7);
	nng_tls_config *cfg =
	    admission_config(NNG_TLS_MODE_SERVER, NNG_TLS_1_2);
	NUTS_PASS(nng_listener_set_tls(l, cfg));
	NUTS_PASS(nng_listener_start(l, 0));
	NUTS_FAIL(
	    nng_listener_set_size(l, NNG_OPT_DTLS_CONN_RATE, 1), NNG_EBUSY);
	NUTS_CLOSE(s);
	nng_tls_config_free(cfg);
}

NUTS_TESTS = {
	{ "admission cookie 1.2", test_admission_cookie12 },
	{ "admission cookie 1.3", test_admission_cookie13 },
	{ "admission fragmented 1.2", test_admission_fragmented12 },
	{ "admission fragmented 1.3", test_admission_fragmented13 },
	{ "admission garbage", test_admission_garbage },
	{ "admission flood 1.2", test_admission_flood12 },
	{ "admission flood 1.3", test_admission_flood13 },
	{ "admission cleanup", test_admission_cleanup },
	{ "admission setup failure", test_admission_setup_failure },
	{ "admission rate", test_admission_rate },
	{ "admission options", test_admission_options },
	{ NULL, NULL },
};
