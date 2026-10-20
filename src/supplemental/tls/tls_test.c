//
// Copyright 2026 Staysail Systems, Inc. <info@staysail.tech>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "nng/nng.h"

// Establish the platform header order before acutest includes windows.h.
#include "tls_common.h"

#include "../../testing/nuts.h"

static void
test_tls_close_idle_bio(void)
{
	nng_tls_config       *cfg;
	nni_tls_conn         *conn;
	nng_aio              *aios[4];
	nng_sockaddr          sa  = { 0 };
	const nni_tls_bio_ops ops = { 0 };
	size_t                size;

	NUTS_PASS(nng_tls_config_alloc(&cfg, NNG_TLS_MODE_CLIENT));
	size = sizeof(*conn) + nni_tls_engine_conn_size();
	NUTS_ASSERT((conn = nni_zalloc(size)) != NULL);
	NUTS_PASS(nni_tls_init(conn, cfg, false));
	sa.s_in.sa_family = NNG_AF_INET;
	NUTS_PASS(nni_tls_start(conn, &ops, NULL, &sa));

	// A lower-layer error can leave no BIO operation to cancel. Closing
	// must still finish every upper-layer operation without a BIO
	// callback.
	conn->bio_closed = true;
	conn->bio_err    = NNG_ECONNSHUT;
	for (size_t i = 0; i < NNI_NUM_ELEMENTS(aios); i++) {
		NUTS_PASS(nng_aio_alloc(&aios[i], NULL, NULL));
		nni_aio_reset(aios[i]);
		NUTS_TRUE(nni_aio_start(aios[i], NULL, NULL));
		nni_aio_list_append(
		    i % 2 ? &conn->recv_queue : &conn->send_queue, aios[i]);
	}

	nni_tls_close(conn);
	for (size_t i = 0; i < NNI_NUM_ELEMENTS(aios); i++) {
		NUTS_TRUE(!nni_aio_busy(aios[i]));
		NUTS_TRUE(!nni_aio_list_active(aios[i]));
		// Clean up a stranded operation even if the regression fails.
		if (nni_aio_list_active(aios[i])) {
			nni_aio_list_remove(aios[i]);
			nni_aio_finish_error(aios[i], NNG_ECLOSED);
		}
		nng_aio_wait(aios[i]);
		NUTS_FAIL(nng_aio_result(aios[i]), NNG_ECLOSED);
		NUTS_TRUE(nng_aio_count(aios[i]) == 0);
		nng_aio_free(aios[i]);
	}
	nni_tls_fini(conn);
	nni_free(conn, size);
	nng_tls_config_free(cfg);
}

static void
test_tls_send_pending(void)
{
	nni_tls_conn conn = { 0 };
	nng_msg     *msg;
	nni_mtx_init(&conn.bio_lock);
	nni_lmq_init(&conn.bio_send_lmq, 2);
	NUTS_TRUE(!nni_tls_send_pending(&conn));
	conn.bio_send_active = true;
	NUTS_TRUE(nni_tls_send_pending(&conn));
	conn.bio_send_active = false;
	conn.bio_send_len    = 1;
	NUTS_TRUE(nni_tls_send_pending(&conn));
	conn.bio_send_len = 0;
	NUTS_PASS(nng_msg_alloc(&msg, 0));
	NUTS_PASS(nni_lmq_put(&conn.bio_send_lmq, msg));
	NUTS_TRUE(nni_tls_send_pending(&conn));
	nni_lmq_flush(&conn.bio_send_lmq);
	NUTS_TRUE(!nni_tls_send_pending(&conn));
	nni_lmq_fini(&conn.bio_send_lmq);
	nni_mtx_fini(&conn.bio_lock);
}

void
test_tls_datagram_truncation(void)
{
	nni_tls_conn conn = { 0 };
	nng_msg     *msg;
	uint8_t      buf[8];
	size_t       len;

	// Exercise the BIO datagram boundary without a TLS handshake. Mark
	// the BIO closed so a read cannot start underlying I/O.
	conn.msg_oriented = true;
	conn.bio_closed   = true;
	nni_mtx_init(&conn.bio_lock);
	nni_lmq_init(&conn.bio_recv_lmq, 2);
	NUTS_PASS(nng_msg_alloc(&msg, 0));
	NUTS_PASS(nng_msg_append(msg, "first datagram", 14));
	NUTS_PASS(nni_lmq_put(&conn.bio_recv_lmq, msg));
	NUTS_PASS(nng_msg_alloc(&msg, 0));
	NUTS_PASS(nng_msg_append(msg, "second", 6));
	NUTS_PASS(nni_lmq_put(&conn.bio_recv_lmq, msg));

	len = 3;
	NUTS_PASS(nng_tls_engine_recv(&conn, buf, &len));
	NUTS_TRUE(len == 3);
	NUTS_TRUE(memcmp(buf, "fir", len) == 0);
	len = sizeof(buf);
	NUTS_PASS(nng_tls_engine_recv(&conn, buf, &len));
	NUTS_TRUE(len == 6);
	NUTS_TRUE(memcmp(buf, "second", len) == 0);
	len = sizeof(buf);
	NUTS_FAIL(nng_tls_engine_recv(&conn, buf, &len), NNG_EAGAIN);
	NUTS_TRUE(conn.bio_recv_msg == NULL);

	nni_lmq_fini(&conn.bio_recv_lmq);
	nni_mtx_fini(&conn.bio_lock);
}

void
test_tls_config_version(void)
{
	nng_tls_config *cfg;

	NUTS_ENABLE_LOG(NNG_LOG_INFO);
	NUTS_PASS(nng_tls_config_alloc(&cfg, NNG_TLS_MODE_SERVER));

	// Verify that min ver < max ver
	NUTS_FAIL(nng_tls_config_version(cfg, NNG_TLS_1_3, NNG_TLS_1_2),
	    NNG_ENOTSUP);

	// Verify that we cannot configure TLS 1.1 or older.
	NUTS_FAIL(
	    nng_tls_config_version(cfg, NNG_TLS_1_2 - 1, NNG_TLS_1_2 - 1),
	    NNG_ENOTSUP);

	// Verify that we cannot configure TLS > 1.3.
	NUTS_FAIL(nng_tls_config_version(cfg, NNG_TLS_1_2, NNG_TLS_1_3 + 1),
	    NNG_ENOTSUP);

	// Verify that we *can* configure some various ranges starting with
	// TLS v1.2.
	NUTS_PASS(nng_tls_config_version(cfg, NNG_TLS_1_2, NNG_TLS_1_2));
	NUTS_PASS(nng_tls_config_version(cfg, NNG_TLS_1_2, NNG_TLS_1_3));

	nng_tls_config_free(cfg);
}

void
test_tls_config_groups(void)
{
	nng_tls_config *cfg;
	nng_tls_group   groups[]    = { NNG_TLS_GRP_SECP256R1,
		NNG_TLS_GRP_SECP384R1 };
	nng_tls_group   invalid[]   = { NNG_TLS_GRP_SECP256R1,
		(nng_tls_group) 0xffff };
	nng_tls_group   duplicate[] = { NNG_TLS_GRP_SECP256R1,
		NNG_TLS_GRP_SECP256R1 };

	NUTS_PASS(nng_tls_config_alloc(&cfg, NNG_TLS_MODE_CLIENT));
	NUTS_FAIL(nng_tls_config_groups(NULL, groups, 1), NNG_EINVAL);
	NUTS_FAIL(nng_tls_config_groups(cfg, NULL, 1), NNG_EINVAL);
	NUTS_FAIL(nng_tls_config_groups(cfg, groups, 0), NNG_EINVAL);
	NUTS_FAIL(nng_tls_config_groups(cfg, groups, NNI_TLS_MAX_GROUPS + 1),
	    NNG_EINVAL);
	NUTS_FAIL(nng_tls_config_groups(cfg, invalid, 2), NNG_ENOTSUP);
	NUTS_FAIL(nng_tls_config_groups(cfg, duplicate, 2), NNG_EINVAL);
	nng_err rv = nng_tls_config_groups(cfg, groups, 2);
	NUTS_TRUE(rv == NNG_OK || rv == NNG_ENOTSUP);
	if (rv == NNG_OK) {
		// Each successful call replaces the list.
		NUTS_PASS(nng_tls_config_groups(cfg, groups + 1, 1));
	}
	nng_tls_config_free(cfg);
}

static void
test_tls_groups_handshake(nng_tls_version version,
    const nng_tls_group *server_groups, size_t server_count,
    const nng_tls_group *client_groups, size_t client_count, bool mismatch,
    bool psk)
{
	nng_tls_config      *cfg[2];
	nng_stream          *stream[2];
	nng_stream_listener *listener;
	nng_stream_dialer   *dialer;
	nng_aio             *aio[2];
	nng_tls_group        copy[NNI_TLS_MAX_GROUPS];
	char                 addr[64];
	int                  port;
	nng_err              rv;
	uint8_t              key[32] = { 1, 2, 3, 4 };
	uint8_t              data[]  = { 1, 2, 3, 4, 5 };
	uint8_t              received[sizeof(data)];
	const nng_tls_group  bad[] = { (nng_tls_group) 0xffff };

	// Probe optional capabilities before performing checks: acutest cannot
	// mark a test skipped after any checks have run.
	rv = nng_tls_config_alloc(&cfg[0], NNG_TLS_MODE_SERVER);
	if (rv != NNG_OK) {
		NUTS_PASS(rv);
		return;
	}
	rv = nng_tls_config_alloc(&cfg[1], NNG_TLS_MODE_CLIENT);
	if (rv != NNG_OK) {
		nng_tls_config_free(cfg[0]);
		NUTS_PASS(rv);
		return;
	}
	for (size_t i = 0; i < 2; i++) {
		size_t count = i == 0 ? server_count : client_count;
		const nng_tls_group *groups =
		    i == 0 ? server_groups : client_groups;
		if ((rv = nng_tls_config_version(cfg[i], version, version)) !=
		    NNG_OK) {
			break;
		}
		memcpy(copy, groups, count * sizeof(copy[0]));
		if ((rv = nng_tls_config_groups(cfg[i], copy, count)) !=
		    NNG_OK) {
			break;
		}
		memset(copy, 0, sizeof(copy));
		if (psk &&
		    (rv = nng_tls_config_psk(
		         cfg[i], "groups", key, sizeof(key))) != NNG_OK) {
			break;
		}
	}
	if (rv == NNG_ENOTSUP) {
		nng_tls_config_free(cfg[0]);
		nng_tls_config_free(cfg[1]);
		NUTS_SKIP("TLS version, groups, or PSK unavailable in this "
		          "engine build");
		return;
	}
	NUTS_PASS(rv);
	for (size_t i = 0; i < 2; i++) {
		size_t count = i == 0 ? server_count : client_count;
		const nng_tls_group *groups =
		    i == 0 ? server_groups : client_groups;
		// Preserve the previous list on common-layer and native
		// rejection.
		NUTS_FAIL(nng_tls_config_groups(cfg[i], bad, 1), NNG_ENOTSUP);
		const nng_tls_group hybrid[] = { NNG_TLS_GRP_SECP256R1,
			NNG_TLS_GRP_X25519MLKEM768 };
		nng_err replacement = nng_tls_config_groups(cfg[i], hybrid, 2);
		NUTS_TRUE(replacement == NNG_OK || replacement == NNG_ENOTSUP);
		if (replacement == NNG_OK) {
			memcpy(copy, groups, count * sizeof(copy[0]));
			NUTS_PASS(nng_tls_config_groups(cfg[i], copy, count));
			memset(copy, 0, sizeof(copy));
		}
	}
	NUTS_PASS(nng_tls_config_own_cert(
	    cfg[0], nuts_server_crt, nuts_server_key, NULL));
	NUTS_PASS(nng_tls_config_auth_mode(cfg[1], NNG_TLS_AUTH_MODE_NONE));
	NUTS_PASS(
	    nng_stream_listener_alloc(&listener, "tls+tcp://127.0.0.1:0"));
	NUTS_PASS(nng_stream_listener_set_tls(listener, cfg[0]));
	NUTS_PASS(nng_stream_listener_listen(listener));
	NUTS_PASS(
	    nng_stream_listener_get_int(listener, NNG_OPT_BOUND_PORT, &port));
	snprintf(addr, sizeof(addr), "tls+tcp://127.0.0.1:%d", port);
	NUTS_PASS(nng_stream_dialer_alloc(&dialer, addr));
	NUTS_PASS(nng_stream_dialer_set_tls(dialer, cfg[1]));
	for (size_t i = 0; i < 2; i++) {
		NUTS_PASS(nng_aio_alloc(&aio[i], NULL, NULL));
		nng_aio_set_timeout(aio[i], 5000);
	}
	nng_stream_listener_accept(listener, aio[0]);
	nng_stream_dialer_dial(dialer, aio[1]);
	for (size_t i = 0; i < 2; i++) {
		nng_aio_wait(aio[i]);
		NUTS_PASS(nng_aio_result(aio[i]));
		stream[i] = nng_aio_get_output(aio[i], 0);
		NUTS_FAIL(
		    nng_tls_config_groups(cfg[i], server_groups, server_count),
		    NNG_EBUSY);
	}
	// Streams establish TLS lazily. Application I/O drives the handshake.
	void *send = nuts_stream_send_start(stream[0], data, sizeof(data));
	void *recv =
	    nuts_stream_recv_start(stream[1], received, sizeof(received));
	int sent = nuts_stream_wait(send);
	if (mismatch) {
		// Some engines do not send an alert after a fatal handshake
		// error. Close the failed sender so the other operation can
		// finish too.
		NUTS_TRUE(sent != NNG_OK);
		NUTS_TRUE(sent != NNG_ETIMEDOUT);
		nng_stream_close(stream[0]);
	}
	int recvd = nuts_stream_wait(recv);
	if (mismatch) {
		NUTS_TRUE(recvd != NNG_OK);
		NUTS_TRUE(recvd != NNG_ETIMEDOUT);
	} else {
		NUTS_PASS(sent);
		NUTS_PASS(recvd);
		NUTS_TRUE(memcmp(data, received, sizeof(data)) == 0);
	}
	for (size_t i = 0; i < 2; i++) {
		nng_stream_stop(stream[i]);
		nng_stream_free(stream[i]);
		nng_aio_free(aio[i]);
		nng_tls_config_free(cfg[i]);
	}
	nng_stream_dialer_free(dialer);
	nng_stream_listener_free(listener);
}

void
test_tls_groups_tls12(void)
{
	const nng_tls_group server[] = { NNG_TLS_GRP_SECP384R1,
		NNG_TLS_GRP_SECP256R1 };
	const nng_tls_group client[] = { NNG_TLS_GRP_SECP256R1 };
	test_tls_groups_handshake(
	    NNG_TLS_1_2, server, 2, client, 1, false, false);
}

void
test_tls_groups_tls13(void)
{
	const nng_tls_group server[] = { NNG_TLS_GRP_SECP384R1,
		NNG_TLS_GRP_SECP256R1 };
	const nng_tls_group client[] = { NNG_TLS_GRP_SECP256R1 };
	test_tls_groups_handshake(
	    NNG_TLS_1_3, server, 2, client, 1, false, false);
}

void
test_tls_groups_mismatch(void)
{
	const nng_tls_group server[] = { NNG_TLS_GRP_SECP384R1 };
	const nng_tls_group client[] = { NNG_TLS_GRP_SECP256R1 };
	test_tls_groups_handshake(
	    NNG_TLS_1_3, server, 1, client, 1, true, false);
}

void
test_tls_groups_hybrid(void)
{
	const nng_tls_group groups[] = { NNG_TLS_GRP_X25519MLKEM768 };
	test_tls_groups_handshake(
	    NNG_TLS_1_3, groups, 1, groups, 1, false, false);
}

void
test_tls_groups_hybrid_mismatch(void)
{
	const nng_tls_group server[] = { NNG_TLS_GRP_X25519MLKEM768 };
	const nng_tls_group client[] = { NNG_TLS_GRP_X25519 };
	test_tls_groups_handshake(
	    NNG_TLS_1_3, server, 1, client, 1, true, false);
}

void
test_tls_groups_hybrid_p256(void)
{
	const nng_tls_group groups[] = { NNG_TLS_GRP_SECP256R1MLKEM768 };
	test_tls_groups_handshake(
	    NNG_TLS_1_3, groups, 1, groups, 1, false, false);
}

void
test_tls_groups_hybrid_p384(void)
{
	const nng_tls_group groups[] = { NNG_TLS_GRP_SECP384R1MLKEM1024 };
	test_tls_groups_handshake(
	    NNG_TLS_1_3, groups, 1, groups, 1, false, false);
}

void
test_tls_groups_hybrid_psk(void)
{
	const nng_tls_group groups[] = { NNG_TLS_GRP_X25519MLKEM768 };
	test_tls_groups_handshake(
	    NNG_TLS_1_3, groups, 1, groups, 1, false, true);
}

void
test_tls_groups_psk(void)
{
	const nng_tls_group groups[] = { NNG_TLS_GRP_SECP256R1 };
	test_tls_groups_handshake(
	    NNG_TLS_1_3, groups, 1, groups, 1, false, true);
}

void
test_tls_groups_psk_mismatch(void)
{
	const nng_tls_group server[] = { NNG_TLS_GRP_SECP384R1 };
	const nng_tls_group client[] = { NNG_TLS_GRP_SECP256R1 };
	test_tls_groups_handshake(
	    NNG_TLS_1_3, server, 1, client, 1, true, true);
}

void
test_tls_config_single_identity(void)
{
	nng_tls_config    *cfg;
	const nng_tls_mode modes[] = {
		NNG_TLS_MODE_CLIENT,
		NNG_TLS_MODE_SERVER,
	};

	for (size_t i = 0; i < NNI_NUM_ELEMENTS(modes); i++) {
		NUTS_PASS(nng_tls_config_alloc(&cfg, modes[i]));
		NUTS_PASS(nng_tls_config_own_cert(
		    cfg, nuts_server_crt, nuts_server_key, NULL));
		// No endpoint uses the configuration yet: this must be the
		// single-identity guard, not the busy-after-first-use guard.
		NUTS_TRUE(!cfg->busy);
		NUTS_FAIL(nng_tls_config_own_cert(cfg, nuts_ecdsa_server_crt,
		              nuts_ecdsa_server_key, "different password"),
		    NNG_EBUSY);
		NUTS_FAIL(nng_tls_config_own_cert(
		              cfg, nuts_server_crt, nuts_server_key, NULL),
		    NNG_EBUSY);
		nng_tls_config_free(cfg);
	}
}

void
test_tls_conn_refused(void)
{
	nng_stream_dialer *dialer;
	nng_aio           *aio;

	NUTS_ENABLE_LOG(NNG_LOG_INFO);
	NUTS_PASS(nng_aio_alloc(&aio, NULL, NULL));
	nng_aio_set_timeout(aio, 5000); // 5 sec

	// port 8 is generally not used for anything.
	NUTS_PASS(nng_stream_dialer_alloc(&dialer, "tls+tcp://127.0.0.1:8"));
	nng_stream_dialer_dial(dialer, aio);
	nng_aio_wait(aio);
	NUTS_FAIL(nng_aio_result(aio), NNG_ECONNREFUSED);

	nng_aio_free(aio);
	nng_stream_dialer_stop(dialer);
	nng_stream_dialer_free(dialer);
}

void
test_tls_large_message(void)
{
	nng_stream_listener *l;
	nng_stream_dialer   *d;
	nng_aio             *aio1, *aio2;
	nng_stream          *s1;
	nng_stream          *s2;
	nng_tls_config      *c1;
	nng_tls_config      *c2;
	char                 addr[32];
	uint8_t             *buf1;
	uint8_t             *buf2;
	size_t               size = 450001;
	void                *t1;
	void                *t2;
	int                  port;

	NUTS_ENABLE_LOG(NNG_LOG_DEBUG);
	// allocate messages
	NUTS_ASSERT((buf1 = nng_alloc(size)) != NULL);
	NUTS_ASSERT((buf2 = nng_alloc(size)) != NULL);

	for (size_t i = 0; i < size; i++) {
		buf1[i] = rand() & 0xff;
	}

	NUTS_PASS(nng_aio_alloc(&aio1, NULL, NULL));
	NUTS_PASS(nng_aio_alloc(&aio2, NULL, NULL));
	nng_aio_set_timeout(aio1, 5000);
	nng_aio_set_timeout(aio2, 5000);

	// Allocate the listener first.  We use a wild-card port.
	NUTS_PASS(nng_stream_listener_alloc(&l, "tls+tcp://127.0.0.1:0"));
	NUTS_PASS(nng_tls_config_alloc(&c1, NNG_TLS_MODE_SERVER));
	NUTS_PASS(nng_tls_config_own_cert(
	    c1, nuts_server_crt, nuts_server_key, NULL));
	NUTS_PASS(nng_stream_listener_set_tls(l, c1));
	NUTS_PASS(nng_stream_listener_listen(l));
	NUTS_PASS(nng_stream_listener_get_int(l, NNG_OPT_BOUND_PORT, &port));
	NUTS_TRUE(port > 0);
	NUTS_TRUE(port < 65536);

	snprintf(addr, sizeof(addr), "tls+tcp://127.0.0.1:%d", port);
	NUTS_PASS(nng_stream_dialer_alloc(&d, addr));
	NUTS_PASS(nng_tls_config_alloc(&c2, NNG_TLS_MODE_CLIENT));
	NUTS_PASS(nng_tls_config_ca_chain(c2, nuts_server_crt, NULL));
	NUTS_PASS(nng_tls_config_server_name(c2, "localhost"));

	NUTS_PASS(nng_stream_dialer_set_tls(d, c2));

	nng_stream_listener_accept(l, aio1);
	nng_stream_dialer_dial(d, aio2);

	nng_aio_wait(aio1);
	nng_aio_wait(aio2);

	NUTS_PASS(nng_aio_result(aio1));
	NUTS_PASS(nng_aio_result(aio2));

	NUTS_TRUE((s1 = nng_aio_get_output(aio1, 0)) != NULL);
	NUTS_TRUE((s2 = nng_aio_get_output(aio2, 0)) != NULL);

	t1 = nuts_stream_send_start(s1, buf1, size);
	t2 = nuts_stream_recv_start(s2, buf2, size);

	NUTS_PASS(nuts_stream_wait(t1));
	NUTS_PASS(nuts_stream_wait(t2));
	NUTS_TRUE(memcmp(buf1, buf2, size) == 0);

	nng_free(buf1, size);
	nng_free(buf2, size);
	nng_stream_stop(s1);
	nng_stream_stop(s2);
	nng_stream_dialer_stop(d);
	nng_stream_listener_stop(l);
	nng_stream_free(s1);
	nng_stream_free(s2);
	nng_stream_dialer_free(d);
	nng_stream_listener_free(l);
	nng_tls_config_free(c1);
	nng_tls_config_free(c2);
	nng_aio_free(aio1);
	nng_aio_free(aio2);
}

void
test_tls_ecdsa(void)
{
	nng_stream_listener *l;
	nng_stream_dialer   *d;
	nng_aio             *aio1, *aio2;
	nng_stream          *s1;
	nng_stream          *s2;
	nng_tls_config      *c1;
	nng_tls_config      *c2;
	char                 addr[32];
	uint8_t             *buf1;
	uint8_t             *buf2;
	size_t               size = 8000;
	void                *t1;
	void                *t2;
	int                  port;

	NUTS_ENABLE_LOG(NNG_LOG_DEBUG);
	// allocate messages
	NUTS_ASSERT((buf1 = nng_alloc(size)) != NULL);
	NUTS_ASSERT((buf2 = nng_alloc(size)) != NULL);

	for (size_t i = 0; i < size; i++) {
		buf1[i] = rand() & 0xff;
	}

	NUTS_PASS(nng_aio_alloc(&aio1, NULL, NULL));
	NUTS_PASS(nng_aio_alloc(&aio2, NULL, NULL));
	nng_aio_set_timeout(aio1, 5000);
	nng_aio_set_timeout(aio2, 5000);

	// Allocate the listener first.  We use a wild-card port.
	NUTS_PASS(nng_stream_listener_alloc(&l, "tls+tcp://127.0.0.1:0"));
	NUTS_PASS(nng_tls_config_alloc(&c1, NNG_TLS_MODE_SERVER));
	NUTS_PASS(nng_tls_config_own_cert(
	    c1, nuts_ecdsa_server_crt, nuts_ecdsa_server_key, NULL));
	NUTS_PASS(nng_stream_listener_set_tls(l, c1));
	NUTS_PASS(nng_stream_listener_listen(l));
	NUTS_PASS(nng_stream_listener_get_int(l, NNG_OPT_BOUND_PORT, &port));
	NUTS_TRUE(port > 0);
	NUTS_TRUE(port < 65536);

	snprintf(addr, sizeof(addr), "tls+tcp://127.0.0.1:%d", port);
	NUTS_PASS(nng_stream_dialer_alloc(&d, addr));
	NUTS_PASS(nng_tls_config_alloc(&c2, NNG_TLS_MODE_CLIENT));
	NUTS_PASS(nng_tls_config_ca_chain(c2, nuts_ecdsa_server_crt, NULL));
	NUTS_PASS(nng_tls_config_server_name(c2, "localhost"));

	NUTS_PASS(nng_stream_dialer_set_tls(d, c2));

	nng_stream_listener_accept(l, aio1);
	nng_stream_dialer_dial(d, aio2);

	nng_aio_wait(aio1);
	nng_aio_wait(aio2);

	NUTS_PASS(nng_aio_result(aio1));
	NUTS_PASS(nng_aio_result(aio2));

	NUTS_TRUE((s1 = nng_aio_get_output(aio1, 0)) != NULL);
	NUTS_TRUE((s2 = nng_aio_get_output(aio2, 0)) != NULL);

	t1 = nuts_stream_send_start(s1, buf1, size);
	t2 = nuts_stream_recv_start(s2, buf2, size);

	NUTS_PASS(nuts_stream_wait(t1));
	NUTS_PASS(nuts_stream_wait(t2));
	NUTS_TRUE(memcmp(buf1, buf2, size) == 0);

	nng_stream_stop(s1);
	nng_stream_stop(s2);
	nng_stream_dialer_stop(d);
	nng_stream_listener_stop(l);
	nng_stream_free(s1);
	nng_stream_free(s2);
	nng_stream_dialer_free(d);
	nng_stream_listener_free(l);
	nng_tls_config_free(c1);
	nng_tls_config_free(c2);
	nng_aio_free(aio1);
	nng_aio_free(aio2);
	nng_free(buf1, size);
	nng_free(buf2, size);
}

void
test_tls_null_server_name(void)
{
	nng_stream_listener *l;
	nng_stream_dialer   *d;
	nng_aio             *aio1, *aio2;
	nng_stream          *s1;
	nng_stream          *s2;
	nng_tls_config      *c1;
	nng_tls_config      *c2;
	char                 addr[32];
	uint8_t             *buf1;
	uint8_t             *buf2;
	size_t               size = 8000;
	void                *t1;
	void                *t2;
	int                  port;

	NUTS_ENABLE_LOG(NNG_LOG_DEBUG);
	// allocate messages
	NUTS_ASSERT((buf1 = nng_alloc(size)) != NULL);
	NUTS_ASSERT((buf2 = nng_alloc(size)) != NULL);

	for (size_t i = 0; i < size; i++) {
		buf1[i] = rand() & 0xff;
	}

	NUTS_PASS(nng_aio_alloc(&aio1, NULL, NULL));
	NUTS_PASS(nng_aio_alloc(&aio2, NULL, NULL));
	nng_aio_set_timeout(aio1, 5000);
	nng_aio_set_timeout(aio2, 5000);

	// Allocate the listener first.  We use a wild-card port.
	NUTS_PASS(nng_stream_listener_alloc(&l, "tls+tcp://127.0.0.1:0"));
	NUTS_PASS(nng_tls_config_alloc(&c1, NNG_TLS_MODE_SERVER));
	NUTS_PASS(nng_tls_config_own_cert(
	    c1, nuts_server_crt, nuts_server_key, NULL));
	NUTS_PASS(nng_stream_listener_set_tls(l, c1));
	NUTS_PASS(nng_stream_listener_listen(l));
	NUTS_PASS(nng_stream_listener_get_int(l, NNG_OPT_BOUND_PORT, &port));
	NUTS_TRUE(port > 0);
	NUTS_TRUE(port < 65536);

	snprintf(addr, sizeof(addr), "tls+tcp://127.0.0.1:%d", port);
	NUTS_PASS(nng_stream_dialer_alloc(&d, addr));
	NUTS_PASS(nng_tls_config_alloc(&c2, NNG_TLS_MODE_CLIENT));
	NUTS_PASS(nng_tls_config_ca_chain(c2, nuts_server_crt, NULL));

	NUTS_PASS(nng_stream_dialer_set_tls(d, c2));

	nng_stream_listener_accept(l, aio1);
	nng_stream_dialer_dial(d, aio2);

	nng_aio_wait(aio1);
	nng_aio_wait(aio2);

	NUTS_PASS(nng_aio_result(aio1));
	NUTS_PASS(nng_aio_result(aio2));

	NUTS_TRUE((s1 = nng_aio_get_output(aio1, 0)) != NULL);
	NUTS_TRUE((s2 = nng_aio_get_output(aio2, 0)) != NULL);

	t1 = nuts_stream_send_start(s1, buf1, size);
	t2 = nuts_stream_recv_start(s2, buf2, size);

	NUTS_PASS(nuts_stream_wait(t1));
	NUTS_PASS(nuts_stream_wait(t2));
	NUTS_TRUE(memcmp(buf1, buf2, size) == 0);

	nng_stream_stop(s1);
	nng_stream_stop(s2);
	nng_stream_dialer_stop(d);
	nng_stream_listener_stop(l);
	nng_stream_free(s1);
	nng_stream_free(s2);
	nng_stream_dialer_free(d);
	nng_stream_listener_free(l);
	nng_tls_config_free(c1);
	nng_tls_config_free(c2);
	nng_aio_free(aio1);
	nng_aio_free(aio2);
	nng_free(buf1, size);
	nng_free(buf2, size);
}

#ifdef NNG_TLS_ENGINE_MBEDTLS
#define NUTS_MBEDTLS_LONG_HOST_NAME_LEN 256

void
test_tls_long_server_name(void)
{
	nng_stream_listener *l;
	nng_stream_dialer   *d;
	nng_aio             *aio1, *aio2;
	nng_stream          *s1;
	nng_tls_config      *c1;
	nng_tls_config      *c2;
	char                 addr[32];
	char                 name[NUTS_MBEDTLS_LONG_HOST_NAME_LEN + 1];
	int                  port;

	NUTS_ENABLE_LOG(NNG_LOG_DEBUG);

	memset(name, 'a', sizeof(name) - 1);
	name[sizeof(name) - 1] = '\0';

	NUTS_PASS(nng_aio_alloc(&aio1, NULL, NULL));
	NUTS_PASS(nng_aio_alloc(&aio2, NULL, NULL));
	nng_aio_set_timeout(aio1, 5000);
	nng_aio_set_timeout(aio2, 5000);

	NUTS_PASS(nng_stream_listener_alloc(&l, "tls+tcp://127.0.0.1:0"));
	NUTS_PASS(nng_tls_config_alloc(&c1, NNG_TLS_MODE_SERVER));
	NUTS_PASS(nng_tls_config_own_cert(
	    c1, nuts_server_crt, nuts_server_key, NULL));
	NUTS_PASS(nng_stream_listener_set_tls(l, c1));
	NUTS_PASS(nng_stream_listener_listen(l));
	NUTS_PASS(nng_stream_listener_get_int(l, NNG_OPT_BOUND_PORT, &port));
	NUTS_TRUE(port > 0);
	NUTS_TRUE(port < 65536);

	snprintf(addr, sizeof(addr), "tls+tcp://127.0.0.1:%d", port);
	NUTS_PASS(nng_stream_dialer_alloc(&d, addr));
	NUTS_PASS(nng_tls_config_alloc(&c2, NNG_TLS_MODE_CLIENT));
	NUTS_PASS(nng_tls_config_auth_mode(c2, NNG_TLS_AUTH_MODE_NONE));
	NUTS_PASS(nng_tls_config_server_name(c2, name));
	NUTS_PASS(nng_stream_dialer_set_tls(d, c2));

	nng_stream_listener_accept(l, aio1);
	nng_stream_dialer_dial(d, aio2);

	nng_aio_wait(aio2);
	NUTS_FAIL(nng_aio_result(aio2), NNG_ECRYPTO);

	nng_aio_wait(aio1);
	if (nng_aio_result(aio1) == NNG_OK) {
		NUTS_TRUE((s1 = nng_aio_get_output(aio1, 0)) != NULL);
		nng_stream_stop(s1);
		nng_stream_free(s1);
	}

	nng_stream_dialer_stop(d);
	nng_stream_listener_stop(l);
	nng_stream_dialer_free(d);
	nng_stream_listener_free(l);
	nng_tls_config_free(c1);
	nng_tls_config_free(c2);
	nng_aio_free(aio1);
	nng_aio_free(aio2);
}
#endif

void
test_tls_no_auth(void)
{
	nng_stream_listener *l;
	nng_stream_dialer   *d;
	nng_aio             *aio1, *aio2;
	nng_stream          *s1;
	nng_stream          *s2;
	nng_tls_config      *c1;
	nng_tls_config      *c2;
	char                 addr[32];
	uint8_t              buf1[8] = { 0, 1, 2, 3, 4, 5, 6, 7 };
	uint8_t              buf2[sizeof(buf1)];
	void                *t1;
	void                *t2;
	int                  port;

	NUTS_ENABLE_LOG(NNG_LOG_DEBUG);

	NUTS_PASS(nng_aio_alloc(&aio1, NULL, NULL));
	NUTS_PASS(nng_aio_alloc(&aio2, NULL, NULL));
	nng_aio_set_timeout(aio1, 5000);
	nng_aio_set_timeout(aio2, 5000);

	NUTS_PASS(nng_stream_listener_alloc(&l, "tls+tcp://127.0.0.1:0"));
	NUTS_PASS(nng_tls_config_alloc(&c1, NNG_TLS_MODE_SERVER));
	NUTS_PASS(nng_tls_config_own_cert(
	    c1, nuts_server_crt, nuts_server_key, NULL));
	NUTS_PASS(nng_stream_listener_set_tls(l, c1));
	NUTS_PASS(nng_stream_listener_listen(l));
	NUTS_PASS(nng_stream_listener_get_int(l, NNG_OPT_BOUND_PORT, &port));
	NUTS_TRUE(port > 0);
	NUTS_TRUE(port < 65536);

	snprintf(addr, sizeof(addr), "tls+tcp://127.0.0.1:%d", port);
	NUTS_PASS(nng_stream_dialer_alloc(&d, addr));
	NUTS_PASS(nng_tls_config_alloc(&c2, NNG_TLS_MODE_CLIENT));
	NUTS_PASS(nng_tls_config_auth_mode(c2, NNG_TLS_AUTH_MODE_NONE));

	NUTS_PASS(nng_stream_dialer_set_tls(d, c2));

	nng_stream_listener_accept(l, aio1);
	nng_stream_dialer_dial(d, aio2);

	nng_aio_wait(aio1);
	nng_aio_wait(aio2);

	NUTS_PASS(nng_aio_result(aio1));
	NUTS_PASS(nng_aio_result(aio2));

	NUTS_TRUE((s1 = nng_aio_get_output(aio1, 0)) != NULL);
	NUTS_TRUE((s2 = nng_aio_get_output(aio2, 0)) != NULL);

	t1 = nuts_stream_send_start(s1, buf1, sizeof(buf1));
	t2 = nuts_stream_recv_start(s2, buf2, sizeof(buf2));

	NUTS_PASS(nuts_stream_wait(t1));
	NUTS_PASS(nuts_stream_wait(t2));
	NUTS_TRUE(memcmp(buf1, buf2, sizeof(buf1)) == 0);

	nng_stream_stop(s1);
	nng_stream_stop(s2);
	nng_stream_dialer_stop(d);
	nng_stream_listener_stop(l);
	nng_stream_free(s1);
	nng_stream_free(s2);
	nng_stream_dialer_free(d);
	nng_stream_listener_free(l);
	nng_tls_config_free(c1);
	nng_tls_config_free(c2);
	nng_aio_free(aio1);
	nng_aio_free(aio2);
}

void
test_tls_garbled_cert(void)
{
	nng_stream_listener *l;
	nng_tls_config      *c1;

	NUTS_ENABLE_LOG(NNG_LOG_INFO);

	// Allocate the listener first.  We use a wild-card port.
	NUTS_PASS(nng_stream_listener_alloc(&l, "tls+tcp://127.0.0.1:0"));
	NUTS_PASS(nng_tls_config_alloc(&c1, NNG_TLS_MODE_SERVER));
	NUTS_FAIL(nng_tls_config_own_cert(
	              c1, nuts_garbled_crt, nuts_server_key, NULL),
	    NNG_ECRYPTO);

	nng_stream_listener_stop(l);
	nng_stream_listener_free(l);
	nng_tls_config_free(c1);
}

void
test_tls_psk(void)
{
	nng_stream_listener *l;
	nng_stream_dialer   *d;
	nng_aio             *aio1, *aio2;
	nng_stream          *s1;
	nng_stream          *s2;
	nng_tls_config      *c1;
	nng_tls_config      *c2;
	char                 addr[32];
	uint8_t              key[32];
	uint8_t             *buf1;
	uint8_t             *buf2;
	size_t               size = 10000;
	void                *t1;
	void                *t2;
	int                  port;

	NUTS_ENABLE_LOG(NNG_LOG_DEBUG);
	// allocate messages
	NUTS_ASSERT((buf1 = nng_alloc(size)) != NULL);
	NUTS_ASSERT((buf2 = nng_alloc(size)) != NULL);

	for (size_t i = 0; i < sizeof(key); i++) {
		key[i] = rand() & 0xff;
	}
	for (size_t i = 0; i < size; i++) {
		buf1[i] = rand() & 0xff;
	}

	NUTS_PASS(nng_aio_alloc(&aio1, NULL, NULL));
	NUTS_PASS(nng_aio_alloc(&aio2, NULL, NULL));
	nng_aio_set_timeout(aio1, 5000);
	nng_aio_set_timeout(aio2, 5000);

	// Allocate the listener first.  We use a wild-card port.
	NUTS_PASS(nng_stream_listener_alloc(&l, "tls+tcp://127.0.0.1:0"));
	NUTS_PASS(nng_tls_config_alloc(&c1, NNG_TLS_MODE_SERVER));
	NUTS_PASS(nng_tls_config_psk(c1, "identity", key, sizeof(key)));
	NUTS_PASS(nng_stream_listener_set_tls(l, c1));
	NUTS_PASS(nng_stream_listener_listen(l));
	NUTS_PASS(nng_stream_listener_get_int(l, NNG_OPT_BOUND_PORT, &port));
	NUTS_TRUE(port > 0);
	NUTS_TRUE(port < 65536);

	snprintf(addr, sizeof(addr), "tls+tcp://127.0.0.1:%d", port);
	NUTS_PASS(nng_stream_dialer_alloc(&d, addr));
	NUTS_PASS(nng_tls_config_alloc(&c2, NNG_TLS_MODE_CLIENT));
	NUTS_PASS(nng_tls_config_psk(c2, "identity", key, sizeof(key)));

	NUTS_PASS(nng_stream_dialer_set_tls(d, c2));

	nng_stream_listener_accept(l, aio1);
	nng_stream_dialer_dial(d, aio2);

	nng_aio_wait(aio1);
	nng_aio_wait(aio2);

	NUTS_PASS(nng_aio_result(aio1));
	NUTS_PASS(nng_aio_result(aio2));

	NUTS_TRUE((s1 = nng_aio_get_output(aio1, 0)) != NULL);
	NUTS_TRUE((s2 = nng_aio_get_output(aio2, 0)) != NULL);

	t1 = nuts_stream_send_start(s1, buf1, size);
	t2 = nuts_stream_recv_start(s2, buf2, size);

	NUTS_PASS(nuts_stream_wait(t1));
	NUTS_PASS(nuts_stream_wait(t2));
	NUTS_TRUE(memcmp(buf1, buf2, size) == 0);

	nng_stream_stop(s1);
	nng_stream_stop(s2);
	nng_stream_dialer_stop(d);
	nng_stream_listener_stop(l);
	nng_stream_free(s1);
	nng_stream_free(s2);
	nng_stream_dialer_free(d);
	nng_stream_listener_free(l);
	nng_tls_config_free(c1);
	nng_tls_config_free(c2);
	nng_aio_free(aio1);
	nng_aio_free(aio2);
	nng_free(buf1, size);
	nng_free(buf2, size);
}

void
test_tls_psk_server_identities(void)
{
	nng_stream_listener *l;
	nng_stream_dialer   *d;
	nng_aio             *aio1, *aio2;
	nng_stream          *s1;
	nng_stream          *s2;
	nng_tls_config      *c1;
	nng_tls_config      *c2;
	char                 addr[32];
	uint8_t             *buf1;
	uint8_t             *buf2;
	size_t               size = 10000;
	void                *t1;
	void                *t2;
	int                  port;
	char                *identity = "test_identity";
	uint8_t              key[32];

	NUTS_ENABLE_LOG(NNG_LOG_INFO);
	// allocate messages
	NUTS_ASSERT((buf1 = nng_alloc(size)) != NULL);
	NUTS_ASSERT((buf2 = nng_alloc(size)) != NULL);

	for (size_t i = 0; i < sizeof(key); i++) {
		key[i] = rand() & 0xff;
	}
	for (size_t i = 0; i < size; i++) {
		buf1[i] = rand() & 0xff;
	}

	NUTS_PASS(nng_aio_alloc(&aio1, NULL, NULL));
	NUTS_PASS(nng_aio_alloc(&aio2, NULL, NULL));
	nng_aio_set_timeout(aio1, 5000);
	nng_aio_set_timeout(aio2, 5000);

	// Allocate the listener first.  We use a wild-card port.
	NUTS_PASS(nng_stream_listener_alloc(&l, "tls+tcp://127.0.0.1:0"));
	NUTS_PASS(nng_tls_config_alloc(&c1, NNG_TLS_MODE_SERVER));
	// Replace the identity .. first write one value, then we change it
	NUTS_PASS(
	    nng_tls_config_psk(c1, "identity2", key + 4, sizeof(key) - 4));
	NUTS_PASS(nng_tls_config_psk(c1, identity, key + 4, sizeof(key) - 4));
	NUTS_PASS(nng_tls_config_psk(c1, identity, key, sizeof(key)));
	NUTS_PASS(nng_stream_listener_set_tls(l, c1));
	NUTS_PASS(nng_stream_listener_listen(l));
	NUTS_PASS(nng_stream_listener_get_int(l, NNG_OPT_BOUND_PORT, &port));
	NUTS_TRUE(port > 0);
	NUTS_TRUE(port < 65536);

	snprintf(addr, sizeof(addr), "tls+tcp://127.0.0.1:%d", port);
	NUTS_PASS(nng_stream_dialer_alloc(&d, addr));
	NUTS_PASS(nng_tls_config_alloc(&c2, NNG_TLS_MODE_CLIENT));
	NUTS_PASS(nng_tls_config_psk(c2, identity, key, sizeof(key)));

	NUTS_PASS(nng_stream_dialer_set_tls(d, c2));

	nng_stream_listener_accept(l, aio1);
	nng_stream_dialer_dial(d, aio2);

	nng_aio_wait(aio1);
	nng_aio_wait(aio2);

	NUTS_PASS(nng_aio_result(aio1));
	NUTS_PASS(nng_aio_result(aio2));

	NUTS_TRUE((s1 = nng_aio_get_output(aio1, 0)) != NULL);
	NUTS_TRUE((s2 = nng_aio_get_output(aio2, 0)) != NULL);

	t1 = nuts_stream_send_start(s1, buf1, size);
	t2 = nuts_stream_recv_start(s2, buf2, size);

	NUTS_PASS(nuts_stream_wait(t1));
	NUTS_PASS(nuts_stream_wait(t2));
	NUTS_TRUE(memcmp(buf1, buf2, size) == 0);

	nng_stream_stop(s1);
	nng_stream_stop(s2);
	nng_stream_dialer_stop(d);
	nng_stream_listener_stop(l);
	nng_stream_free(s1);
	nng_stream_free(s2);
	nng_stream_dialer_free(d);
	nng_stream_listener_free(l);
	nng_tls_config_free(c1);
	nng_tls_config_free(c2);
	nng_aio_free(aio1);
	nng_aio_free(aio2);
	nng_free(buf1, size);
	nng_free(buf2, size);
}

void
test_tls_psk_bad_identity(void)
{
	nng_stream_listener *l;
	nng_stream_dialer   *d;
	nng_aio             *aio1, *aio2;
	nng_stream          *s1;
	nng_stream          *s2;
	nng_tls_config      *c1;
	nng_tls_config      *c2;
	char                 addr[32];
	uint8_t             *buf1;
	uint8_t             *buf2;
	size_t               size = 10000;
	void                *t1;
	void                *t2;
	int                  port;
	uint8_t              key[32];

	NUTS_ENABLE_LOG(NNG_LOG_INFO);
	// allocate messages
	NUTS_ASSERT((buf1 = nng_alloc(size)) != NULL);
	NUTS_ASSERT((buf2 = nng_alloc(size)) != NULL);

	for (size_t i = 0; i < sizeof(key); i++) {
		key[i] = rand() & 0xff;
	}
	for (size_t i = 0; i < size; i++) {
		buf1[i] = rand() & 0xff;
	}

	NUTS_PASS(nng_aio_alloc(&aio1, NULL, NULL));
	NUTS_PASS(nng_aio_alloc(&aio2, NULL, NULL));
	nng_aio_set_timeout(aio1, 5000);
	nng_aio_set_timeout(aio2, 5000);

	// Allocate the listener first.  We use a wild-card port.
	NUTS_PASS(nng_stream_listener_alloc(&l, "tls+tcp://127.0.0.1:0"));
	NUTS_PASS(nng_tls_config_alloc(&c1, NNG_TLS_MODE_SERVER));
	// Replace the identity .. first write one value, then we change it
	NUTS_PASS(nng_tls_config_psk(c1, "identity1", key, sizeof(key)));
	NUTS_PASS(nng_stream_listener_set_tls(l, c1));
	NUTS_PASS(nng_stream_listener_listen(l));
	NUTS_PASS(nng_stream_listener_get_int(l, NNG_OPT_BOUND_PORT, &port));
	NUTS_TRUE(port > 0);
	NUTS_TRUE(port < 65536);

	snprintf(addr, sizeof(addr), "tls+tcp://127.0.0.1:%d", port);
	NUTS_PASS(nng_stream_dialer_alloc(&d, addr));
	NUTS_PASS(nng_tls_config_alloc(&c2, NNG_TLS_MODE_CLIENT));
	NUTS_PASS(nng_tls_config_psk(c2, "identity2", key, sizeof(key)));
	NUTS_PASS(nng_tls_config_server_name(c2, "localhost"));

	NUTS_PASS(nng_stream_dialer_set_tls(d, c2));

	nng_stream_listener_accept(l, aio1);
	nng_stream_dialer_dial(d, aio2);

	nng_aio_wait(aio1);
	nng_aio_wait(aio2);

	NUTS_PASS(nng_aio_result(aio1));
	NUTS_PASS(nng_aio_result(aio2));

	NUTS_TRUE((s1 = nng_aio_get_output(aio1, 0)) != NULL);
	NUTS_TRUE((s2 = nng_aio_get_output(aio2, 0)) != NULL);

	t1 = nuts_stream_send_start(s1, buf1, size);
	t2 = nuts_stream_recv_start(s2, buf2, size);

	// These can fail due to ECRYPTO, EPEERAUTH, or ECONNSHUT, for example
	NUTS_ASSERT(nuts_stream_wait(t1) != 0);
	NUTS_ASSERT(nuts_stream_wait(t2) != 0);

	nng_stream_stop(s1);
	nng_stream_stop(s2);
	nng_stream_dialer_stop(d);
	nng_stream_listener_stop(l);
	nng_stream_free(s1);
	nng_stream_free(s2);
	nng_stream_dialer_free(d);
	nng_stream_listener_free(l);
	nng_tls_config_free(c1);
	nng_tls_config_free(c2);
	nng_aio_free(aio1);
	nng_aio_free(aio2);
	nng_free(buf1, size);
	nng_free(buf2, size);
}

void
test_tls_psk_key_too_big(void)
{
	nng_tls_config *c1;
	uint8_t         key[5000];

	NUTS_ENABLE_LOG(NNG_LOG_INFO);

	// Allocate the listener first.  We use a wild-card port.
	NUTS_PASS(nng_tls_config_alloc(&c1, NNG_TLS_MODE_CLIENT));
	NUTS_FAIL(
	    nng_tls_config_psk(c1, "identity", key, sizeof(key)), NNG_ECRYPTO);
	nng_tls_config_free(c1);
}

void
test_tls_psk_config_busy(void)
{
	nng_tls_config      *c1;
	uint8_t              key[32];
	nng_stream_listener *l;
	nng_aio             *aio;

	nng_aio_alloc(&aio, NULL, NULL);

	NUTS_ENABLE_LOG(NNG_LOG_INFO);

	NUTS_PASS(nng_stream_listener_alloc(&l, "tls+tcp://127.0.0.1:0"));
	NUTS_PASS(nng_tls_config_alloc(&c1, NNG_TLS_MODE_SERVER));
	NUTS_PASS(nng_tls_config_psk(c1, "identity", key, sizeof(key)));
	NUTS_PASS(nng_stream_listener_set_tls(l, c1));
	nng_stream_listener_accept(l, aio);
	nng_msleep(100);
	NUTS_FAIL(
	    nng_tls_config_psk(c1, "identity2", key, sizeof(key)), NNG_EBUSY);

	nng_stream_listener_stop(l);
	nng_stream_listener_free(l);
	nng_aio_free(aio);
	nng_tls_config_free(c1);
}

TEST_LIST = {
	{ "tls close idle BIO", test_tls_close_idle_bio },
	{ "tls pending ciphertext send", test_tls_send_pending },
	{ "tls datagram truncation", test_tls_datagram_truncation },
	{ "tls config version", test_tls_config_version },
	{ "tls config groups", test_tls_config_groups },
	{ "tls groups TLS 1.2", test_tls_groups_tls12 },
	{ "tls groups TLS 1.3", test_tls_groups_tls13 },
	{ "tls groups mismatch", test_tls_groups_mismatch },
	{ "tls groups hybrid", test_tls_groups_hybrid },
	{ "tls groups hybrid mismatch", test_tls_groups_hybrid_mismatch },
	{ "tls groups hybrid P-256", test_tls_groups_hybrid_p256 },
	{ "tls groups hybrid P-384", test_tls_groups_hybrid_p384 },
	{ "tls groups hybrid PSK", test_tls_groups_hybrid_psk },
	{ "tls groups PSK", test_tls_groups_psk },
	{ "tls groups PSK mismatch", test_tls_groups_psk_mismatch },
	{ "tls config single identity", test_tls_config_single_identity },
	{ "tls conn refused", test_tls_conn_refused },
	{ "tls large message", test_tls_large_message },
	{ "tls ecdsa", test_tls_ecdsa },
	{ "tls null server name", test_tls_null_server_name },
#ifdef NNG_TLS_ENGINE_MBEDTLS
	{ "tls long server name", test_tls_long_server_name },
#endif
	{ "tls no auth", test_tls_no_auth },
#ifndef NNG_TLS_ENGINE_WOLFSSL // wolfSSL doesn't validate certas until use
	{ "tls garbled cert", test_tls_garbled_cert },
#endif
#ifdef NNG_SUPP_TLS_PSK
	{ "tls psk", test_tls_psk },
	{ "tls psk server identities", test_tls_psk_server_identities },
	{ "tls psk bad identity", test_tls_psk_bad_identity },
	{ "tls psk key too big", test_tls_psk_key_too_big },
	{ "tls psk key config busy", test_tls_psk_config_busy },
#endif
	{ NULL, NULL },
};
