// Copyright 2026 Staysail Systems, Inc. <info@staysail.tech>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt). A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.

#include "../../../testing/nuts.h"

// Exercise the transport over its actual wire format, rather than hiding
// malformed packets and connection-management loss behind another NNG peer.
enum {
	WIRE_DATA     = 0,
	WIRE_CREQ     = 1,
	WIRE_CACK     = 2,
	WIRE_DISC     = 3,
	DISC_TYPE     = 1,
	DISC_MSGSIZE  = 4,
	DISC_NEGO     = 5,
	DISC_INACTIVE = 6,
	DISC_PROTO    = 7,
	DISC_NOBUF    = 8,
	WIRE_HEADER   = 8,
	WIRE_TIMEOUT  = 3000,
};

typedef struct {
	nng_udp     *udp;
	nng_aio     *send;
	nng_aio     *recv;
	nng_sockaddr addr;
	nng_sockaddr from;
	uint8_t      packet[256];
	size_t       len;
} wire_peer;

typedef struct {
	nng_mtx     *mtx;
	nng_cv      *cv;
	nng_listener listener;
	unsigned     added;
	unsigned     removed;
} wire_events;

static nng_sockaddr
wire_addr(unsigned port)
{
	nng_sockaddr sa   = { 0 };
	sa.s_in.sa_family = NNG_AF_INET;
	sa.s_in.sa_addr   = nuts_be32(0x7f000001);
	sa.s_in.sa_port   = nuts_be16((uint16_t) port);
	return (sa);
}

static uint16_t
wire_get16(const uint8_t *p)
{
	return ((uint16_t) (p[0] | ((uint16_t) p[1] << 8)));
}

static void
wire_header(
    uint8_t *p, unsigned op, unsigned proto, unsigned param, unsigned refresh)
{
	p[0] = 1;
	p[1] = (uint8_t) op;
	p[2] = (uint8_t) proto;
	p[3] = (uint8_t) (proto >> 8);
	p[4] = (uint8_t) param;
	p[5] = (uint8_t) (param >> 8);
	p[6] = (uint8_t) refresh;
	p[7] = (uint8_t) (refresh >> 8);
}

static void
wire_open(wire_peer *p)
{
	memset(p, 0, sizeof(*p));
	p->addr = wire_addr(0);
	NUTS_PASS(nng_udp_open(&p->udp, &p->addr));
	NUTS_PASS(nng_udp_sockname(p->udp, &p->addr));
	NUTS_PASS(nng_aio_alloc(&p->send, NULL, NULL));
	NUTS_PASS(nng_aio_alloc(&p->recv, NULL, NULL));
	nng_aio_set_timeout(p->send, WIRE_TIMEOUT);
}

static void
wire_close(wire_peer *p)
{
	nng_udp_close(p->udp);
	nng_aio_free(p->send);
	nng_aio_free(p->recv);
}

static void
wire_send(wire_peer *p, const nng_sockaddr *to, void *buf, size_t len)
{
	nng_sockaddr dest = *to;
	nng_iov      iov  = { .iov_buf = buf, .iov_len = len };
	NUTS_PASS(nng_aio_set_iov(p->send, 1, &iov));
	NUTS_PASS(nng_aio_set_input(p->send, 0, &dest));
	nng_udp_send(p->udp, p->send);
	nng_aio_wait(p->send);
	NUTS_PASS(nng_aio_result(p->send));
}

static int
wire_recv(wire_peer *p, nng_duration timeout)
{
	nng_iov iov = { .iov_buf = p->packet, .iov_len = sizeof(p->packet) };
	memset(p->packet, 0, sizeof(p->packet));
	nng_aio_set_timeout(p->recv, timeout);
	NUTS_PASS(nng_aio_set_iov(p->recv, 1, &iov));
	NUTS_PASS(nng_aio_set_input(p->recv, 0, &p->from));
	nng_udp_recv(p->udp, p->recv);
	nng_aio_wait(p->recv);
	p->len = nng_aio_count(p->recv);
	return (nng_aio_result(p->recv));
}

static bool
wire_expect(wire_peer *p, const nng_sockaddr *from, unsigned op,
    unsigned param, nng_duration timeout)
{
	int rv = wire_recv(p, timeout);
	NUTS_TRUE(rv == NNG_OK);
	NUTS_MSG("expected UDP response, got %s (%d)", nng_strerror(rv), rv);
	if (rv != NNG_OK) {
		return (false);
	}
	NUTS_TRUE(p->len == WIRE_HEADER);
	NUTS_TRUE(nng_sockaddr_equal(&p->from, from));
	NUTS_TRUE(p->packet[0] == 1);
	NUTS_TRUE(p->packet[1] == op);
	NUTS_TRUE(wire_get16(p->packet + 4) == param);
	return (p->len == WIRE_HEADER && p->packet[1] == op);
}

static void
wire_event(nng_pipe pipe, nng_pipe_ev ev, void *arg)
{
	wire_events *events = arg;
	(void) pipe;
	nng_mtx_lock(events->mtx);
	if (ev == NNG_PIPE_EV_ADD_POST) {
		events->added++;
	} else if (ev == NNG_PIPE_EV_REM_POST) {
		events->removed++;
	}
	nng_cv_wake(events->cv);
	nng_mtx_unlock(events->mtx);
}

static void
wire_events_init(wire_events *events, nng_socket s)
{
	memset(events, 0, sizeof(*events));
	NUTS_PASS(nng_mtx_alloc(&events->mtx));
	NUTS_PASS(nng_cv_alloc(&events->cv, events->mtx));
	NUTS_PASS(
	    nng_pipe_notify(s, NNG_PIPE_EV_ADD_POST, wire_event, events));
	NUTS_PASS(
	    nng_pipe_notify(s, NNG_PIPE_EV_REM_POST, wire_event, events));
}

static void
wire_events_fini(wire_events *events)
{
	// The socket must be closed first, so no callbacks retain this object.
	nng_cv_free(events->cv);
	nng_mtx_free(events->mtx);
}

static void
wire_wait(wire_events *events, unsigned added, unsigned removed)
{
	nng_time deadline = nng_clock() + WIRE_TIMEOUT;
	nng_mtx_lock(events->mtx);
	while (events->added < added || events->removed < removed) {
		if (nng_cv_until(events->cv, deadline) != NNG_OK) {
			break;
		}
	}
	NUTS_TRUE(events->added == added);
	NUTS_TRUE(events->removed == removed);
	nng_mtx_unlock(events->mtx);
}

static nng_sockaddr
wire_listen(nng_socket *s, wire_events *events, size_t max_peers)
{
	nng_listener l;
	int          port;
	NUTS_PASS(nng_pull0_open(s));
	NUTS_PASS(nng_socket_set_ms(*s, NNG_OPT_RECVTIMEO, WIRE_TIMEOUT));
	wire_events_init(events, *s);
	NUTS_PASS(nng_listener_create(&l, *s, "udp4://127.0.0.1:0"));
	events->listener = l;
	NUTS_PASS(nng_listener_set_size(l, NNG_OPT_RECVMAXSZ, 64));
	NUTS_PASS(nng_listener_set_size(l, NNG_OPT_UDP_MAX_PEERS, max_peers));
	NUTS_PASS(nng_listener_start(l, 0));
	NUTS_PASS(nng_listener_get_int(l, NNG_OPT_BOUND_PORT, &port));
	return (wire_addr((unsigned) port));
}

static void
wire_connect(wire_peer *p, const nng_sockaddr *server)
{
	uint8_t packet[WIRE_HEADER];
	wire_header(packet, WIRE_CREQ, NUTS_PROTO(5, 0), 64, 1);
	wire_send(p, server, packet, sizeof(packet));
	if (wire_expect(p, server, WIRE_CACK, 64, WIRE_TIMEOUT)) {
		NUTS_TRUE(wire_get16(p->packet + 2) == NUTS_PROTO(5, 1));
		NUTS_TRUE(wire_get16(p->packet + 6) == 1);
	}
}

static void
test_udp_wire_bad_headers(void)
{
	nng_socket   s;
	wire_events  events;
	wire_peer    p;
	nng_sockaddr server = wire_listen(&s, &events, 1);
	uint8_t      packet[WIRE_HEADER];
	wire_open(&p);
	wire_header(packet, WIRE_CREQ, NUTS_PROTO(5, 0), 64, 1);
	for (size_t len = 0; len < WIRE_HEADER; len++) {
		wire_send(&p, &server, packet, len);
	}
	packet[0] = 2; // unsupported wire version
	wire_send(&p, &server, packet, sizeof(packet));
	wire_header(packet, 255, NUTS_PROTO(5, 0), 0, 0);
	wire_send(&p, &server, packet, sizeof(packet));
	wire_expect(&p, &server, WIRE_DISC, DISC_PROTO, WIRE_TIMEOUT);
	wire_header(packet, WIRE_CREQ, NUTS_PROTO(5, 0), 64, 0);
	wire_send(&p, &server, packet, sizeof(packet));
	wire_expect(&p, &server, WIRE_DISC, DISC_NEGO, WIRE_TIMEOUT);
	// Invalid packets must neither consume the sole peer slot nor poison
	// RX.
	wire_connect(&p, &server);
	wire_wait(&events, 1, 0);
	// A repeated connection request must not allocate another pipe.
	wire_connect(&p, &server);
	wire_wait(&events, 1, 0);
	NUTS_CLOSE(s);
	wire_close(&p);
	wire_events_fini(&events);
}

static void
test_udp_wire_data_lengths(void)
{
	nng_socket     s;
	wire_events    events;
	nng_sockaddr   server    = wire_listen(&s, &events, 0);
	const unsigned lengths[] = { 16, 65 };
	uint8_t        packet[WIRE_HEADER + 8];
	for (unsigned i = 0; i < 2; i++) {
		wire_peer p;
		wire_open(&p);
		wire_connect(&p, &server);
		wire_wait(&events, i + 1, i);
		// Declared length exceeds the actual payload, or the receive
		// limit.
		wire_header(
		    packet, WIRE_DATA, NUTS_PROTO(5, 0), lengths[i], 0);
		memset(packet + WIRE_HEADER, 0, 8);
		wire_send(&p, &server, packet, sizeof(packet));
		wire_expect(
		    &p, &server, WIRE_DISC, DISC_MSGSIZE, WIRE_TIMEOUT);
		wire_wait(&events, i + 1, i + 1);
		wire_close(&p);
	}
	wire_peer p;
	wire_open(&p);
	wire_connect(&p, &server);
	wire_wait(&events, 3, 2);
	// Undeclared trailing bytes must not leak into the application
	// message.
	wire_header(packet, WIRE_DATA, NUTS_PROTO(5, 0), 3, 0);
	memcpy(packet + WIRE_HEADER, "ok\0extra", 8);
	wire_send(&p, &server, packet, sizeof(packet));
	NUTS_RECV(s, "ok");
	NUTS_PASS(nng_socket_set_ms(s, NNG_OPT_RECVTIMEO, 100));
	char   buf[16];
	size_t len = sizeof(buf);
	NUTS_FAIL(nng_recv(s, buf, &len, 0), NNG_ETIMEDOUT);
	NUTS_CLOSE(s);
	wire_close(&p);
	wire_events_fini(&events);
}

static void
test_udp_wire_bad_refresh_type(void)
{
	nng_socket   s;
	wire_events  events;
	nng_sockaddr server = wire_listen(&s, &events, 0);
	uint8_t      packet[WIRE_HEADER];
	for (unsigned i = 0; i < 2; i++) {
		wire_peer p;
		wire_open(&p);
		wire_connect(&p, &server);
		wire_wait(&events, i + 1, i);
		wire_header(packet, WIRE_CREQ,
		    i == 0 ? NUTS_PROTO(5, 0) : NUTS_PROTO(1, 1), 64,
		    i == 0 ? 0 : 1);
		wire_send(&p, &server, packet, sizeof(packet));
		wire_expect(&p, &server, WIRE_DISC,
		    i == 0 ? DISC_NEGO : DISC_TYPE, WIRE_TIMEOUT);
		wire_wait(&events, i + 1, i + 1);
		wire_close(&p);
	}
	NUTS_CLOSE(s);
	wire_events_fini(&events);
}

static void
test_udp_wire_handshake_loss(void)
{
	nng_socket   server_socket, client;
	wire_events  server_events, client_events;
	nng_sockaddr server = wire_listen(&server_socket, &server_events, 1);
	nng_sockaddr client_addr = { 0 };
	wire_peer    proxy;
	nng_dialer   dialer;
	char         url[80];
	unsigned     requests = 0, acknowledgments = 0;
	bool         connected = false;
	wire_open(&proxy);
	NUTS_PASS(nng_push0_open(&client));
	NUTS_PASS(nng_socket_set_ms(client, NNG_OPT_SENDTIMEO, WIRE_TIMEOUT));
	wire_events_init(&client_events, client);
	snprintf(url, sizeof(url), "udp4://127.0.0.1:%u",
	    (unsigned) nuts_be16(proxy.addr.s_in.sa_port));
	NUTS_PASS(nng_dialer_create(&dialer, client, url));
	NUTS_PASS(nng_dialer_set_ms(dialer, NNG_OPT_UDP_CONN_RETRY, 100));
	NUTS_PASS(nng_dialer_set_ms(dialer, NNG_OPT_UDP_CONN_EXPIRE, 10000));
	NUTS_PASS(nng_dialer_start(dialer, NNG_FLAG_NONBLOCK));
	for (unsigned i = 0; i < 20 && !connected; i++) {
		NUTS_ASSERT(wire_recv(&proxy, WIRE_TIMEOUT) == NNG_OK);
		NUTS_ASSERT(proxy.len == WIRE_HEADER);
		if (nng_sockaddr_equal(&proxy.from, &server)) {
			NUTS_ASSERT(proxy.packet[1] == WIRE_CACK);
			acknowledgments++;
			if (acknowledgments == 1) {
				continue; // drop the first server
				          // acknowledgment
			}
			wire_send(
			    &proxy, &client_addr, proxy.packet, proxy.len);
			connected = true;
		} else {
			NUTS_ASSERT(proxy.packet[1] == WIRE_CREQ);
			client_addr = proxy.from;
			requests++;
			if (requests == 1) {
				continue; // drop the first client connection
				          // request
			}
			wire_send(&proxy, &server, proxy.packet, proxy.len);
		}
	}
	NUTS_TRUE(connected);
	NUTS_TRUE(requests >= 3);
	NUTS_TRUE(acknowledgments >= 2);
	wire_wait(&server_events, 1, 0);
	wire_wait(&client_events, 1, 0);
	NUTS_SEND(client, "loss recovery");
	NUTS_PASS(wire_recv(&proxy, WIRE_TIMEOUT));
	NUTS_TRUE(proxy.packet[1] == WIRE_DATA);
	wire_send(&proxy, &server, proxy.packet, proxy.len);
	NUTS_RECV(server_socket, "loss recovery");
	NUTS_CLOSE(client);
	NUTS_CLOSE(server_socket);
	wire_close(&proxy);
	wire_events_fini(&client_events);
	wire_events_fini(&server_events);
}

static void
wire_handshake_timeout(nng_duration retry, nng_duration expire)
{
	wire_peer  peer;
	nng_socket client;
	nng_dialer dialer;
	char       url[80];
	wire_open(&peer);
	NUTS_PASS(nng_push0_open(&client));
	snprintf(url, sizeof(url), "udp4://127.0.0.1:%u",
	    (unsigned) nuts_be16(peer.addr.s_in.sa_port));
	NUTS_PASS(nng_dialer_create(&dialer, client, url));
	NUTS_PASS(nng_dialer_set_ms(dialer, NNG_OPT_UDP_CONN_RETRY, retry));
	NUTS_PASS(nng_dialer_set_ms(dialer, NNG_OPT_UDP_CONN_EXPIRE, expire));
	uint64_t start = nuts_clock();
	// An open but silent UDP port avoids platform-dependent ICMP errors.
	NUTS_FAIL(nng_dialer_start(dialer, 0), NNG_ETIMEDOUT);
	NUTS_AFTER(start + expire);
	NUTS_BEFORE(start + expire + 1500);
	for (unsigned i = 0; i < (retry < expire ? 2u : 1u); i++) {
		NUTS_PASS(wire_recv(&peer, WIRE_TIMEOUT));
		NUTS_TRUE(peer.len == WIRE_HEADER);
		NUTS_TRUE(peer.packet[1] == WIRE_CREQ);
	}
	NUTS_CLOSE(client);
	wire_close(&peer);
}

static void
test_udp_wire_handshake_timeout(void)
{
	wire_handshake_timeout(50, 500);
}

static void
test_udp_wire_expiry_before_retry(void)
{
	wire_handshake_timeout(3000, 100);
}

static void
test_udp_wire_negotiated_refresh(void)
{
	wire_peer   peer;
	wire_events events;
	nng_socket  client;
	nng_dialer  dialer;
	char        url[80];
	uint8_t     header[WIRE_HEADER];
	wire_open(&peer);
	NUTS_PASS(nng_push0_open(&client));
	wire_events_init(&events, client);
	snprintf(url, sizeof(url), "udp4://127.0.0.1:%u",
	    (unsigned) nuts_be16(peer.addr.s_in.sa_port));
	NUTS_PASS(nng_dialer_create(&dialer, client, url));
	NUTS_PASS(nng_dialer_set_ms(dialer, NNG_OPT_UDP_CONN_RETRY, 5000));
	NUTS_PASS(nng_dialer_set_size(dialer, NNG_OPT_RECVMAXSZ, 64));
	NUTS_PASS(nng_dialer_start(dialer, NNG_FLAG_NONBLOCK));
	NUTS_PASS(wire_recv(&peer, WIRE_TIMEOUT));
	NUTS_TRUE(peer.len == WIRE_HEADER);
	NUTS_TRUE(peer.packet[1] == WIRE_CREQ);
	NUTS_TRUE(wire_get16(peer.packet + 6) == 5);
	nng_sockaddr client_addr = peer.from;
	// Negotiating a shorter interval must advance the next CREQ deadline,
	// not leave a wake-up scheduled before the old retry deadline.
	wire_header(header, WIRE_CACK, 0x51, 64, 1);
	wire_send(&peer, &client_addr, header, sizeof(header));
	wire_wait(&events, 1, 0);
	wire_expect(&peer, &client_addr, WIRE_CREQ, 64, WIRE_TIMEOUT);
	NUTS_TRUE(wire_get16(peer.packet + 6) == 1);
	NUTS_CLOSE(client);
	wire_close(&peer);
	wire_events_fini(&events);
}

static void
wire_expiry(bool refresh)
{
	nng_socket   s;
	wire_events  events;
	nng_sockaddr server = wire_listen(&s, &events, 1);
	wire_peer    p, replacement;
	wire_open(&p);
	wire_open(&replacement);
	uint64_t start = nuts_clock();
	wire_connect(&p, &server);
	wire_wait(&events, 1, 0);
	if (refresh) {
		// Exercise the established-peer keep-alive branch as well.
		wire_connect(&p, &server);
	}
	// No graceful disconnect, DATA, or further keep-alives from this peer.
	// Refresh is one second, and the transport expires after five
	// intervals.
	if (wire_expect(&p, &server, WIRE_DISC, DISC_INACTIVE, 10000)) {
		NUTS_AFTER(start + 5000);
		wire_wait(&events, 1, 1);
#ifdef NNG_ENABLE_STATS
		nng_stat       *stats;
		const nng_stat *listener, *wakes;
		NUTS_PASS(nng_stats_get(&stats));
		NUTS_ASSERT((listener = nng_stat_find_listener(
		                 stats, events.listener)) != NULL);
		NUTS_ASSERT(
		    (wakes = nng_stat_find(listener, "timer_wakes")) != NULL);
		// A silent listener only needs to wake to reschedule or
		// expire. Allow scheduling slack, but not a loop on an elapsed
		// deadline.
		uint64_t count = nng_stat_value(wakes);
		NUTS_TRUE(count <= 16);
		NUTS_MSG("listener timer woke %llu times",
		    (unsigned long long) count);
		nng_stats_free(stats);
#endif
		// Reaping must return the sole admission slot to a different
		// address.
		wire_connect(&replacement, &server);
		wire_wait(&events, 2, 1);
	}
	NUTS_CLOSE(s);
	wire_close(&p);
	wire_close(&replacement);
	wire_events_fini(&events);
}

static void
test_udp_wire_initial_expiry(void)
{
	wire_expiry(false);
}

static void
test_udp_wire_refreshed_expiry(void)
{
	wire_expiry(true);
}

NUTS_TESTS = {
	{ "udp wire bad headers", test_udp_wire_bad_headers },
	{ "udp wire data lengths", test_udp_wire_data_lengths },
	{ "udp wire bad refresh and type", test_udp_wire_bad_refresh_type },
	{ "udp wire handshake loss", test_udp_wire_handshake_loss },
	{ "udp wire handshake timeout", test_udp_wire_handshake_timeout },
	{ "udp wire expiry before retry", test_udp_wire_expiry_before_retry },
	{ "udp wire negotiated refresh", test_udp_wire_negotiated_refresh },
	{ "udp wire initial expiry", test_udp_wire_initial_expiry },
	{ "udp wire refreshed expiry", test_udp_wire_refreshed_expiry },
	{ NULL, NULL },
};
