//
// Copyright 2017 Garrett D'Amore <garrett@damore.org>
// Copyright 2017 Capitar IT Group BV <info@capitar.com>
// Copyright 2017 Staysail Systems, Inc. <info@staysail.tech>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "convey.h"
#include "core/nng_impl.h"
#include "nng.h"
#include "protocol/reqrep0/rep.h"
#include "protocol/reqrep0/req.h"
#include <stdlib.h>
#include <string.h>

// Transport common tests.  By making a common test framework for transports,
// we can avoid rewriting the same tests for each new transport.  Include this
// file once in your test code.  The test framework uses the REQ/REP protocol
// for messaging.
typedef int (*trantest_proptest_t)(nng_msg *, nng_listener, nng_dialer);

typedef struct trantest trantest;

struct trantest {
	const char * tmpl;
	char         addr[NNG_MAXADDRLEN + 1];
	nng_socket   reqsock;
	nng_socket   repsock;
	nni_tran *   tran;
	nng_dialer   dialer;
	nng_listener listener;
	int (*init)(struct trantest *);
	void (*fini)(struct trantest *);
	int (*dialer_init)(struct trantest *);
	int (*listener_init)(struct trantest *);
	int (*proptest)(nng_msg *, nng_listener, nng_dialer);
	void *private; // transport specific private data
};

unsigned trantest_port = 0;

#ifndef NNG_HAVE_ZEROTIER
#define nng_zt_register notransport
#endif
#ifndef NNG_HAVE_INPROC
#define nng_inproc_register notransport
#endif
#ifndef NNG_HAVE_IPC
#define nng_ipc_register notransport
#endif
#ifndef NNG_HAVE_TCP
#define nng_tcp_register notransport
#endif
#ifndef NNG_HAVE_TLS
#define nng_tls_register notransport
#endif
#ifndef NNG_HAVE_WEBSOCKET
#define nng_ws_register notransport
#endif

int
notransport(void)
{
	ConveySkip("Transport not configured");
	return (NNG_ENOTSUP);
}

#define CHKTRAN(s, t)                      \
	if (strncmp(s, t, strlen(t)) == 0) \
	notransport()

void
trantest_checktran(const char *url)
{
#ifndef NNG_HAVE_ZEROTIER
	CHKTRAN(url, "zt:");
#endif
#ifndef NNG_HAVE_INPROC
	CHKTRAN(url, "inproc:");
#endif
#ifndef NNG_HAVE_IPC
	CHKTRAN(url, "ipc:");
#endif
#ifndef NNG_HAVE_TCP
	CHKTRAN(url, "tcp:");
#endif
#ifndef NNG_HAVE_TLS
	CHKTRAN(url, "tls+tcp:");
#endif
#ifndef NNG_HAVE_WEBSOCKET
	CHKTRAN(url, "ws:");
#endif

	(void) url;
}

void
trantest_next_address(char *out, const char *template)
{
	trantest_checktran(template);

	if (trantest_port == 0) {
		char *pstr;

		// start at a different port each time -- 5000 - 10000 --
		// unless a specific port is given.
		trantest_port = nni_clock() % 5000 + 5000;
		if (((pstr = ConveyGetEnv("TEST_PORT")) != NULL) &&
		    (atoi(pstr) != 0)) {
			trantest_port = atoi(pstr);
		}
	}
	(void) snprintf(out, NNG_MAXADDRLEN, template, trantest_port);
	trantest_port++;
}

void
trantest_prev_address(char *out, const char *template)
{
	trantest_port--;
	trantest_next_address(out, template);
}

void
trantest_init(trantest *tt, const char *addr)
{
	trantest_next_address(tt->addr, addr);

#if defined(NNG_HAVE_REQ0) && defined(NNG_HAVE_REP0)
	So(nng_req_open(&tt->reqsock) == 0);
	So(nng_rep_open(&tt->repsock) == 0);

	tt->tran = nni_tran_find(addr);
	So(tt->tran != NULL);
#else
	ConveySkip("Missing REQ or REP protocols");
#endif
}

void
trantest_fini(trantest *tt)
{
	nng_close(tt->reqsock);
	nng_close(tt->repsock);
}

int
trantest_dial(trantest *tt)
{
	So(nng_dialer_create(&tt->dialer, tt->reqsock, tt->addr) == 0);
	if (tt->dialer_init != NULL) {
		So(tt->dialer_init(tt) == 0);
	}
	return (nng_dialer_start(tt->dialer, 0));
}

void
trantest_scheme(trantest *tt)
{
	Convey("Scheme is correct", {
		size_t l = strlen(tt->tran->tran_scheme);
		So(strncmp(tt->addr, tt->tran->tran_scheme, l) == 0);
		So(strncmp(tt->addr + l, "://", 3) == 0);
	})
}

void
trantest_conn_refused(trantest *tt)
{
	Convey("Connection refused works", {
		nng_dialer d = 0;

		So(nng_dial(tt->reqsock, tt->addr, &d, 0) == NNG_ECONNREFUSED);
		So(d == 0);
		So(nng_dial(tt->repsock, tt->addr, &d, 0) == NNG_ECONNREFUSED);
		So(d == 0);
	})
}

void
trantest_duplicate_listen(trantest *tt)
{
	Convey("Duplicate listen rejected", {
		nng_listener l;
		int          rv;
		rv = nng_listen(tt->repsock, tt->addr, &l, 0);
		So(rv == 0);
		So(l != 0);
		l = 0;
		So(nng_listen(tt->repsock, tt->addr, &l, 0) == NNG_EADDRINUSE);
		So(l == 0);
	})
}

void
trantest_listen_accept(trantest *tt)
{
	Convey("Listen and accept", {
		nng_listener l;
		nng_dialer   d;
		So(nng_listen(tt->repsock, tt->addr, &l, 0) == 0);
		So(l != 0);

		d = 0;
		So(nng_dial(tt->reqsock, tt->addr, &d, 0) == 0);
		So(d != 0);
	})
}

void
trantest_send_recv(trantest *tt)
{
	Convey("Send and recv", {
		nng_listener l;
		nng_msg *    send;
		nng_msg *    recv;
		size_t       len;
		nng_pipe     p;
		char         url[NNG_MAXADDRLEN];
		size_t       sz;

		So(nng_listen(tt->repsock, tt->addr, &l, 0) == 0);
		So(l != 0);
		So(trantest_dial(tt) == 0);

		nng_msleep(200); // listener may be behind slightly

		send = NULL;
		So(nng_msg_alloc(&send, 0) == 0);
		So(send != NULL);
		So(nng_msg_append(send, "ping", 5) == 0);

		So(nng_sendmsg(tt->reqsock, send, 0) == 0);
		recv = NULL;
		So(nng_recvmsg(tt->repsock, &recv, 0) == 0);
		So(recv != NULL);
		So(nng_msg_len(recv) == 5);
		So(strcmp(nng_msg_body(recv), "ping") == 0);
		nng_msg_free(recv);

		len = strlen("acknowledge");
		So(nng_msg_alloc(&send, 0) == 0);
		So(nng_msg_append(send, "acknowledge", len) == 0);
		So(nng_sendmsg(tt->repsock, send, 0) == 0);
		So(nng_recvmsg(tt->reqsock, &recv, 0) == 0);
		So(recv != NULL);
		So(nng_msg_len(recv) == strlen("acknowledge"));
		So(strcmp(nng_msg_body(recv), "acknowledge") == 0);
		p = nng_msg_get_pipe(recv);
		So(p != 0);
		sz = sizeof(url);
		So(nng_pipe_getopt(p, NNG_OPT_URL, url, &sz) == 0);
		So(strcmp(url, tt->addr) == 0);
		nng_msg_free(recv);
	});
}

void
trantest_check_properties(trantest *tt, trantest_proptest_t f)
{
	Convey("Properties test", {
		nng_listener l;
		nng_dialer   d;
		nng_msg *    send;
		nng_msg *    recv;
		int          rv;

		So(nng_listen(tt->repsock, tt->addr, &l, 0) == 0);
		So(l != 0);
		So(nng_dial(tt->reqsock, tt->addr, &d, 0) == 0);
		So(d != 0);

		nng_msleep(200); // listener may be behind slightly

		send = NULL;
		So(nng_msg_alloc(&send, 0) == 0);
		So(send != NULL);
		So(nng_msg_append(send, "props", 5) == 0);

		So(nng_sendmsg(tt->reqsock, send, 0) == 0);
		recv = NULL;
		So(nng_recvmsg(tt->repsock, &recv, 0) == 0);
		So(recv != NULL);
		So(nng_msg_len(recv) == 5);
		So(strcmp(nng_msg_body(recv), "props") == 0);
		rv = f(recv, l, d);
		nng_msg_free(recv);
		So(rv == 0);
	});
}

void
trantest_send_recv_large(trantest *tt)
{
	Convey("Send and recv large data", {
		nng_listener l;
		nng_dialer   d;
		nng_msg *    send;
		nng_msg *    recv;
		char *       data;
		size_t       size;

		size = 1024 * 128; // bigger than any transport segment
		So((data = nng_alloc(size)) != NULL);

		for (int i = 0; (size_t) i < size; i++) {
			data[i] = nni_random() & 0xff;
		}

		So(nng_listen(tt->repsock, tt->addr, &l, 0) == 0);
		So(l != 0);
		So(nng_dial(tt->reqsock, tt->addr, &d, 0) == 0);
		So(d != 0);

		nng_msleep(200); // listener may be behind slightly

		send = NULL;
		So(nng_msg_alloc(&send, size) == 0);
		So(send != NULL);
		memcpy(nng_msg_body(send), data, size);

		So(nng_sendmsg(tt->reqsock, send, 0) == 0);
		recv = NULL;
		So(nng_recvmsg(tt->repsock, &recv, 0) == 0);
		So(recv != NULL);
		So(nng_msg_len(recv) == size);
		So(memcmp(nng_msg_body(recv), data, size) == 0);
		nng_msg_free(recv);

		memset(data, 0x2, size);

		So(nng_msg_alloc(&send, 0) == 0);
		So(nng_msg_append(send, data, size) == 0);
		So(nng_sendmsg(tt->repsock, send, 0) == 0);
		So(nng_recvmsg(tt->reqsock, &recv, 0) == 0);
		So(recv != NULL);
		So(nng_msg_len(recv) == size);
		So(memcmp(nng_msg_body(recv), data, size) == 0);
		nng_msg_free(recv);

		nng_free(data, size);
	})
}

void
trantest_test_all(const char *addr)
{
	trantest tt;

	memset(&tt, 0, sizeof(tt));
	Convey("Given transport", {
		trantest_init(&tt, addr);

		Reset({ trantest_fini(&tt); });

		trantest_scheme(&tt);
		trantest_conn_refused(&tt);
		trantest_duplicate_listen(&tt);
		trantest_listen_accept(&tt);
		trantest_send_recv(&tt);
		trantest_send_recv_large(&tt);
	})
}

void
trantest_test_extended(const char *addr, trantest_proptest_t f)
{
	trantest tt;

	memset(&tt, 0, sizeof(tt));
	Convey("Given transport", {
		trantest_init(&tt, addr);

		Reset({ trantest_fini(&tt); });

		trantest_scheme(&tt);
		trantest_conn_refused(&tt);
		trantest_duplicate_listen(&tt);
		trantest_listen_accept(&tt);
		trantest_send_recv(&tt);
		trantest_send_recv_large(&tt);
		trantest_check_properties(&tt, f);
	})
}

void
trantest_test(trantest *tt)
{
	Convey("Given transport", {
		trantest_init(tt, tt->tmpl);
		if (tt->init != NULL) {
			So(tt->init(tt) == 0);
		}

		Reset({
			if (tt->fini != NULL) {
				tt->fini(tt);
			}
			trantest_fini(tt);
		});

		trantest_scheme(tt);

		trantest_conn_refused(tt);
		trantest_duplicate_listen(tt);
		trantest_listen_accept(tt);

		trantest_send_recv(tt);
		trantest_send_recv_large(tt);
		if (tt->proptest != NULL) {
			trantest_check_properties(tt, tt->proptest);
		}
	})
}
