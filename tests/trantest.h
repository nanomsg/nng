//
// Copyright 2019 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <stdlib.h>
#include <string.h>

#include <nng/nng.h>
#include <nng/protocol/reqrep0/rep.h>
#include <nng/protocol/reqrep0/req.h>
#include <nng/supplemental/util/platform.h>

#include "convey.h"
#include "core/nng_impl.h"

// Transport common tests.  By making a common test framework for transports,
// we can avoid rewriting the same tests for each new transport.  Include this
// file once in your test code.  The test framework uses the REQ/REP protocol
// for messaging.
typedef int (*trantest_proptest_t)(nng_msg *);

typedef struct trantest trantest;

struct trantest {
	const char *tmpl;
	char        addr[NNG_MAXADDRLEN + 1];
	nng_socket  reqsock;
	nng_socket  repsock;
	nni_tran *  tran;
	int (*init)(struct trantest *);
	void (*fini)(struct trantest *);
	int (*dialer_init)(nng_dialer);
	int (*listener_init)(nng_listener);
	int (*proptest)(nng_msg *);
	void *private; // transport specific private data
};

unsigned trantest_port = 0;

extern int  notransport(void);
extern void trantest_checktran(const char *url);
extern void trantest_next_address(char *out, const char *template);
extern void trantest_prev_address(char *out, const char *template);
extern void trantest_init(trantest *tt, const char *addr);
extern int  trantest_dial(trantest *tt, nng_dialer *dp);
extern int  trantest_listen(trantest *tt, nng_listener *lp);
extern void trantest_scheme(trantest *tt);
extern void trantest_test(trantest *tt);
extern void trantest_test_extended(const char *addr, trantest_proptest_t f);
extern void trantest_test_all(const char *addr);

#ifndef NNG_TRANSPORT_ZEROTIER
#define nng_zt_register notransport
#endif
#ifndef NNG_TRANSPORT_WSS
#define nng_wss_register notransport
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
#ifndef NNG_TRANSPORT_WSS
	CHKTRAN(url, "wss:");
#endif
#ifndef NNG_TRANSPORT_ZEROTIER
	CHKTRAN(url, "zt:");
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
		trantest_port = nng_clock() % 5000 + 5000;
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

	So(nng_req_open(&tt->reqsock) == 0);
	So(nng_rep_open(&tt->repsock) == 0);

	nng_url *url;
	So(nng_url_parse(&url, tt->addr) == 0);
	tt->tran = nni_tran_find(url);
	So(tt->tran != NULL);
	nng_url_free(url);
}

void
trantest_fini(trantest *tt)
{
	nng_close(tt->reqsock);
	nng_close(tt->repsock);
}

int
trantest_dial(trantest *tt, nng_dialer *dp)
{
	nng_dialer d = NNG_DIALER_INITIALIZER;
	int        rv;

	rv = nng_dialer_create(&d, tt->reqsock, tt->addr);
	if (rv != 0) {
		return (rv);
	}
	if (tt->dialer_init != NULL) {
		if ((rv = tt->dialer_init(d)) != 0) {
			nng_dialer_close(d);
			return (rv);
		}
	}
	if ((rv = nng_dialer_start(d, 0)) != 0) {
		nng_dialer_close(d);
		return (rv);
	}
	*dp = d;
	return (0);
}

int
trantest_listen(trantest *tt, nng_listener *lp)
{
	int          rv;
	nng_listener l = NNG_LISTENER_INITIALIZER;

	rv = nng_listener_create(&l, tt->repsock, tt->addr);
	if (rv != 0) {
		return (rv);
	}
	if (tt->listener_init != NULL) {
		if ((rv = tt->listener_init(l)) != 0) {
			nng_listener_close(l);
			return (rv);
		}
	}
	if ((rv = nng_listener_start(l, 0)) != 0) {
		nng_listener_close(l);
		return (rv);
	}
	*lp = l;
	return (rv);
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
		nng_dialer d = NNG_DIALER_INITIALIZER;

		So(trantest_dial(tt, &d) == NNG_ECONNREFUSED);
		So(nng_dialer_id(d) < 0);
		So(trantest_dial(tt, &d) == NNG_ECONNREFUSED);
		So(nng_dialer_id(d) < 0);
	});
}

void
trantest_duplicate_listen(trantest *tt)
{
	Convey("Duplicate listen rejected", {
		nng_listener l1 = NNG_LISTENER_INITIALIZER;
		nng_listener l2 = NNG_LISTENER_INITIALIZER;
		int          rv;
		rv = trantest_listen(tt, &l1);
		So(rv == 0);
		So(nng_listener_id(l1) > 0);
		So(trantest_listen(tt, &l2) == NNG_EADDRINUSE);
		So(nng_listener_id(l2) < 0);
		So(nng_listener_id(l1) != nng_listener_id(l2));
	});
}

void
trantest_listen_accept(trantest *tt)
{
	Convey("Listen and accept", {
		nng_listener l  = NNG_LISTENER_INITIALIZER;
		nng_dialer   d  = NNG_DIALER_INITIALIZER;
		nng_dialer   d0 = NNG_DIALER_INITIALIZER;
		So(trantest_listen(tt, &l) == 0);
		So(nng_listener_id(l) > 0);

		nng_msleep(200);
		So(trantest_dial(tt, &d) == 0);
		So(nng_dialer_id(d) > 0);
		So(nng_dialer_id(d0) < 0);
	});
}

void
trantest_send_recv(trantest *tt)
{
	Convey("Send and recv", {
		nng_listener l = NNG_LISTENER_INITIALIZER;
		nng_dialer   d = NNG_DIALER_INITIALIZER;
		nng_pipe     p = NNG_PIPE_INITIALIZER;
		nng_msg *    send;
		nng_msg *    recv;
		size_t       len;
		char *       url;

		So(trantest_listen(tt, &l) == 0);
		So(nng_listener_id(l) > 0);

		So(trantest_dial(tt, &d) == 0);
		So(nng_dialer_id(d) > 0);

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
		So(nng_pipe_id(p) > 0);
		So(nng_pipe_getopt_string(p, NNG_OPT_URL, &url) == 0);
		So(strcmp(url, tt->addr) == 0);
		nng_strfree(url);
		nng_msg_free(recv);
	});
}

void
trantest_send_recv_multi(trantest *tt)
{
	Convey("Send and recv multi", {
		nng_listener l = NNG_LISTENER_INITIALIZER;
		nng_dialer   d = NNG_DIALER_INITIALIZER;
		nng_pipe     p = NNG_PIPE_INITIALIZER;
		nng_msg *    send;
		nng_msg *    recv;
		char *       url;
		int          i;
		char         msgbuf[16];

		So(trantest_listen(tt, &l) == 0);
		So(nng_listener_id(l) > 0);
		So(trantest_dial(tt, &d) == 0);
		So(nng_dialer_id(d) > 0);

		nng_msleep(200); // listener may be behind slightly

		for (i = 0; i < 10; i++) {
			snprintf(msgbuf, sizeof(msgbuf), "ping%d", i);
			send = NULL;
			So(nng_msg_alloc(&send, 0) == 0);
			So(send != NULL);
			So(nng_msg_append(send, msgbuf, strlen(msgbuf) + 1) ==
			    0);

			So(nng_sendmsg(tt->reqsock, send, 0) == 0);
			recv = NULL;
			So(nng_recvmsg(tt->repsock, &recv, 0) == 0);
			So(recv != NULL);
			So(nng_msg_len(recv) == strlen(msgbuf) + 1);
			So(strcmp(nng_msg_body(recv), msgbuf) == 0);
			nng_msg_free(recv);

			snprintf(msgbuf, sizeof(msgbuf), "pong%d", i);
			So(nng_msg_alloc(&send, 0) == 0);
			So(nng_msg_append(send, msgbuf, strlen(msgbuf) + 1) ==
			    0);
			So(nng_sendmsg(tt->repsock, send, 0) == 0);
			So(nng_recvmsg(tt->reqsock, &recv, 0) == 0);
			So(recv != NULL);
			So(nng_msg_len(recv) == strlen(msgbuf) + 1);
			So(strcmp(nng_msg_body(recv), msgbuf) == 0);
			p = nng_msg_get_pipe(recv);
			So(nng_pipe_id(p) > 0);
			So(nng_pipe_getopt_string(p, NNG_OPT_URL, &url) == 0);
			So(strcmp(url, tt->addr) == 0);
			nng_strfree(url);
			nng_msg_free(recv);
		}
	});
}

void
trantest_check_properties(trantest *tt, trantest_proptest_t f)
{
	Convey("Properties test", {
		nng_listener l = NNG_LISTENER_INITIALIZER;
		nng_dialer   d = NNG_DIALER_INITIALIZER;
		nng_msg *    send;
		nng_msg *    recv;
		int          rv;

		So(trantest_listen(tt, &l) == 0);
		So(nng_listener_id(l) > 0);
		So(trantest_dial(tt, &d) == 0);
		So(nng_dialer_id(d) > 0);

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
		rv = f(recv);
		nng_msg_free(recv);
		So(rv == 0);
	});
}

void
trantest_send_recv_large(trantest *tt)
{
	Convey("Send and recv large data", {
		nng_listener l = NNG_LISTENER_INITIALIZER;
		nng_dialer   d = NNG_DIALER_INITIALIZER;
		nng_msg *    send;
		nng_msg *    recv;
		char *       data;
		size_t       size;

		size = 1024 * 128; // bigger than any transport segment
		So((data = nng_alloc(size)) != NULL);

		for (int i = 0; (size_t) i < size; i++) {
			data[i] = nng_random() & 0xff;
		}

		So(trantest_listen(tt, &l) == 0);
		So(nng_listener_id(l) > 0);
		So(trantest_dial(tt, &d) == 0);
		So(nng_dialer_id(d) > 0);

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
		trantest_send_recv_multi(&tt);
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
		trantest_send_recv_multi(&tt);
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
		trantest_send_recv_multi(tt);
		if (tt->proptest != NULL) {
			trantest_check_properties(tt, tt->proptest);
		}
	})
}
