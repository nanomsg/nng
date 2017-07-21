//
// Copyright 2017 Garrett D'Amore <garrett@damore.org>
// Copyright 2017 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "convey.h"
#include "core/nng_impl.h"
#include "nng.h"
#include <stdlib.h>
#include <string.h>

// Transport common tests.  By making a common test framework for transports,
// we can avoid rewriting the same tests for each new transport.  Include this
// file once in your test code.  The test framework uses the REQ/REP protocol
// for comms.

typedef struct {
	char       addr[NNG_MAXADDRLEN + 1];
	nng_socket reqsock;
	nng_socket repsock;
	nni_tran * tran;
} trantest;

unsigned trantest_port = 0;

void
trantest_next_address(char *out, const char *template)
{
	if (trantest_port == 0) {
		char *pstr;
		trantest_port = 5555;
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

	tt->tran = nni_tran_find(addr);
	So(tt->tran != NULL);
}

void
trantest_fini(trantest *tt)
{
	nng_close(tt->reqsock);
	nng_close(tt->repsock);
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
		So(nng_listen(tt->repsock, tt->addr, &l, 0) == 0);
		So(l != 0);
		l = 0;
		So(nng_listen(tt->reqsock, tt->addr, &l, 0) == NNG_EADDRINUSE);
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
		nng_dialer   d;
		nng_msg *    send;
		nng_msg *    recv;
		size_t       len;
		nng_pipe     p;
		char         url[NNG_MAXADDRLEN];
		size_t       sz;

		So(nng_listen(tt->repsock, tt->addr, &l, 0) == 0);
		So(l != 0);
		So(nng_dial(tt->reqsock, tt->addr, &d, 0) == 0);
		So(d != 0);

		nng_usleep(20000); // listener may be behind slightly

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
		sz = sizeof (url);
		So(nng_pipe_getopt(p, nng_optid_url, url, &sz) == 0);
		So(strcmp(url, tt->addr) == 0);
		nng_msg_free(recv);
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

		for (int i = 0; i < size; i++) {
			data[i] = nni_random() & 0xff;
		}

		So(nng_listen(tt->repsock, tt->addr, &l, 0) == 0);
		So(l != 0);
		So(nng_dial(tt->reqsock, tt->addr, &d, 0) == 0);
		So(d != 0);

		nng_usleep(20000); // listener may be behind slightly

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
