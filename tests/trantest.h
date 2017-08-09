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
		nng_endpoint ep = 0;

		So(nng_dial(tt->reqsock, tt->addr, &ep, NNG_FLAG_SYNCH) ==
		    NNG_ECONNREFUSED);
		So(ep == 0);
		So(nng_dial(tt->repsock, tt->addr, &ep, NNG_FLAG_SYNCH) ==
		    NNG_ECONNREFUSED);
		So(ep == 0);
	})
}

void
trantest_duplicate_listen(trantest *tt)
{
	Convey("Duplicate listen rejected", {
		nng_endpoint ep;
		So(nng_listen(tt->repsock, tt->addr, &ep, NNG_FLAG_SYNCH) ==
		    0);
		So(ep != 0);
		ep = 0;
		So(nng_listen(tt->reqsock, tt->addr, &ep, NNG_FLAG_SYNCH) ==
		    NNG_EADDRINUSE);
		So(ep == 0);
	})
}

void
trantest_listen_accept(trantest *tt)
{
	Convey("Listen and accept", {
		nng_endpoint ep;
		ep = 0;
		So(nng_listen(tt->repsock, tt->addr, &ep, NNG_FLAG_SYNCH) ==
		    0);
		So(ep != 0);

		ep = 0;
		So(nng_dial(tt->reqsock, tt->addr, &ep, NNG_FLAG_SYNCH) == 0);
		So(ep != 0);
	})
}

void
trantest_send_recv(trantest *tt)
{
	Convey("Send and recv", {
		nng_endpoint ep = 0;
		nng_msg *    send;
		nng_msg *    recv;
		size_t       len;

		ep = 0;
		So(nng_listen(tt->repsock, tt->addr, &ep, NNG_FLAG_SYNCH) ==
		    0);
		So(ep != 0);
		ep = 0;
		So(nng_dial(tt->reqsock, tt->addr, &ep, NNG_FLAG_SYNCH) == 0);
		So(ep != 0);

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
		nng_msg_free(recv);
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
	})
}
