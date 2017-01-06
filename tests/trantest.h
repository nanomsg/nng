//
// Copyright 2017 Garrett D'Amore <garrett@damore.org>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "convey.h"
#include "nng.h"
#include "core/nng_impl.h"
#include <string.h>

// Transport common tests.  By making a common test framework for transports,
// we can avoid rewriting the same tests for each new transport.  Include this
// file once in your test code.  The test framework uses the REQ/REP protocol
// for comms.

typedef struct {
	char addr[NNG_MAXADDRLEN+1];
	nng_socket *reqsock;
	nng_socket *repsock;
	nni_tran *tran;
} trantest;

void
trantest_init(trantest *tt, const char *addr)
{
	snprintf(tt->addr, sizeof (tt->addr), "%s", addr);
	tt->tran = nni_tran_find(addr);
	So(tt->tran != NULL);
	So(nng_open(&tt->reqsock, NNG_PROTO_REQ) == 0);
	So(nng_open(&tt->repsock, NNG_PROTO_REP) == 0);
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
		int l = strlen(tt->tran->tran_scheme);
		So(strncmp(tt->addr, tt->tran->tran_scheme, l) == 0);
		So(strncmp(tt->addr + l, "://", 3) == 0);
	})
}

void
trantest_conn_refused(trantest *tt)
{
	Convey("Connection refused works", {
		nng_endpoint *ep = NULL;

		So(nng_dial(tt->reqsock, tt->addr, &ep, NNG_FLAG_SYNCH) == NNG_ECONNREFUSED);
		So(ep == NULL);
		So(nng_dial(tt->repsock, tt->addr, &ep, NNG_FLAG_SYNCH) == NNG_ECONNREFUSED);
		So(ep == NULL);
	})
}

void
trantest_duplicate_listen(trantest *tt)
{
	Convey("Duplicate listen rejected", {
		nng_endpoint *ep;
		So(nng_listen(tt->repsock, tt->addr, &ep, NNG_FLAG_SYNCH) == 0);
		So(ep != NULL);
		ep = NULL;
		So(nng_listen(tt->reqsock, tt->addr, &ep, NNG_FLAG_SYNCH) == NNG_EADDRINUSE);
		So(ep == NULL);
	})
}

void
trantest_listen_accept(trantest *tt)
{
	Convey("Listen and accept" ,{
		nng_endpoint *ep;
		ep = NULL;
		So(nng_listen(tt->repsock, tt->addr, &ep, NNG_FLAG_SYNCH) == 0);
		So(ep != NULL);

		ep = NULL;
		So(nng_dial(tt->reqsock, tt->addr, &ep, NNG_FLAG_SYNCH) == 0);
		So(ep != NULL);
	})
}

void
trantest_send_recv(trantest *tt)
{
	Convey("Send and recv", {
		nng_endpoint *ep = NULL;
		nng_msg *send;
		nng_msg *recv;
		size_t len;

		ep = NULL;
		So(nng_listen(tt->repsock, tt->addr, &ep, NNG_FLAG_SYNCH) == 0);
		So(ep != NULL);
		ep = NULL;
		So(nng_dial(tt->reqsock, tt->addr, &ep, NNG_FLAG_SYNCH) == 0);
		So(ep != NULL);

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

		Reset({
			trantest_fini(&tt);
		})

		trantest_scheme(&tt);
		trantest_conn_refused(&tt);
		trantest_duplicate_listen(&tt);
		trantest_listen_accept(&tt);
		trantest_send_recv(&tt);
	})
}
