//
// Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <string.h>

#include <nng/nng.h>
#include <nng/protocol/reqrep0/rep.h>
#include <nng/protocol/reqrep0/req.h>
#include <nng/supplemental/util/platform.h>

#include "convey.h"
#include "stubs.h"

static struct {
	nng_aio *aio;
	enum { START, SEND, RECV } state;
	nng_socket s;
	nng_msg *  msg;
	int        cnt;
	nng_mtx *  mtx;
} rep_state;

void
rep_cb(void *notused)
{
	int rv;
	(void) notused;

	nng_mtx_lock(rep_state.mtx);
	if (rep_state.state == START) {
		rep_state.state = RECV;
		nng_recv_aio(rep_state.s, rep_state.aio);
		nng_mtx_unlock(rep_state.mtx);
		return;
	}
	if ((rv = nng_aio_result(rep_state.aio)) != 0) {
		if (rep_state.msg != NULL) {
			nng_msg_free(rep_state.msg);
			rep_state.msg = NULL;
		}
		nng_mtx_unlock(rep_state.mtx);
		return;
	}
	switch (rep_state.state) {
	case START:
		break;
	case RECV:
		rep_state.msg   = nng_aio_get_msg(rep_state.aio);
		rep_state.state = SEND;
		nng_aio_set_msg(rep_state.aio, rep_state.msg);
		nng_send_aio(rep_state.s, rep_state.aio);
		break;
	case SEND:
		rep_state.msg   = NULL;
		rep_state.state = RECV;
		nng_aio_set_msg(rep_state.aio, NULL);
		nng_recv_aio(rep_state.s, rep_state.aio);
		rep_state.cnt++;
		break;
	}
	nng_mtx_unlock(rep_state.mtx);
}

#define NCTX 1000

void
markr(void *arg)
{
	*(bool *) arg = true;
}

static void
marks(void *arg)
{
	*(bool *) arg = true;
}

nng_ctx  ctxs[NCTX];
uint32_t recv_order[NCTX];
nng_aio *saios[NCTX];
nng_aio *raios[NCTX];
bool     recd[NCTX];
bool     sent[NCTX];

TestMain("REQ concurrent contexts", {
	int         rv;
	const char *addr = "inproc://test";
	int         i;

	memset(recv_order, 0, NCTX * sizeof(int));

	atexit(nng_fini);

	Convey("We can use REQ contexts concurrently", {
		nng_socket req;

		So(nng_mtx_alloc(&rep_state.mtx) == 0);
		So(nng_aio_alloc(&rep_state.aio, rep_cb, NULL) == 0);
		So(nng_rep_open(&rep_state.s) == 0);
		So(nng_req_open(&req) == 0);

		for (i = 0; i < NCTX; i++) {
			sent[i] = recd[i] = false;
			recv_order[i]     = (uint32_t) i;
			if (nng_aio_alloc(&raios[i], markr, &(recd[i])) != 0) {
				break;
			}
			nng_aio_set_timeout(raios[i], 5000);
			if (nng_aio_alloc(&saios[i], marks, &(sent[i])) != 0) {
				break;
			}
			nng_aio_set_timeout(saios[i], 5000);
		}

		So(nng_setopt_int(rep_state.s, NNG_OPT_SENDBUF, NCTX) == 0);
		So(i == NCTX);
		for (i = 0; i < NCTX; i++) {
			uint32_t tmp;
			int      ni = rand() % NCTX; // recv index

			tmp            = recv_order[i];
			recv_order[i]  = recv_order[ni];
			recv_order[ni] = tmp;
		}
		Reset({
			for (i = 0; i < NCTX; i++) {
				nng_aio_free(saios[i]);
				nng_aio_free(raios[i]);
			}
			nng_close(req);
			nng_close(rep_state.s);
			nng_aio_free(rep_state.aio);
			nng_mtx_free(rep_state.mtx);
		});

		So(nng_listen(rep_state.s, addr, NULL, 0) == 0);
		So(nng_dial(req, addr, NULL, 0) == 0);

		nng_msleep(100); // let things establish.

		// Start the rep state machine going.
		rep_cb(NULL);

		for (i = 0; i < NCTX; i++) {
			if ((rv = nng_ctx_open(&ctxs[i], req)) != 0) {
				break;
			}
		}
		So(rv == 0);
		So(i == NCTX);

		// Send messages
		for (i = 0; i < NCTX; i++) {
			nng_msg *m;
			if ((rv = nng_msg_alloc(&m, sizeof(uint32_t))) != 0) {
				Fail("msg alloc failed: %s", nng_strerror(rv));
			}
			if ((rv = nng_msg_append_u32(m, i)) != 0) {
				Fail("append failed: %s", nng_strerror(rv));
			}
			nng_aio_set_msg(saios[i], m);
			nng_ctx_send(ctxs[i], saios[i]);
		}
		So(rv == 0);
		So(i == NCTX);

		for (i = 0; i < NCTX; i++) {
			nng_aio_wait(saios[i]);
			if ((rv = nng_aio_result(saios[i])) != 0) {
				Fail("send failed: %s", nng_strerror(rv));
				So(false);
				break;
			}
		}
		for (i = 0; i < NCTX; i++) {
			if (!sent[i]) {
				Fail("Index %d (%d) not sent", i, i);
			}
		}

		So(rv == 0);
		So(i == NCTX);
		// Receive answers
		for (i = 0; i < NCTX; i++) {
			int ri = recv_order[i];
			nng_ctx_recv(ctxs[ri], raios[ri]);
		}

		for (i = 0; i < NCTX; i++) {
			nng_msg *msg;
			uint32_t x;

			nng_aio_wait(raios[i]);
			if ((rv = nng_aio_result(raios[i])) != 0) {
				Fail("recv %d (%d) %d failed: %s", i,
				    recv_order[i], rep_state.cnt,
				    nng_strerror(rv));
				continue;
			}
			msg = nng_aio_get_msg(raios[i]);
			if ((rv = nng_msg_chop_u32(msg, &x)) != 0) {
				Fail("recv msg trim: %s", nng_strerror(rv));
				break;
			}
			if (x != (uint32_t) i) {
				Fail("message body mismatch: %x %x\n", x,
				    (uint32_t) i);
				break;
			}

			nng_msg_free(msg);
		}
		for (i = 0; i < NCTX; i++) {
			if (!recd[i]) {
				Fail("Index %d (%d) not received", i,
				    recv_order[i]);
				break;
			}
		}

		So(rv == 0);
		So(i == NCTX);
	});

	Convey("Given a socket and a context", {
		nng_socket req;
		nng_ctx    ctx;
		nng_aio *  aio;

		So(nng_req0_open(&req) == 0);
		So(nng_ctx_open(&ctx, req) == 0);
		So(nng_aio_alloc(&aio, NULL, NULL) == 0);
		nng_aio_set_timeout(aio, 1000);

		Reset({ nng_aio_free(aio); });

		Convey("Closing the socket aborts a context send", {
			nng_msg *msg;
			So(nng_msg_alloc(&msg, 0) == 0);
			nng_aio_set_msg(aio, msg);
			nng_ctx_send(ctx, aio);
			nng_close(req);
			nng_aio_wait(aio);
			So(nng_aio_result(aio) == NNG_ECLOSED);
			nng_msg_free(msg);
		});

		Convey("Closing the context aborts a context send", {
			nng_msg *msg;
			So(nng_msg_alloc(&msg, 0) == 0);
			nng_aio_set_msg(aio, msg);
			nng_ctx_send(ctx, aio);
			nng_ctx_close(ctx);
			nng_aio_wait(aio);
			So(nng_aio_result(aio) == NNG_ECLOSED);
			nng_msg_free(msg);
			nng_close(req);
		});
	});
})
