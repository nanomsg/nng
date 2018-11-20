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
#include <nng/protocol/survey0/respond.h>
#include <nng/protocol/survey0/survey.h>
#include <nng/supplemental/util/platform.h>

#include "convey.h"
#include "stubs.h"

static struct {
	nng_aio *aio;
	enum { START, SEND, RECV } state;
	nng_socket s;
	nng_msg *  msg;
	int        cnt;
} resp_state;

void
resp_cb(void *notused)
{
	int rv;
	(void) notused;

	if (resp_state.state == START) {
		resp_state.state = RECV;
		nng_recv_aio(resp_state.s, resp_state.aio);
		return;
	}
	if ((rv = nng_aio_result(resp_state.aio)) != 0) {
		if (resp_state.msg != NULL) {
			nng_msg_free(resp_state.msg);
			resp_state.msg = NULL;
		}
		return;
	}
	switch (resp_state.state) {
	case START:
		break;
	case RECV:
		resp_state.msg   = nng_aio_get_msg(resp_state.aio);
		resp_state.state = SEND;
		nng_aio_set_msg(resp_state.aio, resp_state.msg);
		nng_send_aio(resp_state.s, resp_state.aio);
		break;
	case SEND:
		resp_state.msg   = NULL;
		resp_state.state = RECV;
		nng_aio_set_msg(resp_state.aio, NULL);
		nng_recv_aio(resp_state.s, resp_state.aio);
		resp_state.cnt++;
		break;
	}
}

#define NCTX 10

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

TestMain("Surveyor concurrent contexts", {
	int         rv;
	const char *addr = "inproc://test";
	int         i;

	memset(recv_order, 0, NCTX * sizeof(int));

	atexit(nng_fini);

	Convey("We can use Surveyor contexts concurrently", {
		nng_socket surv = NNG_SOCKET_INITIALIZER;

		So(nng_aio_alloc(&resp_state.aio, resp_cb, NULL) == 0);
		So(nng_respondent0_open(&resp_state.s) == 0);
		So(nng_surveyor0_open(&surv) == 0);

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

		// So(nng_setopt_int(resp_state.s, NNG_OPT_SENDBUF, NCTX) ==
		// 0);
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
			nng_close(surv);
			nng_close(resp_state.s);
			nng_aio_free(resp_state.aio);
		});

		So(nng_listen(resp_state.s, addr, NULL, 0) == 0);
		So(nng_dial(surv, addr, NULL, 0) == 0);

		nng_msleep(100); // let things establish.

		// Start the rep state machine going.
		resp_cb(NULL);

		for (i = 0; i < NCTX; i++) {
			if ((rv = nng_ctx_open(&ctxs[i], surv)) != 0) {
				break;
			}
			if (nng_ctx_id(ctxs[i]) < 0) {
				Fail("Invalid context ID");
				break;
			}
			if ((i > 0) &&
			    (nng_ctx_id(ctxs[i]) == nng_ctx_id(ctxs[i - 1]))) {
				Fail("Context IDs not different");
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
				    recv_order[i], resp_state.cnt,
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
		nng_socket surv;
		nng_ctx    ctx;
		nng_aio *  aio;

		So(nng_surveyor0_open(&surv) == 0);
		So(nng_ctx_open(&ctx, surv) == 0);
		So(nng_aio_alloc(&aio, NULL, NULL) == 0);
		nng_aio_set_timeout(aio, 1000);

		Reset({ nng_aio_free(aio); });

		Convey("Recv on the context is ESTATE", {
			nng_ctx_recv(ctx, aio);
			nng_aio_wait(aio);
			So(nng_aio_result(aio) == NNG_ESTATE);
		});

		Convey("Closing the socket aborts a context recv", {
			nng_msg *msg;
			So(nng_msg_alloc(&msg, 0) == 0);
			nng_aio_set_msg(aio, msg);
			nng_ctx_send(ctx, aio);
			nng_aio_wait(aio);
			So(nng_aio_result(aio) == 0);
			nng_ctx_recv(ctx, aio);
			nng_close(surv);
			nng_aio_wait(aio);
			So(nng_aio_result(aio) == NNG_ECLOSED);
		});

		Convey("Sending a null message fails", {
			nng_ctx_send(ctx, aio);
			nng_aio_wait(aio);
			So(nng_aio_result(aio) == NNG_EINVAL);
		});

		Convey("Closing the context aborts a context send", {
			nng_msg *msg;
			So(nng_msg_alloc(&msg, 0) == 0);
			nng_aio_set_msg(aio, msg);
			nng_ctx_send(ctx, aio);
			nng_aio_wait(aio);
			So(nng_aio_result(aio) == 0);
			nng_ctx_recv(ctx, aio);
			nng_ctx_close(ctx);
			nng_aio_wait(aio);
			So(nng_aio_result(aio) == NNG_ECLOSED);
			nng_close(surv);
		});

		Convey("We can set separate survey times", {
			nng_duration ms;
			So(nng_setopt_ms(
			       surv, NNG_OPT_SURVEYOR_SURVEYTIME, 100) == 0);
			So(nng_ctx_setopt_ms(
			       ctx, NNG_OPT_SURVEYOR_SURVEYTIME, 200) == 0);
			So(nng_getopt_ms(
			       surv, NNG_OPT_SURVEYOR_SURVEYTIME, &ms) == 0);
			So(ms == 100);
			So(nng_ctx_getopt_ms(
			       ctx, NNG_OPT_SURVEYOR_SURVEYTIME, &ms) == 0);
			So(ms == 200);
		});
	});

	Convey("Raw mode does not support contexts", {
		nng_socket surv;
		nng_ctx    ctx;
		So(nng_surveyor0_open_raw(&surv) == 0);
		So(nng_ctx_open(&ctx, surv) == NNG_ENOTSUP);
		nng_close(surv);
	});
})
