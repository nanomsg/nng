//
// Copyright 2018 Staysail Systems, Inc. <info@staysail.com>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "core/nng_impl.h"

#include <string.h>

typedef struct nni_device_path {
	nni_aio * user; // user aio
	nni_aio * aio;
	nni_sock *src;
	nni_sock *dst;
	int       state;
} nni_device_path;

#define NNI_DEVICE_STATE_INIT 0
#define NNI_DEVICE_STATE_RECV 1
#define NNI_DEVICE_STATE_SEND 2
#define NNI_DEVICE_STATE_FINI 3

typedef struct nni_device_data {
	nni_aio *       user;
	int             npath;
	nni_device_path paths[2];
	nni_mtx         mtx;
	bool            running;
} nni_device_data;

typedef struct nni_device_pair nni_device_pair;

static void
nni_device_cancel(nni_aio *aio, void *arg, int rv)
{
	nni_device_data *dd = arg;
	// cancellation is the only path to shutting it down.

	nni_mtx_lock(&dd->mtx);
	if ((!dd->running) || (dd->user != aio)) {
		nni_mtx_unlock(&dd->mtx);
		return;
	}
	dd->running = false;
	dd->user    = NULL;
	nni_mtx_unlock(&dd->mtx);

	nni_sock_shutdown(dd->paths[0].src);
	nni_sock_shutdown(dd->paths[0].dst);
	nni_aio_finish_error(aio, rv);
}

static void
nni_device_cb(void *arg)
{
	nni_device_path *p   = arg;
	nni_aio *        aio = p->aio;
	int              rv;

	if ((rv = nni_aio_result(aio)) != 0) {
		p->state = NNI_DEVICE_STATE_FINI;
		nni_aio_abort(p->user, rv);
		return;
	}

	switch (p->state) {
	case NNI_DEVICE_STATE_INIT:
	case NNI_DEVICE_STATE_SEND:
		p->state = NNI_DEVICE_STATE_RECV;
		nni_sock_recv(p->src, aio);
		break;
	case NNI_DEVICE_STATE_RECV:
		// Leave the message where it is.
		p->state = NNI_DEVICE_STATE_SEND;
		nni_sock_send(p->dst, aio);
		break;
	case NNI_DEVICE_STATE_FINI:
		break;
	}
}

void
nni_device_fini(nni_device_data *dd)
{
	int i;
	for (i = 0; i < dd->npath; i++) {
		nni_device_path *p = &dd->paths[i];
		nni_aio_stop(p->aio);
	}
	for (i = 0; i < dd->npath; i++) {
		nni_device_path *p = &dd->paths[i];
		nni_aio_free(p->aio);
	}
	nni_mtx_fini(&dd->mtx);
	NNI_FREE_STRUCT(dd);
}

int
nni_device_init(nni_device_data **dp, nni_sock *s1, nni_sock *s2)
{
	nni_device_data *dd;
	int              npath = 2;
	int              i;
	bool             raw;
	size_t           rsz;

	// Specifying either of these as null turns the device into
	// a loopback reflector.
	if (s1 == NULL) {
		s1 = s2;
	}
	if (s2 == NULL) {
		s2 = s1;
	}
	// At least one of the sockets must be valid.
	if ((s1 == NULL) || (s2 == NULL)) {
		return (NNG_EINVAL);
	}
	if ((nni_sock_peer_id(s1) != nni_sock_proto_id(s2)) ||
	    (nni_sock_peer_id(s2) != nni_sock_proto_id(s1))) {
		return (NNG_EINVAL);
	}

	raw = false;
	rsz = sizeof(raw);
	if (((nni_sock_getopt(s1, NNG_OPT_RAW, &raw, &rsz, NNI_TYPE_BOOL) !=
	        0)) ||
	    (!raw)) {
		return (NNG_EINVAL);
	}

	rsz = sizeof(raw);
	if (((nni_sock_getopt(s2, NNG_OPT_RAW, &raw, &rsz, NNI_TYPE_BOOL) !=
	        0)) ||
	    (!raw)) {
		return (NNG_EINVAL);
	}

	// Note we assume that since they peers, we only need to look
	// at the receive flags -- the other side is assumed to be able
	// to send.
	if ((nni_sock_flags(s1) & NNI_PROTO_FLAG_RCV) == 0) {
		nni_sock *temp = s1;
		s1             = s2;
		s2             = temp;
	}

	NNI_ASSERT((nni_sock_flags(s1) & NNI_PROTO_FLAG_RCV) != 0);

	// Only run one forwarder if the protocols are not bidirectional, or
	// if the source and destination sockets are identical.  (The latter is
	// not strictly necessary, but it saves resources and minimizes any
	// extra reordering.)
	if (((nni_sock_flags(s2) & NNI_PROTO_FLAG_RCV) == 0) || (s1 == s2)) {
		npath = 1;
	}

	if ((dd = NNI_ALLOC_STRUCT(dd)) == NULL) {
		return (NNG_ENOMEM);
	}
	nni_mtx_init(&dd->mtx);

	for (i = 0; i < npath; i++) {
		int              rv;
		nni_device_path *p = &dd->paths[i];
		p->src             = i == 0 ? s1 : s2;
		p->dst             = i == 0 ? s2 : s1;
		p->state           = NNI_DEVICE_STATE_INIT;

		if ((rv = nni_aio_alloc(&p->aio, nni_device_cb, p)) != 0) {
			nni_device_fini(dd);
			return (rv);
		}

		nni_aio_set_timeout(p->aio, NNG_DURATION_INFINITE);
	}
	dd->npath = npath;
	*dp       = dd;
	return (0);
}

void
nni_device_start(nni_device_data *dd, nni_aio *user)
{
	int i;
	int rv;

	if (nni_aio_begin(user) != 0) {
		return;
	}
	nni_mtx_lock(&dd->mtx);
	if ((rv = nni_aio_schedule(user, nni_device_cancel, dd)) != 0) {
		nni_mtx_unlock(&dd->mtx);
		nni_aio_finish_error(user, rv);
		return;
	}
	dd->user = user;
	for (i = 0; i < dd->npath; i++) {
		nni_device_path *p = &dd->paths[i];
		p->user            = user;
		p->state           = NNI_DEVICE_STATE_INIT;
	}
	for (i = 0; i < dd->npath; i++) {
		nni_device_path *p = &dd->paths[i];
		p->state           = NNI_DEVICE_STATE_RECV;
		nni_sock_recv(p->src, p->aio);
	}
	dd->running = true;
	nni_mtx_unlock(&dd->mtx);
}

int
nni_device(nni_sock *s1, nni_sock *s2)
{
	nni_device_data *dd;
	nni_aio *        aio;
	int              rv;

	if ((rv = nni_aio_alloc(&aio, NULL, NULL)) != 0) {
		return (rv);
	}
	if ((rv = nni_device_init(&dd, s1, s2)) != 0) {
		nni_aio_free(aio);
		return (rv);
	}
	nni_device_start(dd, aio);
	nni_aio_wait(aio);

	rv = nni_aio_result(aio);
	nni_device_fini(dd);
	nni_aio_free(aio);
	return (rv);
}
