//
// Copyright 2024 Staysail Systems, Inc. <info@staysail.com>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "core/nng_impl.h"

typedef struct device_data_s device_data;
typedef struct device_path_s device_path;

struct device_path_s {
	int          state;
	device_data *d;
	nni_sock    *src;
	nni_sock    *dst;
	nni_aio      aio;
};

#define NNI_DEVICE_STATE_INIT 0
#define NNI_DEVICE_STATE_RECV 1
#define NNI_DEVICE_STATE_SEND 2
#define NNI_DEVICE_STATE_FINI 3

struct device_data_s {
	nni_aio      *user;
	int           num_paths;
	int           running;
	int           rv;
	device_path   paths[2];
	nni_reap_node reap;
};

static void device_fini(void *);

static nni_mtx       device_mtx  = NNI_MTX_INITIALIZER;
static nni_reap_list device_reap = {
	.rl_offset = offsetof(device_data, reap),
	.rl_func   = device_fini,
};

static void
device_fini(void *arg)
{
	device_data *d = arg;

	for (int i = 0; i < d->num_paths; i++) {
		nni_aio_stop(&d->paths[i].aio);
	}
	nni_sock_rele(d->paths[0].src);
	nni_sock_rele(d->paths[0].dst);
	NNI_FREE_STRUCT(d);
}

static void
device_cancel(nni_aio *aio, void *arg, int rv)
{
	device_data *d = arg;
	// cancellation is the only path to shutting it down.

	nni_mtx_lock(&device_mtx);
	if (d->user == aio) {
		for (int i = 0; i < d->num_paths; i++) {
			nni_aio_abort(&d->paths[i].aio, rv);
		}
	}
	nni_mtx_unlock(&device_mtx);
}

static void
device_cb(void *arg)
{
	device_path *p = arg;
	device_data *d = p->d;
	int          rv;

	if ((rv = nni_aio_result(&p->aio)) != 0) {
		nni_mtx_lock(&device_mtx);
		if (p->state == NNI_DEVICE_STATE_SEND) {
			nni_msg_free(nni_aio_get_msg(&p->aio));
			nni_aio_set_msg(&p->aio, NULL);
		}
		p->state = NNI_DEVICE_STATE_FINI;
		d->running--;
		if (d->rv == 0) {
			d->rv = rv;
		}
		for (int i = 0; i < d->num_paths; i++) {
			if (p != &d->paths[i]) {
				nni_aio_abort(&d->paths[i].aio, rv);
			}
		}
		if (d->running == 0) {
			if (d->user != NULL) {
				nni_aio_finish_error(d->user, d->rv);
				d->user = NULL;
			}

			nni_reap(&device_reap, d);
		}
		nni_mtx_unlock(&device_mtx);
		return;
	}

	switch (p->state) {
	case NNI_DEVICE_STATE_INIT:
		break;
	case NNI_DEVICE_STATE_SEND:
		p->state = NNI_DEVICE_STATE_RECV;
		nni_sock_recv(p->src, &p->aio);
		break;
	case NNI_DEVICE_STATE_RECV:
		// Leave the message where it is.
		p->state = NNI_DEVICE_STATE_SEND;
		nni_sock_send(p->dst, &p->aio);
		break;
	case NNI_DEVICE_STATE_FINI:
		break;
	}
}

static int
device_init(device_data **dp, nni_sock *s1, nni_sock *s2)
{
	int          num_paths = 2;
	int          i;
	device_data *d;

	// Specifying either of these as null turns the device into
	// a reflector.
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

	if (!nni_sock_raw(s1)) {
		return (NNG_EINVAL);
	}

	if (!nni_sock_raw(s2)) {
		return (NNG_EINVAL);
	}

	// Note we assume that since they are peers, we only need to look
	// at the recv flags -- the other side is assumed to be able
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
		num_paths = 1;
	}

	if ((d = NNI_ALLOC_STRUCT(d)) == NULL) {
		return (NNG_ENOMEM);
	}

	d->num_paths = 0;
	for (i = 0; i < num_paths; i++) {
		device_path *p = &d->paths[i];
		p->src         = i == 0 ? s1 : s2;
		p->dst         = i == 0 ? s2 : s1;
		p->d           = d;
		p->state       = NNI_DEVICE_STATE_INIT;

		nni_aio_init(&p->aio, device_cb, p);

		nni_aio_set_timeout(&p->aio, NNG_DURATION_INFINITE);
	}
	nni_sock_hold(d->paths[0].src);
	nni_sock_hold(d->paths[0].dst);

	d->num_paths = num_paths;
	*dp          = d;
	return (0);
}

static void
device_start(device_data *d, nni_aio *user)
{
	d->user = user;
	for (int i = 0; i < d->num_paths; i++) {
		device_path *p = &d->paths[i];
		p->state       = NNI_DEVICE_STATE_RECV;
		nni_sock_recv(p->src, &p->aio);
		d->running++;
	}
}

void
nni_device(nni_aio *aio, nni_sock *s1, nni_sock *s2)
{
	device_data *d;
	int          rv;

	if (nni_aio_begin(aio) != 0) {
		return;
	}
	nni_mtx_lock(&device_mtx);
	if ((rv = device_init(&d, s1, s2)) != 0) {
		nni_mtx_unlock(&device_mtx);
		nni_aio_finish_error(aio, rv);
		return;
	}
	if ((rv = nni_aio_schedule(aio, device_cancel, d)) != 0) {
		nni_mtx_unlock(&device_mtx);
		nni_aio_finish_error(aio, rv);
		nni_reap(&device_reap, d);
	}
	device_start(d, aio);
	nni_mtx_unlock(&device_mtx);
}
