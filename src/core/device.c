//
// Copyright 2017 Garrett D'Amore <garrett@damore.org>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "core/nng_impl.h"

#include <string.h>

struct nni_device_pair {
	nni_thr		thrs[2];
	nni_sock *	socks[2];
	int		err[2];
};

typedef struct nni_device_pair   nni_device_pair;

static int
nni_device_loop(nni_sock *from, nni_sock *to)
{
	nni_msg *msg;
	int rv = 0;

	for (;;) {
		// Take messages sock[0], and send to sock[1].
		// If an error occurs, we close both sockets.
		if ((rv = nni_sock_recvmsg(from, &msg, NNI_TIME_NEVER)) != 0) {
			break;
		}
		if ((rv = nni_sock_sendmsg(to, msg, NNI_TIME_NEVER)) != 0) {
			nni_msg_free(msg);
			break;
		}
	}

	return (rv);
}


static void
nni_device_fwd(void *p)
{
	nni_device_pair *pair = p;

	pair->err[0] = nni_device_loop(pair->socks[0], pair->socks[1]);
	nni_sock_shutdown(pair->socks[0]);
	nni_sock_shutdown(pair->socks[1]);
}


static void
nni_device_rev(void *p)
{
	nni_device_pair *pair = p;
	int rv;

	pair->err[1] = nni_device_loop(pair->socks[1], pair->socks[0]);
	nni_sock_shutdown(pair->socks[0]);
	nni_sock_shutdown(pair->socks[1]);
}


int
nni_device(nni_sock *sock1, nni_sock *sock2)
{
	nni_device_pair pair;
	int rv;

	memset(&pair, 0, sizeof (pair));
	pair.socks[0] = sock1;
	pair.socks[1] = sock2;

	if (sock1 == NULL) {
		sock1 = sock2;
	}
	if (sock2 == NULL) {
		sock2 = sock1;
	}
	if ((sock1 == NULL) || (sock2 == NULL)) {
		rv = NNG_EINVAL;
		goto out;
	}
	if ((sock1->s_peer != sock2->s_protocol) ||
	    (sock2->s_peer != sock1->s_protocol)) {
		rv = NNG_EINVAL;
		goto out;
	}

	pair.socks[0] = sock1;
	pair.socks[1] = sock2;

	if ((rv = nni_thr_init(&pair.thrs[0], nni_device_fwd, &pair)) != 0) {
		goto out;
	}
	if ((rv = nni_thr_init(&pair.thrs[1], nni_device_rev, &pair)) != 0) {
		nni_thr_fini(&pair.thrs[0]);
		goto out;
	}
	if (((sock1->s_flags & NNI_PROTO_FLAG_RCV) != 0) &&
	    ((sock2->s_flags & NNI_PROTO_FLAG_SND) != 0)) {
		nni_thr_run(&pair.thrs[0]);
	}
	// If the sockets are the same, then its a simple one way forwarder,
	// and we don't need two workers (but would be harmless if we did it).
	if ((sock1 != sock2) &&
	    ((sock2->s_flags & NNI_PROTO_FLAG_RCV) != 0) &&
	    ((sock1->s_flags & NNI_PROTO_FLAG_SND) != 0)) {
		nni_thr_run(&pair.thrs[1]);
	}

	// This blocks on both threads (though if we didn't start one, that
	// will return immediately.)
	nni_thr_fini(&pair.thrs[0]);
	nni_thr_fini(&pair.thrs[1]);

	nni_sock_rele(sock1);
	if (sock1 != sock2) {
		nni_sock_rele(sock2);
	}

	rv = pair.err[0];
	if (rv == 0) {
		rv = pair.err[1];
	}
	if (rv == 0) {
		// This can happen if neither thread ran.  Shouldn't happen
		// really.
		rv = NNG_EINVAL;
	}

out:
	return (rv);
}
