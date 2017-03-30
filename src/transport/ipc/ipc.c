//
// Copyright 2017 Garrett D'Amore <garrett@damore.org>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "core/nng_impl.h"

// IPC transport.   Platform specific IPC operations must be
// supplied as well.  Normally the IPC is UNIX domain sockets or
// Windows named pipes.  Other platforms could use other mechanisms.

typedef struct nni_ipc_pipe	nni_ipc_pipe;
typedef struct nni_ipc_ep	nni_ipc_ep;

// nni_ipc_pipe is one end of an IPC connection.
struct nni_ipc_pipe {
	const char *		addr;
	nni_plat_ipcsock *	isp;
	uint16_t		peer;
	uint16_t		proto;
	size_t			rcvmax;

	uint8_t			txhead[1+sizeof (uint64_t)];
	uint8_t			rxhead[1+sizeof (uint64_t)];

	nni_aio *		user_txaio;
	nni_aio *		user_rxaio;
	nni_aio			txaio;
	nni_aio			rxaio;
	nni_msg *		rxmsg;
};

struct nni_ipc_ep {
	char			addr[NNG_MAXADDRLEN+1];
	nni_plat_ipcsock *	isp;
	int			closed;
	uint16_t		proto;
	size_t			rcvmax;
};


static void nni_ipc_pipe_send_cb(void *);
static void nni_ipc_pipe_recv_cb(void *);

static int
nni_ipc_tran_init(void)
{
	return (0);
}


static void
nni_ipc_tran_fini(void)
{
}


static void
nni_ipc_pipe_close(void *arg)
{
	nni_ipc_pipe *pipe = arg;

	nni_plat_ipc_shutdown(pipe->isp);
}


static int
nni_ipc_pipe_init(void **argp)
{
	nni_ipc_pipe *pipe;
	int rv;

	if ((pipe = NNI_ALLOC_STRUCT(pipe)) == NULL) {
		return (NNG_ENOMEM);
	}
	if ((rv = nni_plat_ipc_init(&pipe->isp)) != 0) {
		NNI_FREE_STRUCT(pipe);
		return (rv);
	}
	rv = nni_aio_init(&pipe->txaio, nni_ipc_pipe_send_cb, pipe);
	if (rv != 0) {
		nni_plat_ipc_fini(pipe->isp);
		NNI_FREE_STRUCT(pipe);
		return (rv);
	}

	rv = nni_aio_init(&pipe->rxaio, nni_ipc_pipe_recv_cb, pipe);
	if (rv != 0) {
		nni_aio_fini(&pipe->txaio);
		nni_plat_ipc_fini(pipe->isp);
		NNI_FREE_STRUCT(pipe);
		return (rv);
	}
	*argp = pipe;
	return (0);
}


static void
nni_ipc_pipe_fini(void *arg)
{
	nni_ipc_pipe *pipe = arg;

	if (pipe->rxmsg) {
		nni_msg_free(pipe->rxmsg);
	}
	nni_aio_fini(&pipe->rxaio);
	nni_aio_fini(&pipe->txaio);
	nni_plat_ipc_fini(pipe->isp);
	NNI_FREE_STRUCT(pipe);
}


static void
nni_ipc_pipe_send_cb(void *arg)
{
	nni_ipc_pipe *pipe = arg;
	nni_aio *aio;
	int rv;
	size_t len;

	if ((aio = pipe->user_txaio) == NULL) {
		NNI_ASSERT(aio != NULL);
		return;
	}
	pipe->user_txaio = NULL;
	if ((rv = nni_aio_result(&pipe->txaio)) != 0) {
		nni_aio_finish(aio, rv, 0);
		return;
	}

	len = nni_msg_len(aio->a_msg);
	nni_msg_free(aio->a_msg);
	aio->a_msg = NULL;

	nni_aio_finish(aio, 0, len);
}


static void
nni_ipc_pipe_recv_cb(void *arg)
{
	nni_ipc_pipe *pipe = arg;
	nni_aio *aio;
	int rv;

	aio = pipe->user_rxaio;
	if (aio == NULL) {
		// This should never ever happen.
		NNI_ASSERT(aio != NULL);
		return;
	}

	if ((rv = nni_aio_result(&pipe->rxaio)) != 0) {
		// Error on receive.  This has to cause an error back
		// to the user.  Also, if we had allocated an rxmsg, lets
		// toss it.
		if (pipe->rxmsg != NULL) {
			nni_msg_free(pipe->rxmsg);
			pipe->rxmsg = NULL;
		}
		pipe->user_rxaio = NULL;
		nni_aio_finish(aio, rv, 0);
		return;
	}

	// If we don't have a message yet, we were reading the TCP message
	// header, which is just the length.  This tells us the size of the
	// message to allocate and how much more to expect.
	if (pipe->rxmsg == NULL) {
		uint64_t len;

		// Check to make sure we got msg type 1.
		if (pipe->rxhead[0] != 1) {
			nni_aio_finish(aio, NNG_EPROTO, 0);
			return;
		}

		// We should have gotten a message header.
		NNI_GET64(pipe->rxhead+1, len);

		// Make sure the message payload is not too big.  If it is
		// the caller will shut down the pipe.
		if (len > pipe->rcvmax) {
			pipe->user_rxaio = NULL;
			nni_aio_finish(aio, NNG_EMSGSIZE, 0);
			return;
		}

		if ((rv = nng_msg_alloc(&pipe->rxmsg, (size_t) len)) != 0) {
			pipe->user_rxaio = NULL;
			nni_aio_finish(aio, rv, 0);
			return;
		}

		// Submit the rest of the data for a read -- we want to
		// read the entire message now.
		pipe->rxaio.a_iov[0].iov_buf = nni_msg_body(pipe->rxmsg);
		pipe->rxaio.a_iov[0].iov_len = nni_msg_len(pipe->rxmsg);
		pipe->rxaio.a_niov = 1;

		rv = nni_plat_ipc_aio_recv(pipe->isp, &pipe->rxaio);
		if (rv != 0) {
			pipe->user_rxaio = NULL;
			nni_msg_free(pipe->rxmsg);
			pipe->rxmsg = NULL;
			nni_aio_finish(aio, rv, 0);
			return;
		}
		return;
	}

	// Otherwise we got a message read completely.  Let the user know the
	// good news.
	pipe->user_rxaio = NULL;
	aio->a_msg = pipe->rxmsg;
	pipe->rxmsg = NULL;
	nni_aio_finish(aio, 0, nni_msg_len(aio->a_msg));
}


static int
nni_ipc_pipe_aio_send(void *arg, nni_aio *aio)
{
	nni_ipc_pipe *pipe = arg;
	nni_msg *msg = aio->a_msg;
	uint64_t len;

	pipe->user_txaio = aio;

	pipe->txhead[0] = 1;    // message type, 1.
	len = nni_msg_len(msg) + nni_msg_header_len(msg);
	NNI_PUT64(pipe->txhead + 1, len);

	pipe->txaio.a_iov[0].iov_buf = pipe->txhead;
	pipe->txaio.a_iov[0].iov_len = sizeof (pipe->txhead);
	pipe->txaio.a_iov[1].iov_buf = nni_msg_header(msg);
	pipe->txaio.a_iov[1].iov_len = nni_msg_header_len(msg);
	pipe->txaio.a_iov[2].iov_buf = nni_msg_body(msg);
	pipe->txaio.a_iov[2].iov_len = nni_msg_len(msg);
	pipe->txaio.a_niov = 3;

	return (nni_plat_ipc_aio_send(pipe->isp, &pipe->txaio));
}


static int
nni_ipc_pipe_aio_recv(void *arg, nni_aio *aio)
{
	nni_ipc_pipe *pipe = arg;

	pipe->user_rxaio = aio;

	NNI_ASSERT(pipe->rxmsg == NULL);

	// Schedule a read of the IPC header.
	pipe->rxaio.a_iov[0].iov_buf = pipe->rxhead;
	pipe->rxaio.a_iov[0].iov_len = sizeof (pipe->rxhead);
	pipe->rxaio.a_niov = 1;

	return (nni_plat_ipc_aio_recv(pipe->isp, &pipe->rxaio));
}


static uint16_t
nni_ipc_pipe_peer(void *arg)
{
	nni_ipc_pipe *pipe = arg;

	return (pipe->peer);
}


static int
nni_ipc_pipe_getopt(void *arg, int option, void *buf, size_t *szp)
{
#if 0
	nni_inproc_pipe *pipe = arg;
	size_t len;

	switch (option) {
	case NNG_OPT_LOCALADDR:
	case NNG_OPT_REMOTEADDR:
		len = strlen(pipe->addr) + 1;
		if (len > *szp) {
			(void) memcpy(buf, pipe->addr, *szp);
		} else {
			(void) memcpy(buf, pipe->addr, len);
		}
		*szp = len;
		return (0);
	}
#endif
	return (NNG_ENOTSUP);
}


static int
nni_ipc_ep_init(void **epp, const char *url, nni_sock *sock)
{
	nni_ipc_ep *ep;
	int rv;

	if (strlen(url) > NNG_MAXADDRLEN-1) {
		return (NNG_EADDRINVAL);
	}
	if ((ep = NNI_ALLOC_STRUCT(ep)) == NULL) {
		return (NNG_ENOMEM);
	}
	ep->closed = 0;
	ep->proto = nni_sock_proto(sock);
	ep->rcvmax = nni_sock_rcvmaxsz(sock);
	if ((rv = nni_plat_ipc_init(&ep->isp)) != 0) {
		NNI_FREE_STRUCT(ep);
		return (rv);
	}

	(void) snprintf(ep->addr, sizeof (ep->addr), "%s", url);

	*epp = ep;
	return (0);
}


static void
nni_ipc_ep_fini(void *arg)
{
	nni_ipc_ep *ep = arg;

	nni_plat_ipc_fini(ep->isp);
	NNI_FREE_STRUCT(ep);
}


static void
nni_ipc_ep_close(void *arg)
{
	nni_ipc_ep *ep = arg;

	nni_plat_ipc_shutdown(ep->isp);
}


static int
nni_ipc_negotiate(nni_ipc_pipe *pipe)
{
	int rv;
	nni_iov iov;
	uint8_t buf[8];

	// First send our header..
	buf[0] = 0;
	buf[1] = 'S';
	buf[2] = 'P';
	buf[3] = 0;     // version
	NNI_PUT16(&buf[4], pipe->proto);
	NNI_PUT16(&buf[6], 0);

	iov.iov_buf = buf;
	iov.iov_len = 8;
	if ((rv = nni_plat_ipc_send(pipe->isp, &iov, 1)) != 0) {
		return (rv);
	}

	iov.iov_buf = buf;
	iov.iov_len = 8;
	if ((rv = nni_plat_ipc_recv(pipe->isp, &iov, 1)) != 0) {
		return (rv);
	}

	if ((buf[0] != 0) || (buf[1] != 'S') ||
	    (buf[2] != 'P') || (buf[3] != 0) ||
	    (buf[6] != 0) || (buf[7] != 0)) {
		return (NNG_EPROTO);
	}

	NNI_GET16(&buf[4], pipe->peer);
	return (0);
}


static int
nni_ipc_ep_connect(void *arg, void *pipearg)
{
	nni_ipc_ep *ep = arg;
	nni_ipc_pipe *pipe = pipearg;
	int rv;
	const char *path;

	if (strncmp(ep->addr, "ipc://", strlen("ipc://")) != 0) {
		return (NNG_EADDRINVAL);
	}
	path = ep->addr + strlen("ipc://");

	pipe->proto = ep->proto;
	pipe->rcvmax = ep->rcvmax;

	rv = nni_plat_ipc_connect(pipe->isp, path);
	if (rv != 0) {
		return (rv);
	}

	if ((rv = nni_ipc_negotiate(pipe)) != 0) {
		nni_plat_ipc_shutdown(pipe->isp);
		return (rv);
	}
	return (0);
}


static int
nni_ipc_ep_bind(void *arg)
{
	nni_ipc_ep *ep = arg;
	int rv;
	const char *path;

	// We want to strok this, so make a copy.  Skip the scheme.
	if (strncmp(ep->addr, "ipc://", strlen("ipc://")) != 0) {
		return (NNG_EADDRINVAL);
	}
	path = ep->addr + strlen("ipc://");

	if ((rv = nni_plat_ipc_listen(ep->isp, path)) != 0) {
		return (rv);
	}
	return (0);
}


static int
nni_ipc_ep_accept(void *arg, void *pipearg)
{
	nni_ipc_ep *ep = arg;
	nni_ipc_pipe *pipe = pipearg;
	int rv;

	pipe->proto = ep->proto;
	pipe->rcvmax = ep->rcvmax;

	if ((rv = nni_plat_ipc_accept(pipe->isp, ep->isp)) != 0) {
		return (rv);
	}
	if ((rv = nni_ipc_negotiate(pipe)) != 0) {
		nni_plat_ipc_shutdown(pipe->isp);
		return (rv);
	}
	return (0);
}


static nni_tran_pipe nni_ipc_pipe_ops = {
	.p_init		= nni_ipc_pipe_init,
	.p_fini		= nni_ipc_pipe_fini,
	.p_aio_send	= nni_ipc_pipe_aio_send,
	.p_aio_recv	= nni_ipc_pipe_aio_recv,
	.p_close	= nni_ipc_pipe_close,
	.p_peer		= nni_ipc_pipe_peer,
	.p_getopt	= nni_ipc_pipe_getopt,
};

static nni_tran_ep nni_ipc_ep_ops = {
	.ep_init	= nni_ipc_ep_init,
	.ep_fini	= nni_ipc_ep_fini,
	.ep_connect	= nni_ipc_ep_connect,
	.ep_bind	= nni_ipc_ep_bind,
	.ep_accept	= nni_ipc_ep_accept,
	.ep_close	= nni_ipc_ep_close,
	.ep_setopt	= NULL,
	.ep_getopt	= NULL,
};

// This is the IPC transport linkage, and should be the only global
// symbol in this entire file.
struct nni_tran nni_ipc_tran = {
	.tran_scheme	= "ipc",
	.tran_ep	= &nni_ipc_ep_ops,
	.tran_pipe	= &nni_ipc_pipe_ops,
	.tran_init	= nni_ipc_tran_init,
	.tran_fini	= nni_ipc_tran_fini,
};
