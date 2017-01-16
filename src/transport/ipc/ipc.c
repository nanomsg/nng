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
	nni_plat_ipcsock	fd;
	uint16_t		peer;
	uint16_t		proto;
	uint32_t		rcvmax;
};

struct nni_ipc_ep {
	char			addr[NNG_MAXADDRLEN+1];
	nni_plat_ipcsock	fd;
	int			closed;
	uint16_t		proto;
	uint32_t		rcvmax;
};

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

	nni_plat_ipc_shutdown(&pipe->fd);
}


static void
nni_ipc_pipe_destroy(void *arg)
{
	nni_ipc_pipe *pipe = arg;

	nni_plat_ipc_fini(&pipe->fd);
	NNI_FREE_STRUCT(pipe);
}


static int
nni_ipc_pipe_send(void *arg, nni_msg *msg)
{
	nni_ipc_pipe *pipe = arg;
	uint64_t len;
	uint8_t buf[sizeof (len)];
	nni_iov iov[4];
	int rv;
	uint8_t msgtype;

	msgtype = 1; // "inband", the only defined option at present

	iov[0].iov_buf = &msgtype;
	iov[0].iov_len = 1;
	iov[1].iov_buf = buf;
	iov[1].iov_len = sizeof (buf);
	iov[2].iov_buf = nni_msg_header(msg);
	iov[2].iov_len = nni_msg_header_len(msg);
	iov[3].iov_buf = nni_msg_body(msg);
	iov[3].iov_len = nni_msg_len(msg);

	len = (uint64_t) iov[2].iov_len + (uint64_t) iov[3].iov_len;
	NNI_PUT64(buf, len);

	if ((rv = nni_plat_ipc_send(&pipe->fd, iov, 4)) == 0) {
		nni_msg_free(msg);
	}
	return (rv);
}


static int
nni_ipc_pipe_recv(void *arg, nni_msg **msgp)
{
	nni_ipc_pipe *pipe = arg;
	nni_msg *msg;
	uint64_t len;
	uint8_t buf[sizeof (len)];
	nni_iov iov[2];
	int rv;
	uint8_t msgtype;

	iov[0].iov_buf = &msgtype;
	iov[0].iov_len = 1;
	iov[1].iov_buf = buf;
	iov[1].iov_len = sizeof (buf);
	if ((rv = nni_plat_ipc_recv(&pipe->fd, iov, 2)) != 0) {
		return (rv);
	}
	if (msgtype != 1) {
		return (NNG_EPROTO);
	}
	NNI_GET64(buf, len);
	if (len > pipe->rcvmax) {
		return (NNG_EPROTO);
	}

	if ((rv = nng_msg_alloc(&msg, len)) != 0) {
		return (rv);
	}

	iov[0].iov_len = nng_msg_len(msg);
	iov[0].iov_buf = nng_msg_body(msg);

	if ((rv = nni_plat_ipc_recv(&pipe->fd, iov, 1)) == 0) {
		*msgp = msg;
	} else {
		nni_msg_free(msg);
	}
	return (rv);
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
nni_ipc_ep_init(void **epp, const char *url, uint16_t proto)
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
	ep->proto = proto;
	ep->rcvmax = 1024 * 1024;       // XXX: fix this
	if ((rv = nni_plat_ipc_init(&ep->fd)) != 0) {
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

	nni_plat_ipc_fini(&ep->fd);
	NNI_FREE_STRUCT(ep);
}


static void
nni_ipc_ep_close(void *arg)
{
	nni_ipc_ep *ep = arg;

	nni_plat_ipc_shutdown(&ep->fd);
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
	if ((rv = nni_plat_ipc_send(&pipe->fd, &iov, 1)) != 0) {
		return (rv);
	}

	iov.iov_buf = buf;
	iov.iov_len = 8;
	if ((rv = nni_plat_ipc_recv(&pipe->fd, &iov, 1)) != 0) {
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
nni_ipc_ep_connect(void *arg, void **pipep)
{
	nni_ipc_ep *ep = arg;
	nni_ipc_pipe *pipe;
	int rv;
	const char *path;

	if (strncmp(ep->addr, "ipc://", strlen("ipc://")) != 0) {
		return (NNG_EADDRINVAL);
	}
	path = ep->addr + strlen("ipc://");

	if ((pipe = NNI_ALLOC_STRUCT(pipe)) == NULL) {
		return (NNG_ENOMEM);
	}
	if ((rv = nni_plat_ipc_init(&pipe->fd)) != 0) {
		NNI_FREE_STRUCT(pipe);
		return (rv);
	}
	pipe->proto = ep->proto;
	pipe->rcvmax = ep->rcvmax;

	rv = nni_plat_ipc_connect(&pipe->fd, path);
	if (rv != 0) {
		nni_plat_ipc_fini(&pipe->fd);
		NNI_FREE_STRUCT(pipe);
		return (rv);
	}

	if ((rv = nni_ipc_negotiate(pipe)) != 0) {
		nni_plat_ipc_shutdown(&pipe->fd);
		nni_plat_ipc_fini(&pipe->fd);
		NNI_FREE_STRUCT(pipe);
		return (rv);
	}
	*pipep = pipe;
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

	if ((rv = nni_plat_ipc_listen(&ep->fd, path)) != 0) {
		return (rv);
	}
	return (0);
}


static int
nni_ipc_ep_accept(void *arg, void **pipep)
{
	nni_ipc_ep *ep = arg;
	nni_ipc_pipe *pipe;
	int rv;


	if ((pipe = NNI_ALLOC_STRUCT(pipe)) == NULL) {
		return (NNG_ENOMEM);
	}
	pipe->proto = ep->proto;
	pipe->rcvmax = ep->rcvmax;
	if ((rv = nni_plat_ipc_init(&pipe->fd)) != 0) {
		NNI_FREE_STRUCT(pipe);
		return (rv);
	}

	if ((rv = nni_plat_ipc_accept(&pipe->fd, &ep->fd)) != 0) {
		nni_plat_ipc_fini(&pipe->fd);
		NNI_FREE_STRUCT(pipe);
		return (rv);
	}
	if ((rv = nni_ipc_negotiate(pipe)) != 0) {
		nni_plat_ipc_shutdown(&pipe->fd);
		nni_plat_ipc_fini(&pipe->fd);
		NNI_FREE_STRUCT(pipe);
		return (rv);
	}
	*pipep = pipe;
	return (0);
}


static nni_tran_pipe nni_ipc_pipe_ops = {
	.pipe_destroy	= nni_ipc_pipe_destroy,
	.pipe_send	= nni_ipc_pipe_send,
	.pipe_recv	= nni_ipc_pipe_recv,
	.pipe_close	= nni_ipc_pipe_close,
	.pipe_peer	= nni_ipc_pipe_peer,
	.pipe_getopt	= nni_ipc_pipe_getopt,
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
