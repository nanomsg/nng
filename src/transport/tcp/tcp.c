//
// Copyright 2016 Garrett D'Amore <garrett@damore.org>
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

// TCP transport.   Platform specific TCP operations must be
// supplied as well.

typedef struct nni_tcp_pipe	nni_tcp_pipe;
typedef struct nni_tcp_ep	nni_tcp_ep;

// nni_tcp_pipe is one end of a TCP connection.
struct nni_tcp_pipe {
	const char *		addr;
	nni_plat_tcpsock	fd;
	uint16_t		peer;
	uint16_t		proto;
	uint32_t		rcvmax;
};

struct nni_tcp_ep {
	char			addr[NNG_MAXADDRLEN+1];
	nni_plat_tcpsock	fd;
	int			closed;
	uint16_t		proto;
	uint32_t		rcvmax;
	int			ipv4only;
};

static int
nni_tcp_tran_init(void)
{
	return (0);
}


static void
nni_tcp_tran_fini(void)
{
}


static void
nni_tcp_pipe_close(void *arg)
{
	nni_tcp_pipe *pipe = arg;

	nni_plat_tcp_shutdown(&pipe->fd);
}


static void
nni_tcp_pipe_destroy(void *arg)
{
	nni_tcp_pipe *pipe = arg;

	nni_plat_tcp_fini(&pipe->fd);
	NNI_FREE_STRUCT(pipe);
}


static int
nni_tcp_pipe_send(void *arg, nni_msg *msg)
{
	nni_tcp_pipe *pipe = arg;
	uint64_t len;
	uint8_t buf[sizeof (len)];
	nni_iov iov[3];
	int rv;

	iov[0].iov_buf = buf;
	iov[0].iov_len = sizeof (buf);
	iov[1].iov_buf = nni_msg_header(msg, &iov[1].iov_len);
	iov[2].iov_buf = nni_msg_body(msg, &iov[2].iov_len);

	len = (uint64_t) iov[1].iov_len + (uint64_t) iov[2].iov_len;
	NNI_PUT64(buf, len);

	if ((rv = nni_plat_tcp_send(&pipe->fd, iov, 3)) == 0) {
		nni_msg_free(msg);
	}
	return (rv);
}


static int
nni_tcp_pipe_recv(void *arg, nni_msg **msgp)
{
	nni_tcp_pipe *pipe = arg;
	nni_msg *msg;
	uint64_t len;
	uint8_t buf[sizeof (len)];
	nni_iov iov[1];
	int rv;
	size_t sz;

	iov[0].iov_buf = buf;
	iov[0].iov_len = sizeof (buf);
	if ((rv = nni_plat_tcp_recv(&pipe->fd, iov, 1)) != 0) {
		return (rv);
	}
	NNI_GET64(buf, len);
	if (len > pipe->rcvmax) {
		return (NNG_EPROTO);
	}

	if ((rv = nng_msg_alloc(&msg, len)) != 0) {
		return (rv);
	}

	iov[0].iov_len = len;
	iov[0].iov_buf = nng_msg_body(msg, &sz);

	if ((rv = nni_plat_tcp_recv(&pipe->fd, iov, 1)) == 0) {
		*msgp = msg;
	} else {
		nni_msg_free(msg);
	}
	return (rv);
}


static uint16_t
nni_tcp_pipe_peer(void *arg)
{
	nni_tcp_pipe *pipe = arg;

	return (pipe->peer);
}


static int
nni_tcp_pipe_getopt(void *arg, int option, void *buf, size_t *szp)
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
nni_tcp_ep_init(void **epp, const char *url, uint16_t proto)
{
	nni_tcp_ep *ep;
	int rv;

	if (strlen(url) > NNG_MAXADDRLEN-1) {
		return (NNG_EINVAL);
	}
	if ((ep = NNI_ALLOC_STRUCT(ep)) == NULL) {
		return (NNG_ENOMEM);
	}
	ep->closed = 0;
	ep->proto = proto;
	ep->ipv4only = 0;
	ep->rcvmax = 1024 * 1024;       // XXX: fix this
	nni_plat_tcp_init(&ep->fd);

	(void) snprintf(ep->addr, sizeof (ep->addr), "%s", url);

	*epp = ep;
	return (0);
}


static void
nni_tcp_ep_fini(void *arg)
{
	nni_tcp_ep *ep = arg;

	nni_plat_tcp_fini(&ep->fd);
	NNI_FREE_STRUCT(ep);
}


static void
nni_tcp_ep_close(void *arg)
{
	nni_tcp_ep *ep = arg;

	nni_plat_tcp_shutdown(&ep->fd);
}


static int
nni_parseaddr(char *pair, char **hostp, uint16_t *portp)
{
	char *host, *port, *end;
	char c;
	int val;

	if (pair[0] == '[') {
		host = pair+1;
		// IP address enclosed ... for IPv6 usually.
		if ((end = strchr(host, ']')) == NULL) {
			return (NNG_EADDRINVAL);
		}
		*end = '\0';
		port = end + 1;
		if (*port == ':') {
			port++;
		} else if (port != '\0') {
			return (NNG_EADDRINVAL);
		}
	} else {
		host = pair;
		port = strchr(host, ':');
		if (port != NULL) {
			*port = '\0';
			port++;
		}
	}
	val = 0;
	while ((c = *port) != '\0') {
		val *= 10;
		if ((c >= '0') && (c <= '9')) {
			val += (c - '0');
		} else {
			return (NNG_EADDRINVAL);
		}
		if (val > 65535) {
			return (NNG_EADDRINVAL);
		}
		port++;
	}
	if ((strlen(host) == 0) || (strcmp(host, "*") == 0)) {
		*hostp = NULL;
	} else {
		*hostp = host;
	}
	// Stash the port in big endian (network) byte order.
	NNI_PUT16((uint8_t *) portp, val);
	return (0);
}


static int
nni_tcp_negotiate(nni_tcp_pipe *pipe)
{
	int rv;
	nni_iov iov;
	uint8_t buf[8];
	uint16_t peer;

	// First send our header..
	buf[0] = 0;
	buf[1] = 'S';
	buf[2] = 'P';
	buf[3] = 0;     // version
	NNI_PUT16(&buf[4], pipe->proto);
	NNI_PUT16(&buf[6], 0);

	iov.iov_buf = buf;
	iov.iov_len = 8;
	if ((rv = nni_plat_tcp_send(&pipe->fd, &iov, 1)) != 0) {
		return (rv);
	}

	iov.iov_buf = buf;
	iov.iov_len = 8;
	if ((rv = nni_plat_tcp_recv(&pipe->fd, &iov, 1)) != 0) {
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
nni_tcp_ep_connect(void *arg, void **pipep)
{
	nni_tcp_ep *ep = arg;
	nni_tcp_pipe *pipe;
	char *host;
	uint16_t port;
	int flag;
	char addr[NNG_MAXADDRLEN+1];
	nni_sockaddr lcladdr;
	nni_sockaddr remaddr;
	int rv;

	char *lclpart;
	char *rempart;

	flag = ep->ipv4only ? NNI_FLAG_IPV4ONLY : 0;
	snprintf(addr, sizeof (addr), "%s", ep->addr + strlen("tcp://"));

	if ((rempart = strchr(addr, ';')) != NULL) {
		*rempart = '\0';
		rempart++;
		lclpart = addr;

		if ((rv = nni_parseaddr(lclpart, &host, &port)) != 0) {
			return (rv);
		}
		if ((rv = nni_plat_lookup_host(host, &lcladdr, flag)) != 0) {
			return (rv);
		}
		// The port is in the same offset for both v4 and v6.
		lcladdr.s_un.s_in.sa_port = port;
	} else {
		lclpart = NULL;
		rempart = addr;
	}

	if ((rv = nni_parseaddr(rempart, &host, &port)) != 0) {
		return (rv);
	}
	if ((rv = nni_plat_lookup_host(host, &remaddr, flag)) != 0) {
		return (rv);
	}

	if ((pipe = NNI_ALLOC_STRUCT(pipe)) == NULL) {
		return (NNG_ENOMEM);
	}
	nni_plat_tcp_init(&pipe->fd);
	pipe->proto = ep->proto;
	pipe->rcvmax = ep->rcvmax;

	// Port is in the same place for both v4 and v6.
	remaddr.s_un.s_in.sa_port = port;

	rv = nni_plat_tcp_connect(&pipe->fd, &remaddr,
		lclpart == NULL ? NULL : &lcladdr);
	if (rv != 0) {
		NNI_FREE_STRUCT(pipe);
		return (rv);
	}

	if ((rv = nni_tcp_negotiate(pipe)) != 0) {
		nni_plat_tcp_shutdown(&pipe->fd);
		nni_plat_tcp_fini(&pipe->fd);
		NNI_FREE_STRUCT(pipe);
		return (rv);
	}
	*pipep = pipe;
	return (0);
}


static int
nni_tcp_ep_bind(void *arg)
{
	nni_tcp_ep *ep = arg;
	char addr[NNG_MAXADDRLEN+1];
	char *host;
	uint16_t port;
	int flag;
	int rv;
	nni_sockaddr baddr;

	flag = ep->ipv4only ? NNI_FLAG_IPV4ONLY : 0;

	// We want to strok this, so make a copy.  Skip the scheme.
	snprintf(addr, sizeof (addr), "%s", ep->addr + strlen("tcp://"));

	if ((rv = nni_parseaddr(addr, &host, &port)) != 0) {
		return (rv);
	}
	if ((rv = nni_plat_lookup_host(host, &baddr, flag)) != 0) {
		return (rv);
	}
	baddr.s_un.s_in.sa_port = port;

	if ((rv = nni_plat_tcp_listen(&ep->fd, &baddr)) != 0) {
		return (rv);
	}
	return (0);
}


static int
nni_tcp_ep_accept(void *arg, void **pipep)
{
	nni_tcp_ep *ep = arg;
	nni_tcp_pipe *pipe;
	int rv;


	if ((pipe = NNI_ALLOC_STRUCT(pipe)) == NULL) {
		return (NNG_ENOMEM);
	}
	pipe->proto = ep->proto;
	pipe->rcvmax = ep->rcvmax;
	nni_plat_tcp_init(&pipe->fd);

	if ((rv = nni_plat_tcp_accept(&pipe->fd, &ep->fd)) != 0) {
		NNI_FREE_STRUCT(pipe);
		return (rv);
	}
	if ((rv = nni_tcp_negotiate(pipe)) != 0) {
		nni_plat_tcp_shutdown(&pipe->fd);
		nni_plat_tcp_fini(&pipe->fd);
		NNI_FREE_STRUCT(pipe);
		return (rv);
	}
	*pipep = pipe;
	return (0);
}


static nni_tran_pipe nni_tcp_pipe_ops = {
	.pipe_destroy	= nni_tcp_pipe_destroy,
	.pipe_send	= nni_tcp_pipe_send,
	.pipe_recv	= nni_tcp_pipe_recv,
	.pipe_close	= nni_tcp_pipe_close,
	.pipe_peer	= nni_tcp_pipe_peer,
	.pipe_getopt	= nni_tcp_pipe_getopt,
};

static nni_tran_ep nni_tcp_ep_ops = {
	.ep_init	= nni_tcp_ep_init,
	.ep_fini	= nni_tcp_ep_fini,
	.ep_connect	= nni_tcp_ep_connect,
	.ep_bind	= nni_tcp_ep_bind,
	.ep_accept	= nni_tcp_ep_accept,
	.ep_close	= nni_tcp_ep_close,
	.ep_setopt	= NULL,
	.ep_getopt	= NULL,
};

// This is the TCP transport linkage, and should be the only global
// symbol in this entire file.
struct nni_tran nni_tcp_tran = {
	.tran_scheme	= "tcp",
	.tran_ep	= &nni_tcp_ep_ops,
	.tran_pipe	= &nni_tcp_pipe_ops,
	.tran_init	= nni_tcp_tran_init,
	.tran_fini	= nni_tcp_tran_fini,
};
