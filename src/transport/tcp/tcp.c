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

// TCP transport.   Platform specific TCP operations must be
// supplied as well.

typedef struct nni_tcp_pipe	nni_tcp_pipe;
typedef struct nni_tcp_ep	nni_tcp_ep;

// nni_tcp_pipe is one end of a TCP connection.
struct nni_tcp_pipe {
	const char *		addr;
	nni_plat_tcpsock *	tsp;
	uint16_t		peer;
	uint16_t		proto;
	size_t			rcvmax;

	nni_aio *		user_txaio;
	nni_aio *		user_rxaio;

	uint8_t			txlen[sizeof (uint64_t)];
	uint8_t			rxlen[sizeof (uint64_t)];
	nni_aio			txaio;
	nni_aio			rxaio;
	nni_msg *		rxmsg;
};

struct nni_tcp_ep {
	char			addr[NNG_MAXADDRLEN+1];
	nni_plat_tcpsock *	tsp;
	int			closed;
	uint16_t		proto;
	size_t			rcvmax;
	int			ipv4only;
};


static void nni_tcp_pipe_send_cb(void *);
static void nni_tcp_pipe_recv_cb(void *);

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

	nni_plat_tcp_shutdown(pipe->tsp);
}


static int
nni_tcp_pipe_init(void **argp)
{
	nni_tcp_pipe *pipe;
	int rv;

	if ((pipe = NNI_ALLOC_STRUCT(pipe)) == NULL) {
		return (NNG_ENOMEM);
	}
	if ((rv = nni_plat_tcp_init(&pipe->tsp)) != 0) {
		NNI_FREE_STRUCT(pipe);
		return (rv);
	}
	rv = nni_aio_init(&pipe->txaio, nni_tcp_pipe_send_cb, pipe);
	if (rv != 0) {
		nni_plat_tcp_fini(pipe->tsp);
		NNI_FREE_STRUCT(pipe);
		return (rv);
	}
	rv = nni_aio_init(&pipe->rxaio, nni_tcp_pipe_recv_cb, pipe);
	if (rv != 0) {
		nni_aio_fini(&pipe->txaio);
		nni_plat_tcp_fini(pipe->tsp);
		NNI_FREE_STRUCT(pipe);
	}
	*argp = pipe;
	return (0);
}


static void
nni_tcp_pipe_fini(void *arg)
{
	nni_tcp_pipe *pipe = arg;

	nni_aio_fini(&pipe->rxaio);
	nni_aio_fini(&pipe->txaio);
	nni_plat_tcp_fini(pipe->tsp);
	NNI_FREE_STRUCT(pipe);
}


static void
nni_tcp_pipe_send_cb(void *arg)
{
	nni_tcp_pipe *pipe = arg;
	int rv;
	nni_aio *aio;
	size_t len;

	if ((aio = pipe->user_txaio) == NULL) {
		// This should never ever happen.
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
nni_tcp_pipe_recv_cb(void *arg)
{
	nni_tcp_pipe *pipe = arg;
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
		// We should have gotten a message header.
		NNI_GET64(pipe->rxlen, len);

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

		rv = nni_plat_tcp_aio_recv(pipe->tsp, &pipe->rxaio);
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
nni_tcp_pipe_aio_send(void *arg, nni_aio *aio)
{
	nni_tcp_pipe *pipe = arg;
	nni_msg *msg = aio->a_msg;
	uint64_t len;

	pipe->user_txaio = aio;

	len = nni_msg_len(msg) + nni_msg_header_len(msg);
	NNI_PUT64(pipe->txlen, len);

	pipe->txaio.a_iov[0].iov_buf = pipe->txlen;
	pipe->txaio.a_iov[0].iov_len = sizeof (pipe->txlen);
	pipe->txaio.a_iov[1].iov_buf = nni_msg_header(msg);
	pipe->txaio.a_iov[1].iov_len = nni_msg_header_len(msg);
	pipe->txaio.a_iov[2].iov_buf = nni_msg_body(msg);
	pipe->txaio.a_iov[2].iov_len = nni_msg_len(msg);
	pipe->txaio.a_niov = 3;

	return (nni_plat_tcp_aio_send(pipe->tsp, &pipe->txaio));
}


static int
nni_tcp_pipe_aio_recv(void *arg, nni_aio *aio)
{
	nni_tcp_pipe *pipe = arg;

	pipe->user_rxaio = aio;

	NNI_ASSERT(pipe->rxmsg == NULL);

	// Schedule a read of the TCP header.
	pipe->rxaio.a_iov[0].iov_buf = pipe->rxlen;
	pipe->rxaio.a_iov[0].iov_len = sizeof (pipe->rxlen);
	pipe->rxaio.a_niov = 1;

	return (nni_plat_tcp_aio_recv(pipe->tsp, &pipe->rxaio));
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
nni_tcp_ep_init(void **epp, const char *url, nni_sock *sock)
{
	nni_tcp_ep *ep;
	int rv;

	if (strlen(url) > NNG_MAXADDRLEN-1) {
		return (NNG_EADDRINVAL);
	}
	if ((ep = NNI_ALLOC_STRUCT(ep)) == NULL) {
		return (NNG_ENOMEM);
	}
	ep->closed = 0;
	ep->proto = nni_sock_proto(sock);
	ep->ipv4only = 0; // XXX: FIXME
	ep->rcvmax = nni_sock_rcvmaxsz(sock);

	if ((rv = nni_plat_tcp_init(&ep->tsp)) != 0) {
		NNI_FREE_STRUCT(ep);
		return (rv);
	}

	(void) snprintf(ep->addr, sizeof (ep->addr), "%s", url);

	*epp = ep;
	return (0);
}


static void
nni_tcp_ep_fini(void *arg)
{
	nni_tcp_ep *ep = arg;

	nni_plat_tcp_fini(ep->tsp);
	NNI_FREE_STRUCT(ep);
}


static void
nni_tcp_ep_close(void *arg)
{
	nni_tcp_ep *ep = arg;

	nni_plat_tcp_shutdown(ep->tsp);
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

	// First send our header..
	buf[0] = 0;
	buf[1] = 'S';
	buf[2] = 'P';
	buf[3] = 0;     // version
	NNI_PUT16(&buf[4], pipe->proto);
	NNI_PUT16(&buf[6], 0);

	iov.iov_buf = buf;
	iov.iov_len = 8;
	if ((rv = nni_plat_tcp_send(pipe->tsp, &iov, 1)) != 0) {
		return (rv);
	}

	iov.iov_buf = buf;
	iov.iov_len = 8;
	if ((rv = nni_plat_tcp_recv(pipe->tsp, &iov, 1)) != 0) {
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
nni_tcp_ep_connect(void *arg, void *pipearg)
{
	nni_tcp_ep *ep = arg;
	nni_tcp_pipe *pipe = pipearg;
	char *host;
	uint16_t port;
	int flag;
	char addr[NNG_MAXADDRLEN+1];
	nni_sockaddr lcladdr;
	nni_sockaddr remaddr;
	nni_sockaddr *bindaddr;
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
	if (host == NULL) {
		return (NNG_EADDRINVAL);
	}
	if ((rv = nni_plat_lookup_host(host, &remaddr, flag)) != 0) {
		return (rv);
	}

	pipe->proto = ep->proto;
	pipe->rcvmax = ep->rcvmax;

	// Port is in the same place for both v4 and v6.
	remaddr.s_un.s_in.sa_port = port;

	bindaddr = lclpart == NULL ? NULL : &lcladdr;
	rv = nni_plat_tcp_connect(pipe->tsp, &remaddr, bindaddr);
	if (rv != 0) {
		return (rv);
	}

	if ((rv = nni_tcp_negotiate(pipe)) != 0) {
		nni_plat_tcp_shutdown(pipe->tsp);
		return (rv);
	}
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

	if ((rv = nni_plat_tcp_listen(ep->tsp, &baddr)) != 0) {
		return (rv);
	}
	return (0);
}


static int
nni_tcp_ep_accept(void *arg, void *pipearg)
{
	nni_tcp_ep *ep = arg;
	nni_tcp_pipe *pipe = pipearg;
	int rv;

	pipe->proto = ep->proto;
	pipe->rcvmax = ep->rcvmax;

	if ((rv = nni_plat_tcp_accept(pipe->tsp, ep->tsp)) != 0) {
		return (rv);
	}
	if ((rv = nni_tcp_negotiate(pipe)) != 0) {
		nni_plat_tcp_shutdown(pipe->tsp);
		return (rv);
	}
	return (0);
}


static nni_tran_pipe nni_tcp_pipe_ops = {
	.p_init		= nni_tcp_pipe_init,
	.p_fini		= nni_tcp_pipe_fini,
	.p_aio_send	= nni_tcp_pipe_aio_send,
	.p_aio_recv	= nni_tcp_pipe_aio_recv,
	.p_close	= nni_tcp_pipe_close,
	.p_peer		= nni_tcp_pipe_peer,
	.p_getopt	= nni_tcp_pipe_getopt,
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
