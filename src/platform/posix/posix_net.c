//
// Copyright 2017 Garrett D'Amore <garrett@damore.org>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "core/nng_impl.h"

#ifdef PLATFORM_POSIX_NET
#include "platform/posix/posix_aio.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>

static int
nni_posix_tcp_addr(struct sockaddr_storage *ss, const nni_sockaddr *sa)
{
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;

	switch (sa->s_un.s_family) {
	case NNG_AF_INET:
		sin = (void *) ss;
		memset(sin, 0, sizeof (*sin));
		sin->sin_family = PF_INET;
		sin->sin_port = sa->s_un.s_in.sa_port;
		sin->sin_addr.s_addr = sa->s_un.s_in.sa_addr;
		return (sizeof (*sin));


	case NNG_AF_INET6:
		sin6 = (void *) ss;
		memset(sin6, 0, sizeof (*sin6));
#ifdef  SIN6_LEN
		sin6->sin6_len = sizeof (*sin6);
#endif
		sin6->sin6_family = PF_INET6;
		sin6->sin6_port = sa->s_un.s_in6.sa_port;
		memcpy(sin6->sin6_addr.s6_addr, sa->s_un.s_in6.sa_addr, 16);
		return (sizeof (*sin6));
	}
	return (-1);
}


extern int nni_tcp_parse_url(char *, char **, char **, char **, char **);

int
nni_plat_tcp_ep_init(nni_plat_tcp_ep **epp, const char *url, int mode)
{
	nni_posix_epdesc *ed;
	char buf[NNG_MAXADDRLEN];
	int rv;
	char *lhost, *rhost;
	char *lserv, *rserv;
	char *sep;
	struct sockaddr_storage ss;
	int len;
	int passive;
	nni_aio aio;

	if ((rv = nni_posix_epdesc_init(&ed, url)) != 0) {
		return (rv);
	}

	// Make a local copy.
	snprintf(buf, sizeof (buf), "%s", url);
	nni_aio_init(&aio, NULL, NULL);

	if (mode == NNI_EP_MODE_DIAL) {
		rv = nni_tcp_parse_url(buf, &rhost, &rserv, &lhost, &lserv);
		if (rv != 0) {
			goto done;
		}

		// We have to have a remote destination!
		if ((rhost == NULL) || (rserv == NULL)) {
			rv = NNG_EADDRINVAL;
			goto done;
		}
	} else {
		rv = nni_tcp_parse_url(buf, &lhost, &lserv, &rhost, &rserv);
		if (rv != 0) {
			goto done;
		}
		if ((rhost != NULL) || (rserv != NULL)) {
			// remotes are nonsensical here.
			rv = NNG_EADDRINVAL;
			goto done;
		}
		if (lserv == NULL) {
			// missing port to listen on!
			rv = NNG_EADDRINVAL;
			goto done;
		}
	}

	if ((rserv != NULL) || (rhost != NULL)) {
		nni_plat_tcp_resolv(rhost, rserv, NNG_AF_UNSPEC, 0, &aio);
		nni_aio_wait(&aio);
		if ((rv = nni_aio_result(&aio)) != 0) {
			goto done;
		}
		len = nni_posix_tcp_addr(&ss, &aio.a_addrs[0]);
		nni_posix_epdesc_set_remote(ed, &ss, len);
	}

	if ((lserv != NULL) || (lhost != NULL)) {
		nni_plat_tcp_resolv(lhost, lserv, NNG_AF_UNSPEC, 1, &aio);
		nni_aio_wait(&aio);
		if ((rv = nni_aio_result(&aio)) != 0) {
			goto done;
		}
		len = nni_posix_tcp_addr(&ss, &aio.a_addrs[0]);
		nni_posix_epdesc_set_local(ed, &ss, len);
	}
	*epp = (void *) ed;
	return (0);

done:
	if (rv != 0) {
		nni_posix_epdesc_fini(ed);
	}
	nni_aio_fini(&aio);
	return (rv);
}


void
nni_plat_tcp_ep_fini(nni_plat_tcp_ep *ep)
{
	nni_posix_epdesc_fini((void *) ep);
}


void
nni_plat_tcp_ep_close(nni_plat_tcp_ep *ep)
{
	nni_posix_epdesc_close((void *) ep);
}


int
nni_plat_tcp_ep_listen(nni_plat_tcp_ep *ep)
{
	return (nni_posix_epdesc_listen((void *) ep));
}


void
nni_plat_tcp_ep_connect(nni_plat_tcp_ep *ep, nni_aio *aio)
{
	return (nni_posix_epdesc_connect((void *) ep, aio));
}


void
nni_plat_tcp_ep_accept(nni_plat_tcp_ep *ep, nni_aio *aio)
{
	return (nni_posix_epdesc_accept((void *) ep, aio));
}


void
nni_plat_tcp_pipe_fini(nni_plat_tcp_pipe *p)
{
	nni_posix_pipedesc_fini((void *) p);
}


void
nni_plat_tcp_pipe_close(nni_plat_tcp_pipe *p)
{
	nni_posix_pipedesc_close((void *) p);
}


void
nni_plat_tcp_pipe_send(nni_plat_tcp_pipe *p, nni_aio *aio)
{
	nni_posix_pipedesc_send((void *) p, aio);
}


void
nni_plat_tcp_pipe_recv(nni_plat_tcp_pipe *p, nni_aio *aio)
{
	nni_posix_pipedesc_recv((void *) p, aio);
}


#else

// Suppress empty symbols warnings in ranlib.
int nni_posix_net_not_used = 0;

#endif // PLATFORM_POSIX_NET
