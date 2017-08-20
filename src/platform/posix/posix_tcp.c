//
// Copyright 2017 Garrett D'Amore <garrett@damore.org>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "core/nng_impl.h"

#ifdef NNG_PLATFORM_POSIX
#include "platform/posix/posix_aio.h"

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

extern int nni_tcp_parse_url(char *, char **, char **, char **, char **);

int
nni_plat_tcp_ep_init(nni_plat_tcp_ep **epp, const char *url, int mode)
{
	nni_posix_epdesc *      ed;
	char                    buf[NNG_MAXADDRLEN];
	int                     rv;
	char *                  lhost, *rhost;
	char *                  lserv, *rserv;
	char *                  sep;
	struct sockaddr_storage ss;
	int                     len;
	int                     passive;
	nni_aio                 aio;

	if ((rv = nni_posix_epdesc_init(&ed, url)) != 0) {
		return (rv);
	}

	// Make a local copy.
	snprintf(buf, sizeof(buf), "%s", url);
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
		len = nni_posix_nn2sockaddr((void *) &ss, &aio.a_addrs[0]);
		nni_posix_epdesc_set_remote(ed, &ss, len);
	}

	if ((lserv != NULL) || (lhost != NULL)) {
		nni_plat_tcp_resolv(lhost, lserv, NNG_AF_UNSPEC, 1, &aio);
		nni_aio_wait(&aio);
		if ((rv = nni_aio_result(&aio)) != 0) {
			goto done;
		}
		len = nni_posix_nn2sockaddr((void *) &ss, &aio.a_addrs[0]);
		nni_posix_epdesc_set_local(ed, &ss, len);
	}
	nni_aio_fini(&aio);
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

#endif // NNG_PLATFORM_POSIX
