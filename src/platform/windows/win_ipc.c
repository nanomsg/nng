//
// Copyright 2017 Garrett D'Amore <garrett@damore.org>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "core/nng_impl.h"

#ifdef PLATFORM_WINDOWS


int
nni_plat_ipc_send(nni_plat_ipcsock *s, nni_iov *iovs, int cnt)
{
#if 0
	struct iovec iov[4];    // We never have more than 3 at present
	int i;
	int offset;
	int resid = 0;
	int rv;

	if (cnt > 4) {
		return (NNG_EINVAL);
	}

	for (i = 0; i < cnt; i++) {
		iov[i].iov_base = iovs[i].iov_buf;
		iov[i].iov_len = iovs[i].iov_len;
		resid += iov[i].iov_len;
	}

	i = 0;
	while (resid) {
		rv = writev(s->fd, iov, cnt);
		if (rv < 0) {
			if (rv == EINTR) {
				continue;
			}
			return (nni_plat_errno(errno));
		}
		if (rv > resid) {
			nni_panic("writev says it wrote too much!");
		}
		resid -= rv;
		while (rv) {
			if (iov[i].iov_len <= rv) {
				rv -= iov[i].iov_len;
				i++;
				cnt--;
			} else {
				iov[i].iov_len -= rv;
				iov[i].iov_base += rv;
				rv = 0;
			}
		}
	}
#endif
	return (NNG_ENOTSUP);
}


int
nni_plat_ipc_recv(nni_plat_ipcsock *s, nni_iov *iovs, int cnt)
{
#if  0
	struct iovec iov[4];    // We never have more than 3 at present
	int i;
	int offset;
	int resid = 0;
	int rv;

	if (cnt > 4) {
		return (NNG_EINVAL);
	}

	for (i = 0; i < cnt; i++) {
		iov[i].iov_base = iovs[i].iov_buf;
		iov[i].iov_len = iovs[i].iov_len;
		resid += iov[i].iov_len;
	}
	i = 0;
	while (resid) {
		rv = readv(s->fd, iov, cnt);
		if (rv < 0) {
			if (errno == EINTR) {
				continue;
			}
			return (nni_plat_errno(errno));
		}
		if (rv == 0) {
			return (NNG_ECLOSED);
		}
		if (rv > resid) {
			nni_panic("readv says it read too much!");
		}

		resid -= rv;
		while (rv) {
			if (iov[i].iov_len <= rv) {
				rv -= iov[i].iov_len;
				i++;
				cnt--;
			} else {
				iov[i].iov_len -= rv;
				iov[i].iov_base += rv;
				rv = 0;
			}
		}
	}
#endif
	return (NNG_ENOTSUP);
}


int
nni_plat_ipc_init(nni_plat_ipcsock *s)
{
	s->p = INVALID_HANDLE_VALUE;
	return (0);
}


void
nni_plat_ipc_fini(nni_plat_ipcsock *s)
{
	if (s->p != INVALID_HANDLE_VALUE) {
		(void) CloseHandle(s->p);
		s->p = INVALID_HANDLE_VALUE;
	}
}


void
nni_plat_ipc_shutdown(nni_plat_ipcsock *s)
{
	if (s->p != INVALID_HANDLE_VALUE) {
#if 0
		(void) shutdown(s->fd, SHUT_RDWR);
		// This causes the equivalent of a close.  Hopefully waking
		// up anything that didn't get the hint with the shutdown.
		// (macOS does not see the shtudown).
		(void) dup2(nni_plat_devnull, s->fd);
#endif
	}
}


// nni_plat_ipc_listen creates a file descriptor bound to the given address.
// This basically does the equivalent of socket, bind, and listen.  We have
// chosen a default value for the listen backlog of 128, which should be
// plenty.  (If it isn't, then the accept thread can't get enough resources
// to keep up, and your clients are going to experience bad things.  Normally
// the actual backlog should hover near 0 anyway.)
int
nni_plat_ipc_listen(nni_plat_ipcsock *s, const char *path)
{
#if 0
	int fd, checkfd;
	struct sockaddr_un sun;
	int rv;

	if (nni_plat_ipc_path_to_sockaddr(&sun, path) < 0) {
		return (NNG_EADDRINVAL);
	}

	if ((fd = socket(AF_UNIX, NNI_IPC_SOCKTYPE, 0)) < 0) {
		return (nni_plat_errno(errno));
	}

	// We are going to check to see if there was a name already there.
	// If there was, and nothing is listening (ECONNREFUSED), then we
	// will just try to cleanup the old socket.  Note that this is not
	// perfect in all scenarios, so use this with caution.
	if ((checkfd = socket(AF_UNIX, NNI_IPC_SOCKTYPE, 0)) < 0) {
		(void) close(fd);
		return (nni_plat_errno(errno));
	}

	// Nonblocking because we don't want to wait for any remote server.
	(void) fcntl(checkfd, F_SETFL, O_NONBLOCK);
	if (connect(checkfd, (struct sockaddr *) &sun, sizeof (sun)) < 0) {
		if (errno == ECONNREFUSED) {
			(void) unlink(path);
		}
	}
	(void) close(checkfd);

	nni_plat_ipc_setopts(fd);

	if ((s->unlink = nni_alloc(strlen(path) + 1)) == NULL) {
		return (NNG_ENOMEM);
	}
	strcpy(s->unlink, path);
	if (bind(fd, (struct sockaddr *) &sun, sizeof (sun)) < 0) {
		rv = nni_plat_errno(errno);
		nni_free(s->unlink, strlen(path) + 1);
		s->unlink = NULL;
		(void) close(fd);
		return (rv);
	}

	// Listen -- 128 depth is probably sufficient.  If it isn't, other
	// bad things are going to happen.
	if (listen(fd, 128) < 0) {
		rv = nni_plat_errno(errno);
		(void) close(fd);
		return (rv);
	}
	s->fd = fd;
#endif
	return (NNG_ENOTSUP);
}


int
nni_plat_ipc_connect(nni_plat_ipcsock *s, const char *path)
{
#if 0
	int fd;
	int len;
	struct sockaddr_un sun;
	int rv;

	if (nni_plat_ipc_path_to_sockaddr(&sun, path) < 0) {
		return (NNG_EADDRINVAL);
	}

	if ((fd = socket(AF_UNIX, NNI_IPC_SOCKTYPE, 0)) < 0) {
		return (nni_plat_errno(errno));
	}

	nni_plat_ipc_setopts(fd);

	if (connect(fd, (struct sockaddr *) &sun, sizeof (sun)) != 0) {
		rv = nni_plat_errno(errno);
		(void) close(fd);
		if (rv == NNG_ENOENT) {
			// In this case we want to treat this the same as
			// ECONNREFUSED, since they mean the same to us.
			rv = NNG_ECONNREFUSED;
		}
		return (rv);
	}
	s->fd = fd;
#endif
	return (NNG_ENOTSUP);
}


int
nni_plat_ipc_accept(nni_plat_ipcsock *s, nni_plat_ipcsock *server)
{
#if 0
	int fd;

	for (;;) {
		fd = accept(server->fd, NULL, NULL);

		if (fd < 0) {
			if ((errno == EINTR) || (errno == ECONNABORTED)) {
				// These are not fatal errors, keep trying
				continue;
			}
			if ((errno == EAGAIN) || (errno == EWOULDBLOCK)) {
				continue;
			}
			return (nni_plat_errno(errno));
		} else {
			break;
		}
	}

	nni_plat_ipc_setopts(fd);

	s->fd = fd;
#endif
	return (NNG_ENOTSUP);
}


#endif // PLATFORM_WINDOWS
