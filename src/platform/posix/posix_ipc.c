//
// Copyright 2017 Garrett D'Amore <garrett@damore.org>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "core/nng_impl.h"

#ifdef PLATFORM_POSIX_IPC

#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <fcntl.h>
#include <unistd.h>
#include <netdb.h>


#ifdef  SOCK_CLOEXEC
#define NNI_IPC_SOCKTYPE	(SOCK_STREAM | SOCK_CLOEXEC)
#else
#define NNI_IPC_SOCKTYPE	SOCK_STREAM
#endif

static int
nni_plat_ipc_path_to_sockaddr(struct sockaddr_un *sun, const char *path)
{
	memset(sun, 0, sizeof (*sun));
	sun->sun_family = PF_UNIX;

	// Technically on some platforms we could support path names larger
	// than the path, and on others we could skip null termination.  We
	// take a conservative approach, which is that the path must fit in
	// the supplied character array, and *must* be NULL terminated.

	// TODO: abstract sockets, including autobind sockets.
	if (strlen(path) >= sizeof (sun->sun_path)) {
		return (NNG_EADDRINVAL);
	}
	if (strlen(path) == 0) {
		return (-1);
	}
	snprintf(sun->sun_path, sizeof (sun->sun_path), "%s", path);
	return (sizeof (*sun));
}


int
nni_plat_ipc_send(nni_plat_ipcsock *s, nni_iov *iovs, int cnt)
{
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
		rv = writev(s->fd, &iov[i], cnt);
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

	return (0);
}


int
nni_plat_ipc_recv(nni_plat_ipcsock *s, nni_iov *iovs, int cnt)
{
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
		rv = readv(s->fd, &iov[i], cnt);
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

	return (0);
}


static void
nni_plat_ipc_setopts(int fd)
{
	int one;

	// Try to ensure that both CLOEXEC is set, and that we don't
	// generate SIGPIPE.  (Note that SIGPIPE suppression in this way
	// only works on BSD systems.  Linux wants us to use sendmsg().)
	(void) fcntl(fd, F_SETFD, FD_CLOEXEC);
#if defined(F_SETNOSIGPIPE)
	(void) fcntl(fd, F_SETNOSIGPIPE, 1);
#elif defined(SO_NOSIGPIPE)
	one = 1;
	(void) setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof (one));
#endif
}


int
nni_plat_ipc_init(nni_plat_ipcsock *s)
{
	s->fd = -1;
	return (0);
}


void
nni_plat_ipc_fini(nni_plat_ipcsock *s)
{
	if (s->fd != -1) {
		(void) close(s->fd);
		s->fd = -1;
	}
	if (s->unlink != NULL) {
		(void) unlink(s->unlink);
		nni_free(s->unlink, strlen(s->unlink) + 1);
	}
}


void
nni_plat_ipc_shutdown(nni_plat_ipcsock *s)
{
	if (s->fd != -1) {
		(void) shutdown(s->fd, SHUT_RDWR);
		// This causes the equivalent of a close.  Hopefully waking
		// up anything that didn't get the hint with the shutdown.
		// (macOS does not see the shtudown).
		(void) dup2(nni_plat_devnull, s->fd);
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
	return (0);
}


int
nni_plat_ipc_connect(nni_plat_ipcsock *s, const char *path)
{
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
	return (0);
}


int
nni_plat_ipc_accept(nni_plat_ipcsock *s, nni_plat_ipcsock *server)
{
	int fd;

	for (;;) {
#ifdef NNG_USE_ACCEPT4
		fd = accept4(server->fd, NULL, NULL, SOCK_CLOEXEC);
		if ((fd < 0) && ((errno == ENOSYS) || (errno == ENOTSUP))) {
			fd = accept(server->fd, NULL, NULL);
		}
#else
		fd = accept(server->fd, NULL, NULL);
#endif

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
	return (0);
}


#else

// Suppress empty symbols warnings in ranlib.
int nni_posix_ipc_not_used = 0;

#endif // PLATFORM_POSIX_IPC
