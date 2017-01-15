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

// Windows has infinite numbers of error codes it seems.  We only bother
// with the ones that are relevant to us (we think).
static struct {
	int	win_err;
	int	nng_err;
}
nni_winpipe_errnos[] = {
	{ ERROR_FILE_NOT_FOUND,	    NNG_ENOENT	     },
	{ ERROR_ACCESS_DENIED,	    NNG_EPERM	     },
	{ ERROR_INVALID_HANDLE,	    NNG_ECLOSED	     },
	{ ERROR_NOT_ENOUGH_MEMORY,  NNG_ENOMEM	     },
	{ ERROR_INVALID_ACCESS,	    NNG_EPERM	     },
	{ ERROR_INVALID_DATA,	    NNG_EINVAL	     },
	{ ERROR_OUTOFMEMORY,	    NNG_ENOMEM	     },
	{ ERROR_HANDLE_EOF,	    NNG_ECLOSED	     },
	{ ERROR_NOT_SUPPORTED,	    NNG_ENOTSUP	     },
	{ ERROR_OUT_OF_STRUCTURES,  NNG_ENOMEM	     },
	{ ERROR_INVALID_PARAMETER,  NNG_EINVAL	     },
	{ ERROR_CONNECTION_REFUSED, NNG_ECONNREFUSED },
	{ ERROR_BROKEN_PIPE,	    NNG_ECLOSED	     },
	{ ERROR_BAD_PIPE,	    NNG_ECLOSED	     },
	{ ERROR_NO_DATA,	    NNG_ECLOSED	     },
	{ ERROR_PIPE_NOT_CONNECTED, NNG_ECLOSED	     },
	{ ERROR_OPERATION_ABORTED,  NNG_ECLOSED	     },
	{ WAIT_TIMEOUT,		    NNG_ETIMEDOUT    },
	// Must be Last!!
	{			 0,		   0 },
};


static int
nni_winpipe_error(int werr)
{
	int i;

	if (werr == 0) {
		return (0);
	}

	for (i = 0; nni_winpipe_errnos[i].nng_err != 0; i++) {
		if (werr == nni_winpipe_errnos[i].win_err) {
			return (nni_winpipe_errnos[i].nng_err);
		}
	}
	// Other system errno.
	return (NNG_ESYSERR + werr);
}


int
nni_plat_ipc_send(nni_plat_ipcsock *s, nni_iov *iovs, int cnt)
{
	int i;
	DWORD nsent;
	DWORD resid;
	char *buf;
	DWORD len;
	nni_iov iov[4];
	int rv;
	OVERLAPPED *olp = &s->send_olpd;

	NNI_ASSERT(cnt <= 4);
	for (i = 0, resid = 0; i < cnt; resid += iov[i].iov_len, i++) {
		iov[i].iov_len = iovs[i].iov_len;
		iov[i].iov_buf = iovs[i].iov_buf;
	}

	i = 0;
	while (resid) {
		NNI_ASSERT(i < cnt);
		nsent = 0;
		// We limit ourselves to writing 16MB at a time.  Named Pipes
		// on Windows have limits of between 31 and 64MB.
		len = iov[i].iov_len > 0x1000000 ? 0x1000000 : iov[i].iov_len;
		buf = iov[i].iov_buf;

		if (!WriteFile(s->p, buf, len, NULL, olp)) {
			if ((rv = GetLastError()) != ERROR_IO_PENDING) {
				return (nni_winpipe_error(rv));
			}
		}
		if (!GetOverlappedResult(s->p, olp, &nsent, TRUE)) {
			rv = GetLastError();
			return (nni_winpipe_error(rv));
		}
		NNI_ASSERT(nsent <= resid);
		NNI_ASSERT(nsent <= len);
		resid -= nsent;
		if (nsent < iov[i].iov_len) {
			iov[i].iov_buf = buf + nsent;
			iov[i].iov_len -= nsent;
		} else {
			i++;
		}
	}
	return (0);
}


int
nni_plat_ipc_recv(nni_plat_ipcsock *s, nni_iov *iovs, int cnt)
{
	int i;
	DWORD nrecv;
	DWORD resid;
	DWORD len;
	char *buf;
	nni_iov iov[4];
	int rv;
	OVERLAPPED *olp = &s->recv_olpd;

	NNI_ASSERT(cnt <= 4);
	for (i = 0, resid = 0; i < cnt; resid += iov[i].iov_len, i++) {
		iov[i].iov_len = iovs[i].iov_len;
		iov[i].iov_buf = iovs[i].iov_buf;
	}

	i = 0;
	while (resid) {
		NNI_ASSERT(i < cnt);
		nrecv = 0;
		// We limit ourselves to writing 16MB at a time.  Named Pipes
		// on Windows have limits of between 31 and 64MB.
		len = iov[i].iov_len > 0x1000000 ? 0x1000000 : iov[i].iov_len;
		buf = iov[i].iov_buf;

		if (!ReadFile(s->p, buf, len, NULL, olp)) {
			if ((rv = GetLastError()) != ERROR_IO_PENDING) {
				return (nni_winpipe_error(rv));
			}
		}
		if (!GetOverlappedResult(s->p, olp, &nrecv, TRUE)) {
			rv = GetLastError();
			return (nni_winpipe_error(rv));
		}
		NNI_ASSERT(nrecv <= resid);
		NNI_ASSERT(nrecv <= len);
		resid -= nrecv;
		if (nrecv < iov[i].iov_len) {
			iov[i].iov_buf = buf + nrecv;
			iov[i].iov_len -= nrecv;
		} else {
			i++;
		}
	}
	return (0);
}


int
nni_plat_ipc_init(nni_plat_ipcsock *s)
{
	int rv;

	s->p = INVALID_HANDLE_VALUE;
	s->recv_olpd.hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
	if (s->recv_olpd.hEvent == INVALID_HANDLE_VALUE) {
		rv = GetLastError();
		return (nni_winpipe_error(rv));
	}
	s->send_olpd.hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
	if (s->send_olpd.hEvent == INVALID_HANDLE_VALUE) {
		rv = GetLastError();
		CloseHandle(s->recv_olpd.hEvent);
		return (nni_winpipe_error(rv));
	}
	s->conn_olpd.hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
	if (s->conn_olpd.hEvent == INVALID_HANDLE_VALUE) {
		rv = GetLastError();
		CloseHandle(s->send_olpd.hEvent);
		CloseHandle(s->recv_olpd.hEvent);
		return (nni_winpipe_error(rv));
	}
	InitializeCriticalSection(&s->cs);
	return (0);
}


static void
nni_plat_ipc_close(nni_plat_ipcsock *s)
{
	HANDLE fd;

	EnterCriticalSection(&s->cs);
	if ((fd = s->p) != INVALID_HANDLE_VALUE) {
		s->p = INVALID_HANDLE_VALUE;
		if (s->server) {
			(void) DisconnectNamedPipe(fd);
		}
		(void) CancelIoEx(fd, &s->send_olpd);
		(void) CancelIoEx(fd, &s->recv_olpd);
		(void) CancelIoEx(fd, &s->conn_olpd);
		(void) CloseHandle(fd);
	}
	LeaveCriticalSection(&s->cs);
}


void
nni_plat_ipc_fini(nni_plat_ipcsock *s)
{
	nni_plat_ipc_close(s);
	DeleteCriticalSection(&s->cs);
	CloseHandle(s->recv_olpd.hEvent);
	CloseHandle(s->send_olpd.hEvent);
	CloseHandle(s->conn_olpd.hEvent);
}


void
nni_plat_ipc_shutdown(nni_plat_ipcsock *s)
{
	nni_plat_ipc_close(s);
}


int
nni_plat_ipc_listen(nni_plat_ipcsock *s, const char *path)
{
	int rv;

	snprintf(s->path, sizeof (s->path), "\\\\.\\pipe\\%s", path);

	// We create the first named pipe, and we make sure that it is
	// properly ours.
	s->p = CreateNamedPipeA(
		s->path,
		PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED |
		FILE_FLAG_FIRST_PIPE_INSTANCE,
		PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT |
		PIPE_REJECT_REMOTE_CLIENTS,
		PIPE_UNLIMITED_INSTANCES,
		4096, 4096, 0, NULL);

	if (s->p == INVALID_HANDLE_VALUE) {
		if ((rv = GetLastError()) == ERROR_ACCESS_DENIED) {
			return (NNG_EADDRINUSE);
		}
		return (nni_winpipe_error(rv));
	}
	s->server = 1;

	return (0);
}


int
nni_plat_ipc_accept(nni_plat_ipcsock *s, nni_plat_ipcsock *server)
{
	int rv;
	OVERLAPPED *olp = &s->conn_olpd;
	HANDLE newp;
	DWORD nbytes;

	s->server = 1;
	if (!ConnectNamedPipe(server->p, olp)) {
		rv = GetLastError();
		switch (rv) {
		case ERROR_PIPE_CONNECTED:
			break;
		case ERROR_IO_PENDING:
			if (!GetOverlappedResult(server->p, olp, &nbytes,
			    TRUE)) {
				rv = GetLastError();
				return (nni_winpipe_error(rv));
			}
		default:
			rv = GetLastError();
			return (nni_winpipe_error(rv));
		}
	}

	EnterCriticalSection(&server->cs);
	if (server->p != INVALID_HANDLE_VALUE) {
		s->p = server->p;
		server->p = CreateNamedPipeA(
			server->path,
			PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
			PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT |
			PIPE_REJECT_REMOTE_CLIENTS,
			PIPE_UNLIMITED_INSTANCES,
			4096, 4096, 0, NULL);
		if (server->p == INVALID_HANDLE_VALUE) {
			// We return the old handle, so that future accept
			// attempts have a chance of succeeding.  That means
			// we will disconnect the current client.
			rv = GetLastError();
			server->p = s->p;
			DisconnectNamedPipe(server->p);
			s->p = INVALID_HANDLE_VALUE;
			LeaveCriticalSection(&server->cs);
			return (nni_winpipe_error(rv));
		}
	}
	LeaveCriticalSection(&server->cs);

	return (0);
}


int
nni_plat_ipc_connect(nni_plat_ipcsock *s, const char *path)
{
	int rv;

	snprintf(s->path, sizeof (s->path), "\\\\.\\pipe\\%s", path);

	for (;;) {
		s->p = CreateFileA(s->path, GENERIC_READ | GENERIC_WRITE,
			0, NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);
		if (s->p == INVALID_HANDLE_VALUE) {
			rv = GetLastError();
			switch (rv) {
			case ERROR_PIPE_BUSY:
				if (!WaitNamedPipe(s->path,
				    NMPWAIT_USE_DEFAULT_WAIT)) {
					return (NNG_ETIMEDOUT);
				}
				continue;
			case ERROR_FILE_NOT_FOUND:
				// No present pipes (no listener?)
				return (NNG_ECONNREFUSED);

			default:
				return (nni_winpipe_error(rv));
			}
		}
		s->server = 0;
		break;
	}
	return (0);
}


#endif // PLATFORM_WINDOWS
