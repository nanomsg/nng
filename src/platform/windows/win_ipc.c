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

#include <stdio.h>

static void nni_win_ipc_acc_cb(void *);
static void nni_win_ipc_send_cb(void *);
static void nni_win_ipc_recv_cb(void *);
static void nni_win_ipc_send_start(nni_plat_ipc_pipe *);
static void nni_win_ipc_recv_start(nni_plat_ipc_pipe *);

struct nni_plat_ipc_pipe {
	HANDLE        p;
	nni_win_event recv_evt;
	nni_win_event send_evt;
	nni_mtx       mtx;
	nni_list      readq;
	nni_list      writeq;
};

struct nni_plat_ipc_ep {
	char          path[256];
	int           mode;
	int           started;
	nni_list      aios;
	HANDLE        p;       // accept side only
	nni_win_event acc_evt; // accept side only
	nni_mtx       mtx;     // accept side only
	nni_list_node node;    // conn side uses this
};

static int
nni_win_ipc_pipe_init(nni_plat_ipc_pipe **pipep, HANDLE p)
{
	nni_plat_ipc_pipe *pipe;
	int                rv;

	if ((pipe = NNI_ALLOC_STRUCT(pipe)) == NULL) {
		return (NNG_ENOMEM);
	}
	if ((rv = nni_mtx_init(&pipe->mtx)) != 0) {
		NNI_FREE_STRUCT(pipe);
		return (rv);
	}
	rv = nni_win_event_init(&pipe->recv_evt, nni_win_ipc_recv_cb, pipe, p);
	if (rv != 0) {
		nni_plat_ipc_pipe_fini(pipe);
		return (rv);
	}
	rv = nni_win_event_init(&pipe->send_evt, nni_win_ipc_send_cb, pipe, p);
	if (rv != 0) {
		nni_plat_ipc_pipe_fini(pipe);
		return (rv);
	}

	pipe->p = p;
	nni_aio_list_init(&pipe->readq);
	nni_aio_list_init(&pipe->writeq);
	*pipep = pipe;
	return (0);
}

static void
nni_win_ipc_send_cancel(nni_aio *aio)
{
	nni_plat_ipc_pipe *pipe = aio->a_prov_data;

	nni_mtx_lock(&pipe->mtx);
	nni_win_event_cancel(&pipe->recv_evt);
	nni_aio_list_remove(aio);
	nni_mtx_unlock(&pipe->mtx);
}

static void
nni_win_ipc_send_finish(nni_plat_ipc_pipe *pipe)
{
	nni_win_event *evt  = &pipe->send_evt;
	OVERLAPPED *   olpd = nni_win_event_overlapped(evt);
	int            rv   = 0;
	nni_aio *      aio;
	DWORD          cnt;

	if (GetOverlappedResult(pipe->p, olpd, &cnt, TRUE) == FALSE) {
		rv = nni_win_error(GetLastError());
	}
	if ((aio = nni_list_first(&pipe->writeq)) == NULL) {
		// If the AIO was canceled, but IOCP thread was still
		// working on it, we might have seen this.
		return;
	}
	if (rv == 0) {
		NNI_ASSERT(cnt <= aio->a_iov[0].iov_len);
		aio->a_count += cnt;
		aio->a_iov[0].iov_buf = (char *) aio->a_iov[0].iov_buf + cnt;
		aio->a_iov[0].iov_len -= cnt;

		if (aio->a_iov[0].iov_len == 0) {
			int i;
			for (i = 1; i < aio->a_niov; i++) {
				aio->a_iov[i - 1] = aio->a_iov[i];
			}
			aio->a_niov--;
		}

		if (aio->a_niov > 0) {
			// If we have more to do, submit it!
			nni_win_ipc_send_start(pipe);
			return;
		}
	}

	// All done; hopefully successfully.
	nni_list_remove(&pipe->writeq, aio);
	nni_aio_finish(aio, rv, aio->a_count);
}

static void
nni_win_ipc_send_start(nni_plat_ipc_pipe *pipe)
{
	void *         buf;
	DWORD          len;
	int            rv;
	nni_win_event *evt  = &pipe->send_evt;
	OVERLAPPED *   olpd = nni_win_event_overlapped(evt);
	nni_aio *      aio  = nni_list_first(&pipe->writeq);

	NNI_ASSERT(aio != NULL);
	NNI_ASSERT(aio->a_niov > 0);
	NNI_ASSERT(aio->a_iov[0].iov_len > 0);
	NNI_ASSERT(aio->a_iov[0].iov_buf != NULL);

	if (pipe->p == INVALID_HANDLE_VALUE) {
		rv = NNG_ECLOSED;
		goto fail;
	}

	if ((rv = nni_win_event_reset(evt)) != 0) {
		goto fail;
	}

	// Now start a writefile.  We assume that only one send can be
	// outstanding on a pipe at a time.  This is important to avoid
	// scrambling the data anyway.  Note that Windows named pipes do
	// not appear to support scatter/gather, so we have to process
	// each element in turn.
	buf  = aio->a_iov[0].iov_buf;
	len  = (DWORD) aio->a_iov[0].iov_len;
	olpd = nni_win_event_overlapped(evt);

	// We limit ourselves to writing 16MB at a time.  Named Pipes
	// on Windows have limits of between 31 and 64MB.
	if (len > 0x1000000) {
		len = 0x1000000;
	}

	if (!WriteFile(pipe->p, buf, len, NULL, olpd)) {
		// If we failed immediately, then process it.
		if ((rv = GetLastError()) == ERROR_IO_PENDING) {
			// This is the normal path we expect; the IO will
			// complete asynchronously.
			return;
		}

		// Some synchronous error occurred.
		rv = nni_win_error(rv);
		goto fail;
	}

	// If we completed synchronously, then do the completion.  This is
	// not normally expected.
	nni_win_ipc_send_finish(pipe);
	return;

fail:
	nni_aio_list_remove(aio);
	nni_aio_finish(aio, rv, aio->a_count);
}

static void
nni_win_ipc_send_cb(void *arg)
{
	nni_plat_ipc_pipe *pipe = arg;

	nni_mtx_lock(&pipe->mtx);
	nni_win_ipc_send_finish(pipe);
	nni_mtx_unlock(&pipe->mtx);
}

void
nni_plat_ipc_pipe_send(nni_plat_ipc_pipe *pipe, nni_aio *aio)
{
	nni_win_event *evt = &pipe->send_evt;
	int            rv;

	nni_mtx_lock(&pipe->mtx);
	if ((rv = nni_aio_start(aio, nni_win_ipc_send_cancel, pipe)) != 0) {
		nni_mtx_unlock(&pipe->mtx);
		return;
	}
	if (pipe->p == INVALID_HANDLE_VALUE) {
		nni_aio_finish(aio, NNG_ECLOSED, 0);
		nni_mtx_unlock(&pipe->mtx);
		return;
	}

	if ((rv = nni_win_event_reset(evt)) != 0) {
		nni_aio_finish(aio, rv, 0);
		nni_mtx_unlock(&pipe->mtx);
		return;
	}
	nni_aio_list_append(&pipe->writeq, aio);
	nni_win_ipc_send_start(pipe);
	nni_mtx_unlock(&pipe->mtx);
}

static void
nni_win_ipc_recv_cancel(nni_aio *aio)
{
	nni_plat_ipc_pipe *pipe = aio->a_prov_data;

	nni_mtx_lock(&pipe->mtx);
	nni_win_event_cancel(&pipe->recv_evt);
	nni_aio_list_remove(aio);
	nni_mtx_unlock(&pipe->mtx);
}

static void
nni_win_ipc_recv_finish(nni_plat_ipc_pipe *pipe)
{
	nni_win_event *evt  = &pipe->recv_evt;
	OVERLAPPED *   olpd = nni_win_event_overlapped(evt);
	int            rv   = 0;
	nni_aio *      aio;
	DWORD          cnt;

	if (GetOverlappedResult(pipe->p, olpd, &cnt, TRUE) == FALSE) {
		rv = nni_win_error(GetLastError());
	}
	if ((aio = nni_list_first(&pipe->readq)) == NULL) {
		// If the AIO was canceled, but IOCP thread was still
		// working on it, we might have seen this.
		return;
	}
	if (rv == 0) {
		NNI_ASSERT(cnt <= aio->a_iov[0].iov_len);
		aio->a_count += cnt;
		aio->a_iov[0].iov_buf = (char *) aio->a_iov[0].iov_buf + cnt;
		aio->a_iov[0].iov_len -= cnt;

		if (aio->a_iov[0].iov_len == 0) {
			int i;
			for (i = 1; i < aio->a_niov; i++) {
				aio->a_iov[i - 1] = aio->a_iov[i];
			}
			aio->a_niov--;
		}

		if (aio->a_niov > 0) {
			// If we have more to do, submit it!
			nni_win_ipc_recv_start(pipe);
			return;
		}
	}

	// All done; hopefully successfully.
	nni_list_remove(&pipe->readq, aio);
	nni_aio_finish(aio, rv, aio->a_count);
}

static void
nni_win_ipc_recv_start(nni_plat_ipc_pipe *pipe)
{
	void *         buf;
	DWORD          len;
	int            rv;
	nni_win_event *evt  = &pipe->recv_evt;
	OVERLAPPED *   olpd = nni_win_event_overlapped(evt);
	nni_aio *      aio  = nni_list_first(&pipe->readq);

	NNI_ASSERT(aio != NULL);
	NNI_ASSERT(aio->a_niov > 0);
	NNI_ASSERT(aio->a_iov[0].iov_len > 0);
	NNI_ASSERT(aio->a_iov[0].iov_buf != NULL);

	if (pipe->p == INVALID_HANDLE_VALUE) {
		rv = NNG_ECLOSED;
		goto fail;
	}

	if ((rv = nni_win_event_reset(evt)) != 0) {
		goto fail;
	}

	// Now start a readfile.  We assume that only one read can be
	// outstanding on a pipe at a time.  This is important to avoid
	// scrambling the data anyway.  Note that Windows named pipes do
	// not appear to support scatter/gather, so we have to process
	// each element in turn.
	buf  = aio->a_iov[0].iov_buf;
	len  = (DWORD) aio->a_iov[0].iov_len;
	olpd = nni_win_event_overlapped(evt);

	// We limit ourselves to writing 16MB at a time.  Named Pipes
	// on Windows have limits of between 31 and 64MB.
	if (len > 0x1000000) {
		len = 0x1000000;
	}

	if (!ReadFile(pipe->p, buf, len, NULL, olpd)) {
		// If we failed immediately, then process it.
		if ((rv = GetLastError()) == ERROR_IO_PENDING) {
			// This is the normal path we expect; the IO will
			// complete asynchronously.
			return;
		}

		// Some synchronous error occurred.
		rv = nni_win_error(rv);
		goto fail;
	}

	// If we completed synchronously, then do the completion.  This is
	// not normally expected.
	nni_win_ipc_recv_finish(pipe);
	return;

fail:
	nni_aio_list_remove(aio);
	nni_aio_finish(aio, rv, 0);
}

static void
nni_win_ipc_recv_cb(void *arg)
{
	nni_plat_ipc_pipe *pipe = arg;

	nni_mtx_lock(&pipe->mtx);
	nni_win_ipc_recv_finish(pipe);
	nni_mtx_unlock(&pipe->mtx);
}

void
nni_plat_ipc_pipe_recv(nni_plat_ipc_pipe *pipe, nni_aio *aio)
{
	nni_win_event *evt = &pipe->send_evt;
	int            rv;

	nni_mtx_lock(&pipe->mtx);
	if ((rv = nni_aio_start(aio, nni_win_ipc_recv_cancel, pipe)) != 0) {
		nni_mtx_unlock(&pipe->mtx);
		return;
	}
	if (pipe->p == INVALID_HANDLE_VALUE) {
		nni_aio_finish(aio, NNG_ECLOSED, 0);
		nni_mtx_unlock(&pipe->mtx);
		return;
	}

	if ((rv = nni_win_event_reset(evt)) != 0) {
		nni_aio_finish(aio, rv, 0);
		nni_mtx_unlock(&pipe->mtx);
		return;
	}
	nni_aio_list_append(&pipe->readq, aio);
	nni_win_ipc_recv_start(pipe);
}

void
nni_plat_ipc_pipe_close(nni_plat_ipc_pipe *pipe)
{
	nni_mtx_lock(&pipe->mtx);
	if (pipe->p != INVALID_HANDLE_VALUE) {
		CloseHandle(pipe->p);
		pipe->p = INVALID_HANDLE_VALUE;
	}
	nni_win_event_cancel(&pipe->send_evt);
	nni_win_event_cancel(&pipe->recv_evt);
	nni_mtx_unlock(&pipe->mtx);
}

void
nni_plat_ipc_pipe_fini(nni_plat_ipc_pipe *pipe)
{
	nni_plat_ipc_pipe_close(pipe);

	nni_win_event_fini(&pipe->send_evt);
	nni_win_event_fini(&pipe->recv_evt);
	nni_mtx_fini(&pipe->mtx);
	NNI_FREE_STRUCT(pipe);
}

int
nni_plat_ipc_ep_init(nni_plat_ipc_ep **epp, const char *url, int mode)
{
	const char *     path;
	nni_plat_ipc_ep *ep;
	int              rv;

	if (strncmp(url, "ipc://", strlen("ipc://")) != 0) {
		return (NNG_EADDRINVAL);
	}
	path = url + strlen("ipc://");
	if ((ep = NNI_ALLOC_STRUCT(ep)) == NULL) {
		return (NNG_ENOMEM);
	}
	ZeroMemory(ep, sizeof(ep));
	if ((rv = nni_mtx_init(&ep->mtx)) != 0) {
		NNI_FREE_STRUCT(ep);
		return (rv);
	}

	ep->mode = mode;
	NNI_LIST_NODE_INIT(&ep->node);
	nni_aio_list_init(&ep->aios);

	(void) snprintf(ep->path, sizeof(ep->path), "\\\\.\\pipe\\%s", path);

	*epp = ep;
	return (0);
}

int
nni_plat_ipc_ep_listen(nni_plat_ipc_ep *ep)
{
	int    rv;
	HANDLE p;

	nni_mtx_lock(&ep->mtx);
	if (ep->mode != NNI_EP_MODE_LISTEN) {
		nni_mtx_unlock(&ep->mtx);
		return (NNG_EINVAL);
	}
	if (ep->started) {
		nni_mtx_unlock(&ep->mtx);
		return (NNG_EBUSY);
	}

	// We create the first named pipe, and we make sure that it is
	// properly ours.
	p = CreateNamedPipeA(ep->path,
	    PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED |
	        FILE_FLAG_FIRST_PIPE_INSTANCE,
	    PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT |
	        PIPE_REJECT_REMOTE_CLIENTS,
	    PIPE_UNLIMITED_INSTANCES, 4096, 4096, 0, NULL);
	if (p == INVALID_HANDLE_VALUE) {
		if ((rv = GetLastError()) == ERROR_ACCESS_DENIED) {
			rv = NNG_EADDRINUSE;
		} else {
			rv = nni_win_error(rv);
		}
		goto failed;
	}
	rv = nni_win_event_init(&ep->acc_evt, nni_win_ipc_acc_cb, ep, p);
	if (rv != 0) {
		goto failed;
	}

	if ((rv = nni_win_iocp_register(p)) != 0) {
		goto failed;
	}

	ep->p       = p;
	ep->started = 1;
	nni_mtx_unlock(&ep->mtx);
	return (0);

failed:

	nni_mtx_unlock(&ep->mtx);
	if (p != INVALID_HANDLE_VALUE) {
		(void) CloseHandle(p);
	}

	return (rv);
}

static void
nni_win_ipc_acc_finish(nni_plat_ipc_ep *ep)
{
	nni_win_event *    evt = &ep->acc_evt;
	DWORD              nbytes;
	int                rv;
	nni_plat_ipc_pipe *pipe;
	nni_aio *          aio;
	HANDLE             newp, oldp;

	// Note: This should be called with the ep lock held, and only when
	// the ConnectNamedPipe has finished.

	rv = 0;
	if (!GetOverlappedResult(ep->p, &evt->olpd, &nbytes, FALSE)) {
		if ((rv = GetLastError()) == ERROR_IO_INCOMPLETE) {
			// We should never be here normally, but if the
			// pipe got accepted by another client we can
			// some times race here.
			return;
		}
	}

	if ((aio = nni_list_first(&ep->aios)) == NULL) {
		// No completion available to us.
		if (rv == 0) {
			NNI_ASSERT(0);
			DisconnectNamedPipe(ep->p);
		}
		return;
	}

	nni_list_remove(&ep->aios, aio);
	if (rv != 0) {
		nni_aio_finish(aio, rv, 0);
		return;
	}

	newp = CreateNamedPipeA(ep->path,
	    PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
	    PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT |
	        PIPE_REJECT_REMOTE_CLIENTS,
	    PIPE_UNLIMITED_INSTANCES, 4096, 4096, 0, NULL);
	if (newp == INVALID_HANDLE_VALUE) {
		rv = nni_win_error(GetLastError());
		DisconnectNamedPipe(ep->p);
		return;
	}
	oldp  = ep->p;
	ep->p = newp;

	if ((rv = nni_win_ipc_pipe_init(&pipe, oldp)) != 0) {
		DisconnectNamedPipe(oldp);
		nni_aio_finish(aio, rv, 0);
		return;
	}

	aio->a_pipe = pipe;
	nni_aio_finish(aio, 0, 0);
}

static void
nni_win_ipc_acc_cb(void *arg)
{
	nni_plat_ipc_ep *ep = arg;

	nni_mtx_lock(&ep->mtx);
	nni_win_ipc_acc_finish(ep);
	nni_mtx_unlock(&ep->mtx);
}

static void
nni_win_ipc_acc_cancel(nni_aio *aio)
{
	nni_plat_ipc_ep *ep = aio->a_prov_data;

	nni_mtx_lock(&ep->mtx);
	nni_win_event_cancel(&ep->acc_evt);
	nni_aio_list_remove(aio);
	nni_mtx_unlock(&ep->mtx);
}

void
nni_plat_ipc_ep_accept(nni_plat_ipc_ep *ep, nni_aio *aio)
{
	int            rv;
	nni_win_event *evt = &ep->acc_evt;

	nni_mtx_lock(&ep->mtx);
	if (nni_aio_start(aio, nni_win_ipc_acc_cancel, ep) != 0) {
		nni_mtx_unlock(&ep->mtx);
		return;
	}
	rv = 0;
	if ((rv = nni_win_event_reset(evt)) != 0) {
		nni_aio_finish(aio, rv, 0);
		nni_mtx_unlock(&ep->mtx);
		return;
	}
	if (!ConnectNamedPipe(ep->p, nni_win_event_overlapped(evt))) {
		rv = GetLastError();
		switch (rv) {
		case ERROR_PIPE_CONNECTED:
			rv = 0;
			break;
		case ERROR_IO_PENDING:
			nni_aio_list_append(&ep->aios, aio);
			nni_mtx_unlock(&ep->mtx);
			return;

		default:
			rv = nni_win_error(GetLastError());
			nni_aio_finish(aio, rv, 0);
			nni_mtx_unlock(&ep->mtx);
			return;
		}
	}

	nni_win_ipc_acc_finish(ep);
	nni_mtx_unlock(&ep->mtx);
}

// So Windows IPC is a bit different on the client side.  There is no
// support for asynchronous connection, but we can fake it with a single
// thread that runs to establish the connection.  That thread will run
// keep looping, sleeping for 10 ms between attempts.  It performs non-blocking
// attempts to connect.
typedef struct nni_win_ipc_conn_work nni_win_ipc_conn_work;
struct nni_win_ipc_conn_work {
	nni_list waiters;
	nni_list workers;
	nni_mtx  mtx;
	nni_cv   cv;
	nni_thr  thr;
	int      exit;
};

static nni_win_ipc_conn_work nni_win_ipc_connecter;

static void
nni_win_ipc_conn_thr(void *arg)
{
	nni_win_ipc_conn_work *w = arg;
	nni_plat_ipc_ep *      ep;
	nni_plat_ipc_pipe *    pipe;
	nni_aio *              aio;
	HANDLE                 p;
	int                    rv;

	nni_mtx_lock(&w->mtx);
	for (;;) {
		if (w->exit) {
			break;
		}
		while ((ep = nni_list_first(&w->waiters)) != NULL) {
			nni_list_remove(&w->waiters, ep);
			nni_list_append(&w->workers, ep);
		}

		while ((ep = nni_list_first(&w->workers)) != NULL) {
			nni_list_remove(&w->workers, ep);

			if ((aio = nni_list_first(&ep->aios)) == NULL) {
				continue;
			}
			nni_list_remove(&ep->aios, aio);
			p = CreateFileA(ep->path, GENERIC_READ | GENERIC_WRITE,
			    0, NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED,
			    NULL);

			if (p == INVALID_HANDLE_VALUE) {
				switch ((rv = GetLastError())) {
				case ERROR_PIPE_BUSY:
					// still in progress.
					nni_list_prepend(&ep->aios, aio);
					break;
				case ERROR_FILE_NOT_FOUND:
					nni_aio_finish(
					    aio, NNG_ECONNREFUSED, 0);
					break;
				default:
					nni_aio_finish(
					    aio, nni_win_error(rv), 0);
					break;
				}
			} else {
				rv = nni_win_ipc_pipe_init(&pipe, p);
				if (rv == 0) {
					rv = nni_win_iocp_register(p);
				}
				if (rv != 0) {
					DisconnectNamedPipe(p);
					CloseHandle(p);
					nni_aio_finish(aio, rv, 0);
				} else {
					aio->a_pipe = pipe;
					nni_aio_finish(aio, 0, 0);
				}
			}
			if (!nni_list_empty(&ep->aios)) {
				nni_list_append(&w->waiters, ep);
			}
		}

		// Wait 10 ms, unless woken earlier.
		if (nni_list_empty(&w->waiters)) {
			nni_cv_wait(&w->cv);
		} else {
			nni_cv_until(&w->cv, nni_clock() + 10000);
		}
	}
	nni_mtx_unlock(&w->mtx);
}

static void
nni_win_ipc_conn_cancel(nni_aio *aio)
{
	nni_win_ipc_conn_work *w  = &nni_win_ipc_connecter;
	nni_plat_ipc_ep *      ep = aio->a_prov_data;

	nni_mtx_lock(&w->mtx);
	nni_aio_list_remove(aio);
	if (nni_list_empty(&ep->aios)) {
		nni_list_remove(&w->waiters, ep);
	}
	nni_mtx_unlock(&w->mtx);
}

void
nni_plat_ipc_ep_connect(nni_plat_ipc_ep *ep, nni_aio *aio)
{
	nni_win_ipc_conn_work *w = &nni_win_ipc_connecter;

	nni_mtx_lock(&w->mtx);

	if (nni_list_active(&w->waiters, ep)) {
		nni_aio_finish(aio, NNG_EBUSY, 0);
		nni_mtx_unlock(&w->mtx);
		return;
	}

	if (nni_aio_start(aio, nni_win_ipc_conn_cancel, ep) != 0) {
		nni_mtx_unlock(&w->mtx);
		return;
	}
	nni_list_append(&ep->aios, aio);
	nni_list_append(&w->waiters, ep);
	nni_cv_wake(&w->cv);
	nni_mtx_unlock(&w->mtx);
}

void
nni_plat_ipc_ep_fini(nni_plat_ipc_ep *ep)
{
	nni_mtx_lock(&ep->mtx);
	if (ep->p) {
		CloseHandle(ep->p);
		ep->p = NULL;
	}
	nni_mtx_unlock(&ep->mtx);
	nni_mtx_fini(&ep->mtx);
	NNI_FREE_STRUCT(ep);
}

void
nni_plat_ipc_ep_close(nni_plat_ipc_ep *ep)
{
	nni_win_ipc_conn_work *w = &nni_win_ipc_connecter;
	nni_aio *              aio;

	switch (ep->mode) {
	case NNI_EP_MODE_DIAL:
		nni_mtx_lock(&w->mtx);
		if (nni_list_active(&w->waiters, ep)) {
			nni_list_remove(&w->waiters, ep);
		}
		while ((aio = nni_list_first(&ep->aios)) != NULL) {
			nni_list_remove(&ep->aios, aio);
			nni_aio_finish(aio, NNG_ECLOSED, 0);
		}
		nni_mtx_unlock(&w->mtx);
		break;
	case NNI_EP_MODE_LISTEN:
		nni_mtx_lock(&ep->mtx);
		while ((aio = nni_list_first(&ep->aios)) != NULL) {
			nni_list_remove(&ep->aios, aio);
			nni_aio_finish(aio, NNG_ECLOSED, 0);
		}
		if (ep->p != INVALID_HANDLE_VALUE) {
			nni_win_event_cancel(&ep->acc_evt);
			CloseHandle(ep->p);
			ep->p = INVALID_HANDLE_VALUE;
		}
		nni_mtx_unlock(&ep->mtx);
		break;
	}
}

int
nni_win_ipc_sysinit(void)
{
	int                    rv;
	nni_win_ipc_conn_work *worker = &nni_win_ipc_connecter;

	NNI_LIST_INIT(&worker->workers, nni_plat_ipc_ep, node);
	NNI_LIST_INIT(&worker->waiters, nni_plat_ipc_ep, node);

	if (((rv = nni_mtx_init(&worker->mtx)) != 0) ||
	    ((rv = nni_cv_init(&worker->cv, &worker->mtx)) != 0)) {
		return (rv);
	}
	rv = nni_thr_init(&worker->thr, nni_win_ipc_conn_thr, worker);
	if (rv != 0) {
		return (rv);
	}

	nni_thr_run(&worker->thr);

	return (0);
}

void
nni_win_ipc_sysfini(void)
{
	nni_win_ipc_conn_work *worker = &nni_win_ipc_connecter;

	nni_mtx_lock(&worker->mtx);
	worker->exit = 1;
	nni_cv_wake(&worker->cv);
	nni_mtx_unlock(&worker->mtx);
	nni_thr_fini(&worker->thr);
	nni_cv_fini(&worker->cv);
	nni_mtx_fini(&worker->mtx);
}

#else

// Suppress empty symbols warnings in ranlib.
int nni_win_ipc_not_used = 0;

#endif // PLATFORM_WINDOWS
