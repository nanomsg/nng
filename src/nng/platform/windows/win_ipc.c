//
// Copyright 2017 Garrett D'Amore <garrett@damore.org>
// Copyright 2017 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "core/nng_impl.h"

#ifdef NNG_PLATFORM_WINDOWS

#include <stdio.h>

struct nni_plat_ipc_pipe {
	HANDLE        p;
	nni_win_event rcv_ev;
	nni_win_event snd_ev;
};

struct nni_plat_ipc_ep {
	char          path[256];
	nni_sockaddr  addr;
	int           mode;
	int           started;
	HANDLE        p;       // accept side only
	nni_win_event acc_ev;  // accept side only
	nni_aio *     con_aio; // conn side only
	nni_list_node node;    // conn side uses this
};

static int  nni_win_ipc_pipe_start(nni_win_event *, nni_aio *);
static void nni_win_ipc_pipe_finish(nni_win_event *, nni_aio *);
static void nni_win_ipc_pipe_cancel(nni_win_event *);

static nni_win_event_ops nni_win_ipc_pipe_ops = {
	.wev_start  = nni_win_ipc_pipe_start,
	.wev_finish = nni_win_ipc_pipe_finish,
	.wev_cancel = nni_win_ipc_pipe_cancel,
};

static int  nni_win_ipc_acc_start(nni_win_event *, nni_aio *);
static void nni_win_ipc_acc_finish(nni_win_event *, nni_aio *);
static void nni_win_ipc_acc_cancel(nni_win_event *);

static nni_win_event_ops nni_win_ipc_acc_ops = {
	.wev_start  = nni_win_ipc_acc_start,
	.wev_finish = nni_win_ipc_acc_finish,
	.wev_cancel = nni_win_ipc_acc_cancel,
};

static int
nni_win_ipc_pipe_start(nni_win_event *evt, nni_aio *aio)
{
	void *             buf;
	DWORD              len;
	BOOL               ok;
	int                rv;
	nni_plat_ipc_pipe *pipe = evt->ptr;

	NNI_ASSERT(aio != NULL);
	NNI_ASSERT(aio->a_niov > 0);
	NNI_ASSERT(aio->a_iov[0].iov_len > 0);
	NNI_ASSERT(aio->a_iov[0].iov_buf != NULL);

	if (pipe->p == INVALID_HANDLE_VALUE) {
		evt->status = NNG_ECLOSED;
		evt->count  = 0;
		return (1);
	}

	// Now start a writefile.  We assume that only one send can be
	// outstanding on a pipe at a time.  This is important to avoid
	// scrambling the data anyway.  Note that Windows named pipes do
	// not appear to support scatter/gather, so we have to process
	// each element in turn.
	buf = aio->a_iov[0].iov_buf;
	len = (DWORD) aio->a_iov[0].iov_len;

	// We limit ourselves to writing 16MB at a time.  Named Pipes
	// on Windows have limits of between 31 and 64MB.
	if (len > 0x1000000) {
		len = 0x1000000;
	}

	evt->count = 0;
	if (evt == &pipe->snd_ev) {
		ok = WriteFile(pipe->p, buf, len, NULL, &evt->olpd);
	} else {
		ok = ReadFile(pipe->p, buf, len, NULL, &evt->olpd);
	}
	if ((!ok) && ((rv = GetLastError()) != ERROR_IO_PENDING)) {
		// Synchronous failure.
		evt->status = nni_win_error(rv);
		evt->count  = 0;
		return (1);
	}

	// Wait for the I/O completion event.  Note that when an I/O
	// completes immediately, the I/O completion packet is still
	// delivered.
	return (0);
}

static void
nni_win_ipc_pipe_cancel(nni_win_event *evt)
{
	nni_plat_ipc_pipe *pipe = evt->ptr;

	CancelIoEx(pipe->p, &evt->olpd);
}

static void
nni_win_ipc_pipe_finish(nni_win_event *evt, nni_aio *aio)
{
	int   rv;
	DWORD cnt;

	cnt = evt->count;
	if ((rv = evt->status) == 0) {
		NNI_ASSERT(cnt <= aio->a_iov[0].iov_len);
		aio->a_count += cnt;
		aio->a_iov[0].iov_buf = (char *) aio->a_iov[0].iov_buf + cnt;
		aio->a_iov[0].iov_len -= cnt;

		if (aio->a_iov[0].iov_len == 0) {
			int i;
			aio->a_niov--;
			for (i = 0; i < aio->a_niov; i++) {
				aio->a_iov[i] = aio->a_iov[i + 1];
			}
		}

		if (aio->a_niov > 0) {
			// If we have more to do, submit it!
			nni_win_event_resubmit(evt, aio);
			return;
		}
	}

	// All done; hopefully successfully.
	nni_aio_finish(aio, rv, aio->a_count);
}

static int
nni_win_ipc_pipe_init(nni_plat_ipc_pipe **pipep, HANDLE p)
{
	nni_plat_ipc_pipe *pipe;
	int                rv;

	if ((pipe = NNI_ALLOC_STRUCT(pipe)) == NULL) {
		return (NNG_ENOMEM);
	}
	rv = nni_win_event_init(&pipe->rcv_ev, &nni_win_ipc_pipe_ops, pipe);
	if (rv != 0) {
		nni_plat_ipc_pipe_fini(pipe);
		return (rv);
	}
	rv = nni_win_event_init(&pipe->snd_ev, &nni_win_ipc_pipe_ops, pipe);
	if (rv != 0) {
		nni_plat_ipc_pipe_fini(pipe);
		return (rv);
	}

	pipe->p = p;
	*pipep  = pipe;
	return (0);
}

void
nni_plat_ipc_pipe_send(nni_plat_ipc_pipe *pipe, nni_aio *aio)
{
	nni_win_event_submit(&pipe->snd_ev, aio);
}

void
nni_plat_ipc_pipe_recv(nni_plat_ipc_pipe *pipe, nni_aio *aio)
{
	nni_win_event_submit(&pipe->rcv_ev, aio);
}

void
nni_plat_ipc_pipe_close(nni_plat_ipc_pipe *pipe)
{
	HANDLE p;

	nni_win_event_close(&pipe->snd_ev);
	nni_win_event_close(&pipe->rcv_ev);

	if ((p = pipe->p) != INVALID_HANDLE_VALUE) {
		pipe->p = INVALID_HANDLE_VALUE;
		CloseHandle(p);
	}
}

void
nni_plat_ipc_pipe_fini(nni_plat_ipc_pipe *pipe)
{
	nni_plat_ipc_pipe_close(pipe);

	nni_win_event_fini(&pipe->snd_ev);
	nni_win_event_fini(&pipe->rcv_ev);
	NNI_FREE_STRUCT(pipe);
}

int
nni_plat_ipc_ep_init(nni_plat_ipc_ep **epp, const nni_sockaddr *sa, int mode)
{
	const char *     path;
	nni_plat_ipc_ep *ep;

	path = sa->s_un.s_path.sa_path;

	if ((ep = NNI_ALLOC_STRUCT(ep)) == NULL) {
		return (NNG_ENOMEM);
	}
	ZeroMemory(ep, sizeof(ep));

	ep->mode = mode;
	NNI_LIST_NODE_INIT(&ep->node);

	ep->addr = *sa;
	(void) snprintf(ep->path, sizeof(ep->path), "\\\\.\\pipe\\%s", path);

	*epp = ep;
	return (0);
}

int
nni_plat_ipc_ep_listen(nni_plat_ipc_ep *ep)
{
	int    rv;
	HANDLE p;

	if (ep->mode != NNI_EP_MODE_LISTEN) {
		return (NNG_EINVAL);
	}
	if (ep->started) {
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
	rv = nni_win_event_init(&ep->acc_ev, &nni_win_ipc_acc_ops, ep);
	if (rv != 0) {
		goto failed;
	}

	if ((rv = nni_win_iocp_register(p)) != 0) {
		goto failed;
	}

	ep->p       = p;
	ep->started = 1;
	return (0);

failed:

	if (p != INVALID_HANDLE_VALUE) {
		(void) CloseHandle(p);
	}

	return (rv);
}

static void
nni_win_ipc_acc_finish(nni_win_event *evt, nni_aio *aio)
{
	nni_plat_ipc_ep *  ep = evt->ptr;
	nni_plat_ipc_pipe *pipe;
	int                rv;
	HANDLE             newp, oldp;

	if ((rv = evt->status) != 0) {
		nni_aio_finish_error(aio, rv);
		return;
	}

	newp = CreateNamedPipeA(ep->path,
	    PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
	    PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT |
	        PIPE_REJECT_REMOTE_CLIENTS,
	    PIPE_UNLIMITED_INSTANCES, 4096, 4096, 0, NULL);
	if (newp == INVALID_HANDLE_VALUE) {
		rv = nni_win_error(GetLastError());
		// We connected, but as we cannot get a new pipe,
		// we have to disconnect the old one.
		DisconnectNamedPipe(ep->p);
		nni_aio_finish_error(aio, rv);
		return;
	}
	if ((rv = nni_win_iocp_register(newp)) != 0) {
		// Disconnect the old pipe.
		DisconnectNamedPipe(ep->p);
		// And discard the half-baked new one.
		DisconnectNamedPipe(newp);
		(void) CloseHandle(newp);
		nni_aio_finish_error(aio, rv);
		return;
	}

	oldp  = ep->p;
	ep->p = newp;

	if ((rv = nni_win_ipc_pipe_init(&pipe, oldp)) != 0) {
		// The new pipe is already fine for us.  Discard
		// the old one, since failed to be able to use it.
		DisconnectNamedPipe(oldp);
		(void) CloseHandle(oldp);
		nni_aio_finish_error(aio, rv);
		return;
	}

	nni_aio_finish_pipe(aio, pipe);
}

static void
nni_win_ipc_acc_cancel(nni_win_event *evt)
{
	nni_plat_ipc_ep *ep = evt->ptr;

	(void) CancelIoEx(ep->p, &evt->olpd);
	// Just to be sure.
	(void) DisconnectNamedPipe(ep->p);
}

static int
nni_win_ipc_acc_start(nni_win_event *evt, nni_aio *aio)
{
	nni_plat_ipc_ep *ep = evt->ptr;

	if (!ConnectNamedPipe(ep->p, &evt->olpd)) {
		int rv = GetLastError();
		switch (rv) {
		case ERROR_PIPE_CONNECTED:
			// Synch completion already occurred.
			// Windows is weird.  Apparently the I/O
			// completion packet has already been sent.
			return (0);

		case ERROR_IO_PENDING:
			// Normal asynchronous operation.  Wait for
			// completion.
			return (0);

		default:
			// Fast-fail (synchronous).
			evt->status = nni_win_error(rv);
			evt->count  = 0;
			return (1);
		}
	}

	// Synch completion right now.  I/O completion packet delivered
	// already.
	return (0);
}

void
nni_plat_ipc_ep_accept(nni_plat_ipc_ep *ep, nni_aio *aio)
{
	nni_win_event_submit(&ep->acc_ev, aio);
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

			if ((aio = ep->con_aio) == NULL) {
				continue;
			}
			ep->con_aio = NULL;

			pipe = NULL;

			p = CreateFileA(ep->path, GENERIC_READ | GENERIC_WRITE,
			    0, NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED,
			    NULL);

			if (p == INVALID_HANDLE_VALUE) {
				switch ((rv = GetLastError())) {
				case ERROR_PIPE_BUSY:
					// Still in progress.  This shouldn't
					// happen unless the other side aborts
					// the connection.
					ep->con_aio = aio;
					nni_list_append(&w->waiters, ep);
					continue;

				case ERROR_FILE_NOT_FOUND:
					rv = NNG_ECONNREFUSED;
					break;
				default:
					rv = nni_win_error(rv);
					break;
				}
				goto fail;
			}
			if (((rv = nni_win_ipc_pipe_init(&pipe, p)) != 0) ||
			    ((rv = nni_win_iocp_register(p)) != 0)) {
				goto fail;
			}
			nni_aio_finish_pipe(aio, pipe);
			continue;

		fail:
			if (p != INVALID_HANDLE_VALUE) {
				DisconnectNamedPipe(p);
				CloseHandle(p);
			}
			if (pipe != NULL) {
				nni_plat_ipc_pipe_fini(pipe);
			}
			nni_aio_finish_error(aio, rv);
		}

		if (nni_list_empty(&w->waiters)) {
			// Wait until an endpoint is added.
			nni_cv_wait(&w->cv);
		} else {
			// Wait 10 ms, unless woken earlier.
			nni_cv_until(&w->cv, nni_clock() + 10000);
		}
	}
	nni_mtx_unlock(&w->mtx);
}

static void
nni_win_ipc_conn_cancel(nni_aio *aio, int rv)
{
	nni_win_ipc_conn_work *w  = &nni_win_ipc_connecter;
	nni_plat_ipc_ep *      ep = aio->a_prov_data;

	nni_mtx_lock(&w->mtx);
	if (aio == ep->con_aio) {
		ep->con_aio = NULL;
		if (nni_list_active(&w->waiters, ep)) {
			nni_list_remove(&w->waiters, ep);
			nni_cv_wake(&w->cv);
		}
		nni_aio_finish_error(aio, rv);
	}
	nni_mtx_unlock(&w->mtx);
}

void
nni_plat_ipc_ep_connect(nni_plat_ipc_ep *ep, nni_aio *aio)
{
	nni_win_ipc_conn_work *w = &nni_win_ipc_connecter;

	nni_mtx_lock(&w->mtx);

	NNI_ASSERT(!nni_list_active(&w->waiters, ep));

	if (nni_aio_start(aio, nni_win_ipc_conn_cancel, ep) != 0) {
		nni_mtx_unlock(&w->mtx);
		return;
	}
	ep->con_aio = aio;
	nni_list_append(&w->waiters, ep);
	nni_cv_wake(&w->cv);
	nni_mtx_unlock(&w->mtx);
}

void
nni_plat_ipc_ep_fini(nni_plat_ipc_ep *ep)
{
	nni_plat_ipc_ep_close(ep);
	if (ep->p != INVALID_HANDLE_VALUE) {
		CloseHandle(ep->p);
		ep->p = INVALID_HANDLE_VALUE;
	}
	nni_win_event_close(&ep->acc_ev);
	nni_win_event_fini(&ep->acc_ev);
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
		if ((aio = ep->con_aio) != NULL) {
			ep->con_aio = NULL;
			nni_aio_finish_error(aio, NNG_ECLOSED);
		}
		nni_mtx_unlock(&w->mtx);
		break;

	case NNI_EP_MODE_LISTEN:
		nni_win_event_close(&ep->acc_ev);
		if (ep->p != INVALID_HANDLE_VALUE) {
			CloseHandle(ep->p);
			ep->p = INVALID_HANDLE_VALUE;
		}
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

	nni_mtx_init(&worker->mtx);
	nni_cv_init(&worker->cv, &worker->mtx);

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

#endif // NNG_PLATFORM_WINDOWS
