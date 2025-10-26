//
// Copyright 2025 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
// Copyright 2018 Devolutions <info@devolutions.net>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <stdbool.h>
#include <stdio.h>

#include "../../core/nng_impl.h"
#include "win_tcp.h"

typedef struct tcp_listener {
	nng_stream_listener ops;
	nng_sockaddr        sa;
	SOCKET              s;
	nni_list            aios;
	bool                closed;
	bool                started;
	bool                nodelay;   // initial value for child conns
	bool                keepalive; // initial value for child conns
	bool                running;
	SOCKADDR_STORAGE    ss;
	nni_mtx             mtx;
	nni_reap_node       reap;
	nni_win_io          accept_io;
	int                 accept_rv;
	nni_tcp_conn       *pend_conn;
} tcp_listener;

static void tcp_listener_accepted(tcp_listener *l);
static void tcp_listener_doaccept(tcp_listener *l);
static void tcp_listener_free(void *arg);

static void
tcp_accept_cb(nni_win_io *io, int rv, size_t cnt)
{
	tcp_listener *l = io->ptr;
	nni_aio      *aio;
	nni_tcp_conn *c;

	NNI_ARG_UNUSED(cnt);

	nni_mtx_lock(&l->mtx);

	l->running = false;
	if ((rv == 0) && (!l->closed)) {
		tcp_listener_accepted(l);
	} else {
		if (l->accept_rv != 0) {
			rv           = l->accept_rv;
			l->accept_rv = 0;
		} else if (l->closed) {
			rv = NNG_ECLOSED;
		}
		if ((aio = nni_list_first(&l->aios)) != NULL) {
			nni_aio_list_remove(aio);
			nni_aio_finish_error(aio, rv);
		}

		if ((c = l->pend_conn) != NULL) {
			l->pend_conn = NULL;
			nng_stream_free(&c->ops);
		}
	}
	tcp_listener_doaccept(l);
	nni_mtx_unlock(&l->mtx);
}

static void
tcp_listener_close(void *arg)
{
	nni_aio      *aio;
	nni_tcp_conn *conn;
	tcp_listener *l = arg;

	nni_mtx_lock(&l->mtx);
	if (!l->closed) {
		l->closed = true;
		if (!nni_list_empty(&l->aios)) {
			CancelIoEx((HANDLE) l->s, &l->accept_io.olpd);
		}
		closesocket(l->s);
		if ((conn = l->pend_conn) != NULL) {
			l->pend_conn = NULL;
			nng_stream_free(&conn->ops);
		}
		while ((aio = nni_list_first(&l->aios)) != NULL) {
			nni_aio_list_remove(aio);
			nni_aio_finish_error(aio, NNG_ECLOSED);
		}
	}
	nni_mtx_unlock(&l->mtx);
}

static nni_reap_list tcp_listener_reap_list = {
	.rl_offset = offsetof(tcp_listener, reap),
	.rl_func   = (nni_cb) tcp_listener_free,
};

static void
tcp_listener_stop(void *arg)
{
	tcp_listener *l = arg;
	tcp_listener_close(l);
	// TODO: maybe wait for l->l_accept_io.olpd to finish?
}

static void
tcp_listener_free(void *arg)
{
	tcp_listener *l = arg;

	tcp_listener_close(l);
	nni_mtx_lock(&l->mtx);
	if (l->running) {
		nni_mtx_unlock(&l->mtx);
		nni_reap(&tcp_listener_reap_list, l);
		return;
	}
	nni_mtx_unlock(&l->mtx);
	nni_mtx_fini(&l->mtx);
	NNI_FREE_STRUCT(l);
}

static nng_err
tcp_listener_listen(void *arg)
{
	nng_err       rv;
	BOOL          yes;
	DWORD         no;
	int           len;
	tcp_listener *l = arg;

	nni_mtx_lock(&l->mtx);
	if (l->closed) {
		nni_mtx_unlock(&l->mtx);
		return (NNG_ECLOSED);
	}
	if (l->started) {
		nni_mtx_unlock(&l->mtx);
		return (NNG_EBUSY);
	}
	if ((len = nni_win_nn2sockaddr(&l->ss, &l->sa)) <= 0) {
		nni_mtx_unlock(&l->mtx);
		return (NNG_EADDRINVAL);
	}
	l->s = socket(l->ss.ss_family, SOCK_STREAM, 0);
	if (l->s == INVALID_SOCKET) {
		rv = nni_win_error(GetLastError());
		nni_mtx_unlock(&l->mtx);
		return (rv);
	}

	// Don't inherit the handle (CLOEXEC really).
	SetHandleInformation((HANDLE) l->s, HANDLE_FLAG_INHERIT, 0);

	no = 0;
	(void) setsockopt(
	    l->s, IPPROTO_IPV6, IPV6_V6ONLY, (char *) &no, sizeof(no));
	yes = 1;
	(void) setsockopt(
	    l->s, IPPROTO_TCP, TCP_NODELAY, (char *) &yes, sizeof(yes));

	if ((rv = nni_win_io_register((HANDLE) l->s)) != 0) {
		closesocket(l->s);
		l->s = INVALID_SOCKET;
		nni_mtx_unlock(&l->mtx);
		return (rv);
	}

	// Make sure that we use the address exclusively.  Windows lets
	// others hijack us by default.
	yes = 1;
	if ((setsockopt(l->s, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (char *) &yes,
	         sizeof(yes)) != 0) ||
	    (bind(l->s, (SOCKADDR *) &l->ss, len) != 0) ||
	    (getsockname(l->s, (SOCKADDR *) &l->ss, &len) != 0) ||
	    (listen(l->s, SOMAXCONN) != 0)) {
		rv = nni_win_error(GetLastError());
		closesocket(l->s);
		l->s = INVALID_SOCKET;
		nni_mtx_unlock(&l->mtx);
		return (rv);
	}
	l->started = true;
	nni_mtx_unlock(&l->mtx);
	return (NNG_OK);
}

static void
tcp_accept_cancel(nni_aio *aio, void *arg, nng_err rv)
{
	tcp_listener *l = arg;

	nni_mtx_lock(&l->mtx);
	if (aio == nni_list_first(&l->aios)) {
		l->accept_rv = rv;
		CancelIoEx((HANDLE) l->s, &l->accept_io.olpd);
	} else {
		nni_aio *srch;
		NNI_LIST_FOREACH (&l->aios, srch) {
			if (srch == aio) {
				nni_aio_list_remove(aio);
				nni_aio_finish_error(aio, rv);
				break;
			}
		}
	}
	nni_mtx_unlock(&l->mtx);
}

static void
tcp_listener_accepted(tcp_listener *l)
{
	BOOL             nd;
	BOOL             ka;
	nni_tcp_conn    *c;
	nni_aio         *aio;
	SOCKADDR_STORAGE sockname;
	SOCKADDR_STORAGE peername;

	aio          = nni_list_first(&l->aios);
	c            = l->pend_conn;
	l->pend_conn = NULL;
	ka           = l->keepalive;
	nd           = l->nodelay;

	nni_aio_list_remove(aio);
	nni_win_get_acceptex_sockaddrs(c->buf, &sockname, &peername);
	nni_win_sockaddr2nn(&c->sockname, &sockname, sizeof(sockname));
	nni_win_sockaddr2nn(&c->peername, &peername, sizeof(peername));

	(void) setsockopt(c->s, SOL_SOCKET, SO_UPDATE_ACCEPT_CONTEXT,
	    (char *) &l->s, sizeof(l->s));

	(void) setsockopt(
	    c->s, SOL_SOCKET, SO_KEEPALIVE, (char *) &ka, sizeof(ka));

	(void) setsockopt(
	    c->s, IPPROTO_TCP, TCP_NODELAY, (char *) &nd, sizeof(nd));

	nni_aio_set_output(aio, 0, c);
	nni_aio_finish(aio, 0, 0);
}

static void
tcp_listener_doaccept(tcp_listener *l)
{
	nni_aio      *aio;
	SOCKET        s;
	nni_tcp_conn *c;
	int           rv;
	DWORD         cnt;

	while ((aio = nni_list_first(&l->aios)) != NULL) {
		// Windows requires us to explicitly create the socket
		// before calling accept on it.
		if (l->closed) {
			nni_aio_list_remove(aio);
			nni_aio_finish_error(aio, NNG_ECLOSED);
			continue;
		}
		if ((s = socket(l->ss.ss_family, SOCK_STREAM, 0)) ==
		    INVALID_SOCKET) {
			nni_aio_list_remove(aio);
			rv = nni_win_error(GetLastError());
			nni_aio_finish_error(aio, rv);
			continue;
		}

		if ((rv = nni_win_tcp_init(&c, s)) != 0) {
			nni_aio_list_remove(aio);
			closesocket(s);
			nni_aio_finish_error(aio, rv);
			continue;
		}
		c->listener  = l;
		l->pend_conn = c;
		if (nni_win_acceptex(l->s, s, c->buf, &l->accept_io.olpd)) {
			// completed synchronously
			tcp_listener_accepted(l);
			continue;
		}

		if ((rv = GetLastError()) == ERROR_IO_PENDING) {
			// deferred (will be handled in callback)
			l->running = true;
			return;
		}

		// Fast failure (synchronous.)
		nni_aio_list_remove(aio);
		nng_stream_free(&c->ops);
		nni_aio_finish_error(aio, rv);
	}
	l->running = false;
}

static void
tcp_listener_accept(void *arg, nni_aio *aio)
{
	tcp_listener *l = arg;

	nni_aio_reset(aio);

	nni_mtx_lock(&l->mtx);
	if (!l->started) {
		nni_mtx_unlock(&l->mtx);
		nni_aio_finish_error(aio, NNG_ESTATE);
		return;
	}
	if (l->closed) {
		nni_mtx_unlock(&l->mtx);
		nni_aio_finish_error(aio, NNG_ECLOSED);
		return;
	}
	if (!nni_aio_start(aio, tcp_accept_cancel, l)) {
		nni_mtx_unlock(&l->mtx);
		return;
	}

	nni_aio_list_append(&l->aios, aio);
	if (aio == nni_list_first(&l->aios)) {
		tcp_listener_doaccept(l);
	}
	nni_mtx_unlock(&l->mtx);
}

static nng_err
tcp_listener_get_locaddr(void *arg, void *buf, size_t *szp, nni_type t)
{
	tcp_listener *l = arg;
	nng_sockaddr  sa;
	nni_mtx_lock(&l->mtx);
	if (l->started) {
		nni_win_sockaddr2nn(&sa, &l->ss, sizeof(l->ss));
	} else {
		sa.s_family = NNG_AF_UNSPEC;
	}
	nni_mtx_unlock(&l->mtx);
	return (nni_copyout_sockaddr(&sa, buf, szp, t));
}

static nng_err
tcp_listener_set_nodelay(void *arg, const void *buf, size_t sz, nni_type t)
{
	tcp_listener *l = arg;
	nng_err       rv;
	bool          b;

	if (((rv = nni_copyin_bool(&b, buf, sz, t)) != NNG_OK) ||
	    (l == NULL)) {
		return (rv);
	}
	nni_mtx_lock(&l->mtx);
	l->nodelay = b;
	nni_mtx_unlock(&l->mtx);
	return (0);
}

static nng_err
tcp_listener_get_nodelay(void *arg, void *buf, size_t *szp, nni_type t)
{
	bool          b;
	tcp_listener *l = arg;
	nni_mtx_lock(&l->mtx);
	b = l->nodelay;
	nni_mtx_unlock(&l->mtx);
	return (nni_copyout_bool(b, buf, szp, t));
}

static nng_err
tcp_listener_set_keepalive(void *arg, const void *buf, size_t sz, nni_type t)
{
	tcp_listener *l = arg;
	nng_err       rv;
	bool          b;

	if (((rv = nni_copyin_bool(&b, buf, sz, t)) != NNG_OK) ||
	    (l == NULL)) {
		return (rv);
	}
	nni_mtx_lock(&l->mtx);
	l->keepalive = b;
	nni_mtx_unlock(&l->mtx);
	return (0);
}

static nng_err
tcp_listener_get_keepalive(void *arg, void *buf, size_t *szp, nni_type t)
{
	bool          b;
	tcp_listener *l = arg;
	nni_mtx_lock(&l->mtx);
	b = l->keepalive;
	nni_mtx_unlock(&l->mtx);
	return (nni_copyout_bool(b, buf, szp, t));
}

static nng_err
tcp_listener_get_port(void *arg, void *buf, size_t *szp, nni_type t)
{
	tcp_listener *l = arg;
	nng_sockaddr  sa;
	size_t        sz;
	int           port;
	uint8_t      *paddr;

	sz = sizeof(sa);
	(void) tcp_listener_get_locaddr(l, &sa, &sz, NNI_TYPE_SOCKADDR);

	switch (sa.s_family) {
	case NNG_AF_INET:
		paddr = (void *) &sa.s_in.sa_port;
		break;

	case NNG_AF_INET6:
		paddr = (void *) &sa.s_in6.sa_port;
		break;

	default:
		return (NNG_ESTATE);
	}

	NNI_GET16(paddr, port);
	return (nni_copyout_int(port, buf, szp, t));
}

static nng_err
tcp_listener_set_listen_fd(void *arg, const void *buf, size_t sz, nni_type t)
{
	tcp_listener    *l = arg;
	int              fd;
	SOCKADDR_STORAGE ss;
	int              len = sizeof(ss);
	nng_err          rv;

	if ((rv = nni_copyin_int(&fd, buf, sz, 0, NNI_MAXINT, t)) != NNG_OK) {
		return (rv);
	}

	if (getsockname(fd, (void *) &ss, &len) != 0) {
		return (nni_win_error(GetLastError()));
	}

	if (((nni_win_sockaddr2nn(&l->sa, &ss, len)) != 0) ||
#ifdef NNG_ENABLE_IPV6
	    ((ss.ss_family != AF_INET) && (ss.ss_family != AF_INET6))
#else
	    (ss.ss_family != AF_INET)
#endif
	) {
		return (NNG_EADDRINVAL);
	}

	nni_mtx_lock(&l->mtx);
	if (l->started) {
		nni_mtx_unlock(&l->mtx);
		return (NNG_EBUSY);
	}
	if (l->closed) {
		nni_mtx_unlock(&l->mtx);
		return (NNG_ECLOSED);
	}

	int yes = 1;
	(void) setsockopt(
	    l->s, IPPROTO_TCP, TCP_NODELAY, (char *) &yes, sizeof(yes));

	l->ss = ss;
	l->s  = (SOCKET) fd;
	if ((rv = nni_win_io_register((HANDLE) l->s)) != NNG_OK) {
		l->s = INVALID_SOCKET;
		nni_mtx_unlock(&l->mtx);
		return (rv);
	}
	l->started = true;
	nni_mtx_unlock(&l->mtx);
	return (NNG_OK);
}

#ifdef NNG_TEST_LIB
// this is readable only for test code -- user code should never rely on this
static nng_err
tcp_listener_get_listen_fd(void *arg, void *buf, size_t *szp, nni_type t)
{
	nng_err       rv;
	tcp_listener *l = arg;
	nni_mtx_lock(&l->mtx);
	NNI_ASSERT(l->started);
	NNI_ASSERT(!l->closed);
	rv = nni_copyout_int((int) l->s, buf, szp, t);
	nni_mtx_unlock(&l->mtx);
	return (rv);
}
#endif

static const nni_option tcp_listener_options[] = {
	{
	    .o_name = NNG_OPT_TCP_NODELAY,
	    .o_set  = tcp_listener_set_nodelay,
	    .o_get  = tcp_listener_get_nodelay,
	},
	{
	    .o_name = NNG_OPT_TCP_KEEPALIVE,
	    .o_set  = tcp_listener_set_keepalive,
	    .o_get  = tcp_listener_get_keepalive,
	},
	{
	    .o_name = NNG_OPT_BOUND_PORT,
	    .o_get  = tcp_listener_get_port,
	},
	{
	    .o_name = NNG_OPT_LISTEN_FD,
	    .o_set  = tcp_listener_set_listen_fd,
#ifdef NNG_TEST_LIB
	    .o_get = tcp_listener_get_listen_fd,
#endif
	},
	{
	    .o_name = NULL,
	},
};

static nng_err
tcp_listener_get(
    void *arg, const char *name, void *buf, size_t *szp, nni_type t)
{
	return (nni_getopt(tcp_listener_options, name, arg, buf, szp, t));
}

static nng_err
tcp_listener_set(
    void *arg, const char *name, const void *buf, size_t sz, nni_type t)
{
	return (nni_setopt(tcp_listener_options, name, arg, buf, sz, t));
}

static nng_err
tcp_listener_alloc_addr(nng_stream_listener **lp, const nng_sockaddr *sa)
{
	tcp_listener *l;
	nng_err       rv;

	if ((l = NNI_ALLOC_STRUCT(l)) == NULL) {
		return (NNG_ENOMEM);
	}

	nni_mtx_init(&l->mtx);
	nni_aio_list_init(&l->aios);
	nni_win_io_init(&l->accept_io, tcp_accept_cb, l);

	// We assume these defaults -- not everyone will agree, but anyone
	// can change them.
	l->keepalive = false;
	l->nodelay   = true;
	l->closed    = false;
	l->started   = false;
	l->nodelay   = true;
	l->sa        = *sa;
	l->accept_rv = 0;

	l->ops.sl_free   = tcp_listener_free;
	l->ops.sl_close  = tcp_listener_close;
	l->ops.sl_stop   = tcp_listener_stop;
	l->ops.sl_listen = tcp_listener_listen;
	l->ops.sl_accept = tcp_listener_accept;
	l->ops.sl_get    = tcp_listener_get;
	l->ops.sl_set    = tcp_listener_set;

	*lp = (void *) l;
	return (NNG_OK);
}

nng_err
nni_tcp_listener_alloc(nng_stream_listener **lp, const nng_url *url)
{
	nng_err      rv;
	nng_sockaddr sa;

	if ((rv = nni_url_to_address(&sa, url)) != NNG_OK) {
		return (rv);
	}

	return (tcp_listener_alloc_addr(lp, &sa));
}
