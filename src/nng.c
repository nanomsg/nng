//
// Copyright 2021 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "nng/nng.h"
#include "core/nng_impl.h"

// This file provides the "public" API.  This is a thin wrapper around
// internal API functions.  We use the public prefix instead of internal,
// to indicate that these interfaces are intended for applications to use
// directly.
//
// Anything not defined in this file, applications have no business using.
// Pretty much every function calls the nni_platform_init to check against
// fork related activity.

#include <stdio.h>
#include <string.h>

void
nng_fini(void)
{
	nni_sock_closeall();
	nni_fini();
}

int
nng_close(nng_socket s)
{
	int       rv;
	nni_sock *sock;

	// Close is special, because we still want to be able to get
	// a hold on the socket even if shutdown was called.
	if ((rv = nni_sock_find(&sock, s.id)) != 0) {
		return (rv);
	}
	// No release -- close releases it.
	nni_sock_close(sock);
	return (0);
}

int
nng_socket_id(nng_socket s)
{
	return (((int) s.id > 0) ? (int) s.id : -1);
}

void *
nng_alloc(size_t sz)
{
	return (nni_alloc(sz));
}

void *
nng_zalloc(size_t sz)
{
	return (nni_zalloc(sz));
}

void
nng_free(void *buf, size_t sz)
{
	nni_free(buf, sz);
}

char *
nng_strdup(const char *src)
{
	return (nni_strdup(src));
}

void
nng_strfree(char *s)
{
	nni_strfree(s);
}

int
nng_recv(nng_socket s, void *buf, size_t *szp, int flags)
{
	nng_msg *msg;
	int      rv;

	// Note that while it would be nice to make this a zero copy operation,
	// its not normally possible if a size was specified.
	if ((rv = nng_recvmsg(s, &msg, flags & ~(NNG_FLAG_ALLOC))) != 0) {
		return (rv);
	}
	if (!(flags & NNG_FLAG_ALLOC)) {
		memcpy(buf, nng_msg_body(msg),
		    *szp > nng_msg_len(msg) ? nng_msg_len(msg) : *szp);
		*szp = nng_msg_len(msg);
	} else {
		// We'd really like to avoid a separate data copy, but since
		// we have allocated messages with headroom, we can't really
		// make free() work on the base pointer.  We'd have to have
		// some other API for this.  Folks that want zero copy had
		// better use nng_recvmsg() instead.
		void *nbuf;

		if (nng_msg_len(msg) != 0) {
			if ((nbuf = nni_alloc(nng_msg_len(msg))) == NULL) {
				nng_msg_free(msg);
				return (NNG_ENOMEM);
			}

			*(void **) buf = nbuf;
			memcpy(nbuf, nni_msg_body(msg), nni_msg_len(msg));
			*szp = nng_msg_len(msg);
		} else {
			*(void **) buf = NULL;
			*szp           = 0;
		}
	}
	nni_msg_free(msg);
	return (0);
}

int
nng_recvmsg(nng_socket s, nng_msg **msgp, int flags)
{
	int       rv;
	nni_sock *sock;
	nni_aio   aio;

	if ((rv = nni_sock_find(&sock, s.id)) != 0) {
		return (rv);
	}

	nni_aio_init(&aio, NULL, NULL);
	if (flags & NNG_FLAG_NONBLOCK) {
		nng_aio_set_timeout(&aio, NNG_DURATION_ZERO);
	} else {
		nng_aio_set_timeout(&aio, NNG_DURATION_DEFAULT);
	}
	nni_sock_recv(sock, &aio);
	nni_sock_rele(sock);

	nni_aio_wait(&aio);

	if ((rv = nni_aio_result(&aio)) == 0) {
		*msgp = nng_aio_get_msg(&aio);

	} else if ((rv == NNG_ETIMEDOUT) &&
	    ((flags & NNG_FLAG_NONBLOCK) == NNG_FLAG_NONBLOCK)) {
		rv = NNG_EAGAIN;
	}
	nni_aio_fini(&aio);

	return (rv);
}

int
nng_send(nng_socket s, void *buf, size_t len, int flags)
{
	nng_msg *msg;
	int      rv;

	if ((rv = nng_msg_alloc(&msg, len)) != 0) {
		return (rv);
	}
	memcpy(nng_msg_body(msg), buf, len);
	if ((rv = nng_sendmsg(s, msg, flags)) != 0) {
		// If nng_sendmsg() succeeded, then it took ownership.
		nng_msg_free(msg);
	} else {
		if (flags & NNG_FLAG_ALLOC) {
			nni_free(buf, len);
		}
	}
	return (rv);
}

int
nng_sendmsg(nng_socket s, nng_msg *msg, int flags)
{
	int       rv;
	nni_aio   aio;
	nni_sock *sock;

	if (msg == NULL) {
		return (NNG_EINVAL);
	}
	if ((rv = nni_sock_find(&sock, s.id)) != 0) {
		return (rv);
	}

	nni_aio_init(&aio, NULL, NULL);
	if ((flags & NNG_FLAG_NONBLOCK) == NNG_FLAG_NONBLOCK) {
		nni_aio_set_timeout(&aio, NNG_DURATION_ZERO);
	} else {
		nni_aio_set_timeout(&aio, NNG_DURATION_DEFAULT);
	}

	nng_aio_set_msg(&aio, msg);
	nni_sock_send(sock, &aio);
	nni_sock_rele(sock);

	nni_aio_wait(&aio);
	rv = nni_aio_result(&aio);
	nni_aio_fini(&aio);

	// Possibly massage nonblocking attempt.  Note that nonblocking is
	// still done asynchronously, and the calling thread loses context.
	if ((rv == NNG_ETIMEDOUT) &&
	    ((flags & NNG_FLAG_NONBLOCK) == NNG_FLAG_NONBLOCK)) {
		rv = NNG_EAGAIN;
	}

	return (rv);
}

void
nng_recv_aio(nng_socket s, nng_aio *aio)
{
	nni_sock *sock;
	int       rv;

	if ((rv = nni_sock_find(&sock, s.id)) != 0) {
		if (nni_aio_begin(aio) == 0) {
			nni_aio_finish_error(aio, rv);
		}
		return;
	}
	nni_sock_recv(sock, aio);
	nni_sock_rele(sock);
}

void
nng_send_aio(nng_socket s, nng_aio *aio)
{
	nni_sock *sock;
	int       rv;

	if (nni_aio_get_msg(aio) == NULL) {
		if (nni_aio_begin(aio) == 0) {
			nni_aio_finish_error(aio, NNG_EINVAL);
		}
		return;
	}
	if ((rv = nni_sock_find(&sock, s.id)) != 0) {
		if (nni_aio_begin(aio) == 0) {
			nni_aio_finish_error(aio, rv);
		}
		return;
	}
	nni_sock_send(sock, aio);
	nni_sock_rele(sock);
}

int
nng_ctx_open(nng_ctx *cp, nng_socket s)
{
	nni_sock *sock;
	nni_ctx  *ctx;
	int       rv;
	nng_ctx   c;

	if ((rv = nni_sock_find(&sock, s.id)) != 0) {
		return (rv);
	}
	if ((rv = nni_ctx_open(&ctx, sock)) != 0) {
		nni_sock_rele(sock);
		return (rv);
	}
	c.id = nni_ctx_id(ctx);
	nni_ctx_rele(ctx);
	nni_sock_rele(sock);
	*cp = c;
	return (0);
}

int
nng_ctx_close(nng_ctx c)
{
	int      rv;
	nni_ctx *ctx;

	if ((rv = nni_ctx_find(&ctx, c.id, true)) != 0) {
		return (rv);
	}
	// no release, close releases implicitly.
	nni_ctx_close(ctx);
	return (0);
}

int
nng_ctx_id(nng_ctx c)
{
	return (((int) c.id > 0) ? (int) c.id : -1);
}

int
nng_ctx_recvmsg(nng_ctx cid, nng_msg **msgp, int flags)
{
	int       rv;
	nni_aio   aio;
	nni_ctx  *ctx;

	if ((rv = nni_ctx_find(&ctx, cid.id, false)) != 0) {
		return (rv);
	}

	nni_aio_init(&aio, NULL, NULL);
	if (flags & NNG_FLAG_NONBLOCK) {
		nng_aio_set_timeout(&aio, NNG_DURATION_ZERO);
	} else {
		nng_aio_set_timeout(&aio, NNG_DURATION_DEFAULT);
	}
	nni_ctx_recv(ctx, &aio);
	nni_ctx_rele(ctx);

	nni_aio_wait(&aio);

	if ((rv = nni_aio_result(&aio)) == 0) {
		*msgp = nng_aio_get_msg(&aio);

	} else if ((rv == NNG_ETIMEDOUT) &&
	    ((flags & NNG_FLAG_NONBLOCK) == NNG_FLAG_NONBLOCK)) {
		rv = NNG_EAGAIN;
	}
	nni_aio_fini(&aio);

	return (rv);
}

void
nng_ctx_recv(nng_ctx cid, nng_aio *aio)
{
	int      rv;
	nni_ctx *ctx;

	debug_msg(" ######## nng_ctx_recv context id %d ######## ", cid.id);
	if ((rv = nni_ctx_find(&ctx, cid.id, false)) != 0) {
		if (nni_aio_begin(aio) == 0) {
			nni_aio_finish_error(aio, rv);
		}
		return;
	}
	nni_ctx_recv(ctx, aio);
	nni_ctx_rele(ctx);
}

void
nng_ctx_send(nng_ctx cid, nng_aio *aio)
{
	int      rv;
	nni_ctx *ctx;

	if (nni_aio_get_msg(aio) == NULL) {
		if (nni_aio_begin(aio) == 0) {
			nni_aio_finish_error(aio, NNG_EINVAL);
		}
		return;
	}
	if ((rv = nni_ctx_find(&ctx, cid.id, false)) != 0) {
		if (nni_aio_begin(aio) == 0) {
			nni_aio_finish_error(aio, rv);
		}
		return;
	}
	nni_ctx_send(ctx, aio);
	nni_ctx_rele(ctx);
}

int
nng_ctx_sendmsg(nng_ctx cid, nng_msg *msg, int flags)
{
	int       rv;
	nni_aio   aio;
	nni_ctx *ctx;

	if (msg == NULL) {
		return (NNG_EINVAL);
	}
	if ((rv = nni_ctx_find(&ctx, cid.id, false)) != 0) {
		return (rv);
	}

	nni_aio_init(&aio, NULL, NULL);
	if ((flags & NNG_FLAG_NONBLOCK) == NNG_FLAG_NONBLOCK) {
		nni_aio_set_timeout(&aio, NNG_DURATION_ZERO);
	} else {
		nni_aio_set_timeout(&aio, NNG_DURATION_DEFAULT);
	}

	nng_aio_set_msg(&aio, msg);
	nni_ctx_send(ctx, &aio);
	nni_ctx_rele(ctx);

	nni_aio_wait(&aio);
	rv = nni_aio_result(&aio);
	nni_aio_fini(&aio);

	// Possibly massage nonblocking attempt.  Note that nonblocking is
	// still done asynchronously, and the calling thread loses context.
	if ((rv == NNG_ETIMEDOUT) &&
	    ((flags & NNG_FLAG_NONBLOCK) == NNG_FLAG_NONBLOCK)) {
		rv = NNG_EAGAIN;
	}

	return (rv);
}

static int
ctx_get(nng_ctx id, const char *n, void *v, size_t *szp, nni_type t)
{
	nni_ctx *ctx;
	int      rv;

	if ((rv = nni_init()) != 0) {
		return (rv);
	}
	if ((rv = nni_ctx_find(&ctx, id.id, false)) != 0) {
		return (rv);
	}
	rv = nni_ctx_getopt(ctx, n, v, szp, t);
	nni_ctx_rele(ctx);
	return (rv);
}

int
nng_ctx_get(nng_ctx id, const char *n, void *v, size_t *szp)
{
	return (ctx_get(id, n, v, szp, NNI_TYPE_OPAQUE));
}

int
nng_ctx_get_int(nng_ctx id, const char *n, int *v)
{
	return (ctx_get(id, n, v, NULL, NNI_TYPE_INT32));
}

int
nng_ctx_get_bool(nng_ctx id, const char *n, bool *v)
{
	return (ctx_get(id, n, v, NULL, NNI_TYPE_BOOL));
}

int
nng_ctx_get_size(nng_ctx id, const char *n, size_t *v)
{
	return (ctx_get(id, n, v, NULL, NNI_TYPE_SIZE));
}

int
nng_ctx_get_uint64(nng_ctx id, const char *n, uint64_t *v)
{
	return (ctx_get(id, n, v, NULL, NNI_TYPE_UINT64));
}

int
nng_ctx_get_string(nng_ctx id, const char *n, char **v)
{
	return (ctx_get(id, n, v, NULL, NNI_TYPE_STRING));
}

int
nng_ctx_get_ptr(nng_ctx id, const char *n, void **v)
{
	return (ctx_get(id, n, v, NULL, NNI_TYPE_POINTER));
}

int
nng_ctx_get_ms(nng_ctx id, const char *n, nng_duration *v)
{
	return (ctx_get(id, n, v, NULL, NNI_TYPE_DURATION));
}

int
nng_ctx_get_addr(nng_ctx id, const char *n, nng_sockaddr *v)
{
	return (ctx_get(id, n, v, NULL, NNI_TYPE_SOCKADDR));
}

static int
ctx_set(nng_ctx id, const char *n, const void *v, size_t sz, nni_type t)
{
	nni_ctx *ctx;
	int      rv;

	if ((rv = nni_init()) != 0) {
		return (rv);
	}
	if ((rv = nni_ctx_find(&ctx, id.id, false)) != 0) {
		return (rv);
	}
	rv = nni_ctx_setopt(ctx, n, v, sz, t);
	nni_ctx_rele(ctx);
	return (rv);
}

int
nng_ctx_set(nng_ctx id, const char *n, const void *v, size_t sz)
{
	return (ctx_set(id, n, v, sz, NNI_TYPE_OPAQUE));
}

int
nng_ctx_set_int(nng_ctx id, const char *n, int v)
{
	return (ctx_set(id, n, &v, sizeof(v), NNI_TYPE_INT32));
}

int
nng_ctx_set_bool(nng_ctx id, const char *n, bool v)
{
	return (ctx_set(id, n, &v, sizeof(v), NNI_TYPE_BOOL));
}

int
nng_ctx_set_size(nng_ctx id, const char *n, size_t v)
{
	return (ctx_set(id, n, &v, sizeof(v), NNI_TYPE_SIZE));
}

int
nng_ctx_set_uint64(nng_ctx id, const char *n, uint64_t v)
{
	return (ctx_set(id, n, &v, sizeof(v), NNI_TYPE_UINT64));
}

int
nng_ctx_set_ms(nng_ctx id, const char *n, nng_duration v)
{
	return (ctx_set(id, n, &v, sizeof(v), NNI_TYPE_DURATION));
}

int
nng_ctx_set_ptr(nng_ctx id, const char *n, void *v)
{
	return (ctx_set(id, n, &v, sizeof(v), NNI_TYPE_POINTER));
}

int
nng_ctx_set_string(nng_ctx id, const char *n, const char *v)
{
	return (
	    ctx_set(id, n, v, v == NULL ? 0 : strlen(v) + 1, NNI_TYPE_STRING));
}

int
nng_ctx_set_addr(nng_ctx id, const char *n, const nng_sockaddr *v)
{
	return (ctx_set(id, n, v, sizeof(*v), NNI_TYPE_SOCKADDR));
}

int
nng_dial(nng_socket sid, const char *addr, nng_dialer *dp, int flags)
{
	nni_dialer *d;
	int         rv;
	nni_sock   *s;

	if ((rv = nni_sock_find(&s, sid.id)) != 0) {
		return (rv);
	}
	if ((rv = nni_dialer_create(&d, s, addr)) != 0) {
		nni_sock_rele(s);
		return (rv);
	}
	if ((rv = nni_dialer_start(d, flags)) != 0) {
		nni_dialer_close(d);
		return (rv);
	}
	if (dp != NULL) {
		nng_dialer did;
		did.id = nni_dialer_id(d);
		*dp    = did;
	}
	nni_dialer_rele(d);
	return (0);
}

int
nng_listen(nng_socket sid, const char *addr, nng_listener *lp, int flags)
{
	int           rv;
	nni_sock     *s;
	nni_listener *l;

	if ((rv = nni_sock_find(&s, sid.id)) != 0) {
		return (rv);
	}
	if ((rv = nni_listener_create(&l, s, addr)) != 0) {
		nni_sock_rele(s);
		return (rv);
	}
	if ((rv = nni_listener_start(l, flags)) != 0) {
		nni_listener_close(l);
		return (rv);
	}

	if (lp != NULL) {
		nng_listener lid;
		lid.id = nni_listener_id(l);
		*lp    = lid;
	}
	nni_listener_rele(l);
	return (rv);
}

int
nng_listener_create(nng_listener *lp, nng_socket sid, const char *addr)
{
	nni_sock     *s;
	int           rv;
	nni_listener *l;
	nng_listener  lid;

	if ((rv = nni_sock_find(&s, sid.id)) != 0) {
		return (rv);
	}
	if ((rv = nni_listener_create(&l, s, addr)) != 0) {
		nni_sock_rele(s);
		return (rv);
	}
	lid.id = nni_listener_id(l);
	*lp    = lid;
	nni_listener_rele(l);
	return (0);
}

int
nng_listener_start(nng_listener lid, int flags)
{
	nni_listener *l;
	int           rv;

	if ((rv = nni_listener_find(&l, lid.id)) != 0) {
		return (rv);
	}
	rv = nni_listener_start(l, flags);
	nni_listener_rele(l);
	return (rv);
}

int
nng_listener_id(nng_listener l)
{
	return (((int) l.id > 0) ? (int) l.id : -1);
}

int
nng_dialer_create(nng_dialer *dp, nng_socket sid, const char *addr)
{
	nni_sock   *s;
	nni_dialer *d;
	int         rv;
	nng_dialer  did;

	if ((rv = nni_sock_find(&s, sid.id)) != 0) {
		return (rv);
	}
	if ((rv = nni_dialer_create(&d, s, addr)) != 0) {
		nni_sock_rele(s);
		return (rv);
	}
	did.id = nni_dialer_id(d);
	*dp    = did;
	nni_dialer_rele(d);
	return (0);
}

int
nng_dialer_set_cb(nng_dialer did, void *cb)
{
	nni_dialer *d;
	int         rv;

	if ((rv = nni_dialer_find(&d, did.id)) != 0) {
		return (rv);
	}

	nni_dialer_setcb(d, cb);
	return (0);
}

int
nng_dialer_start(nng_dialer did, int flags)
{
	nni_dialer *d;
	int         rv;

	if ((rv = nni_dialer_find(&d, did.id)) != 0) {
		return (rv);
	}
	rv = nni_dialer_start(d, flags);
	nni_dialer_rele(d);
	return (rv);
}

int
nng_dialer_id(nng_dialer d)
{
	return (((int) d.id > 0) ? (int) d.id : -1);
}

static int
dialer_set(nng_dialer id, const char *n, const void *v, size_t sz, nni_type t)
{
	nni_dialer *d;
	int         rv;

	if ((rv = nni_init()) != 0) {
		return (rv);
	}
	if ((rv = nni_dialer_find(&d, id.id)) != 0) {
		return (rv);
	}
	rv = nni_dialer_setopt(d, n, v, sz, t);
	nni_dialer_rele(d);
	return (rv);
}

int
nng_dialer_set(nng_dialer id, const char *n, const void *v, size_t sz)
{
	return (dialer_set(id, n, v, sz, NNI_TYPE_OPAQUE));
}

int
nng_dialer_set_int(nng_dialer id, const char *n, int v)
{
	return (dialer_set(id, n, &v, sizeof(v), NNI_TYPE_INT32));
}

int
nng_dialer_set_bool(nng_dialer id, const char *n, bool v)
{
	return (dialer_set(id, n, &v, sizeof(v), NNI_TYPE_BOOL));
}

int
nng_dialer_set_size(nng_dialer id, const char *n, size_t v)
{
	return (dialer_set(id, n, &v, sizeof(v), NNI_TYPE_SIZE));
}

int
nng_dialer_set_uint64(nng_dialer id, const char *n, uint64_t v)
{
	return (dialer_set(id, n, &v, sizeof(v), NNI_TYPE_UINT64));
}

int
nng_dialer_set_ms(nng_dialer id, const char *n, nng_duration v)
{
	return (dialer_set(id, n, &v, sizeof(v), NNI_TYPE_DURATION));
}

int
nng_dialer_set_ptr(nng_dialer id, const char *n, void *v)
{
	return (dialer_set(id, n, &v, sizeof(v), NNI_TYPE_POINTER));
}

int
nng_dialer_set_string(nng_dialer id, const char *n, const char *v)
{
	return (dialer_set(
	    id, n, v, v == NULL ? 0 : strlen(v) + 1, NNI_TYPE_STRING));
}

int
nng_dialer_set_addr(nng_dialer id, const char *n, const nng_sockaddr *v)
{
	return (dialer_set(id, n, v, sizeof(*v), NNI_TYPE_SOCKADDR));
}

static int
dialer_get(nng_dialer id, const char *n, void *v, size_t *szp, nni_type t)
{
	nni_dialer *d;
	int         rv;

	if ((rv = nni_init()) != 0) {
		return (rv);
	}
	if ((rv = nni_dialer_find(&d, id.id)) != 0) {
		return (rv);
	}
	rv = nni_dialer_getopt(d, n, v, szp, t);
	nni_dialer_rele(d);
	return (rv);
}

int
nng_dialer_get(nng_dialer id, const char *n, void *v, size_t *szp)
{
	return (dialer_get(id, n, v, szp, NNI_TYPE_OPAQUE));
}

int
nng_dialer_get_int(nng_dialer id, const char *n, int *v)
{
	return (dialer_get(id, n, v, NULL, NNI_TYPE_INT32));
}

int
nng_dialer_get_bool(nng_dialer id, const char *n, bool *v)
{
	return (dialer_get(id, n, v, NULL, NNI_TYPE_BOOL));
}

int
nng_dialer_get_size(nng_dialer id, const char *n, size_t *v)
{
	return (dialer_get(id, n, v, NULL, NNI_TYPE_SIZE));
}

int
nng_dialer_get_uint64(nng_dialer id, const char *n, uint64_t *v)
{
	return (dialer_get(id, n, v, NULL, NNI_TYPE_UINT64));
}

int
nng_dialer_get_string(nng_dialer id, const char *n, char **v)
{
	return (dialer_get(id, n, v, NULL, NNI_TYPE_STRING));
}

int
nng_dialer_get_ptr(nng_dialer id, const char *n, void **v)
{
	return (dialer_get(id, n, v, NULL, NNI_TYPE_POINTER));
}

int
nng_dialer_get_ms(nng_dialer id, const char *n, nng_duration *v)
{
	return (dialer_get(id, n, v, NULL, NNI_TYPE_DURATION));
}

int
nng_dialer_get_addr(nng_dialer id, const char *n, nng_sockaddr *v)
{
	return (dialer_get(id, n, v, NULL, NNI_TYPE_SOCKADDR));
}

static int
listener_set(
    nng_listener lid, const char *name, const void *v, size_t sz, nni_type t)
{
	nni_listener *l;
	int           rv;

	if ((rv = nni_init()) != 0) {
		return (rv);
	}
	if ((rv = nni_listener_find(&l, lid.id)) != 0) {
		return (rv);
	}
	rv = nni_listener_setopt(l, name, v, sz, t);
	nni_listener_rele(l);
	return (rv);
}

int
nng_listener_set(nng_listener id, const char *n, const void *v, size_t sz)
{
	return (listener_set(id, n, v, sz, NNI_TYPE_OPAQUE));
}

int
nng_listener_set_int(nng_listener id, const char *n, int v)
{
	return (listener_set(id, n, &v, sizeof(v), NNI_TYPE_INT32));
}

int
nng_listener_set_bool(nng_listener id, const char *n, bool v)
{
	return (listener_set(id, n, &v, sizeof(v), NNI_TYPE_BOOL));
}

int
nng_listener_set_size(nng_listener id, const char *n, size_t v)
{
	return (listener_set(id, n, &v, sizeof(v), NNI_TYPE_SIZE));
}

int
nng_listener_set_uint64(nng_listener id, const char *n, uint64_t v)
{
	return (listener_set(id, n, &v, sizeof(v), NNI_TYPE_UINT64));
}

int
nng_listener_set_ms(nng_listener id, const char *n, nng_duration v)
{
	return (listener_set(id, n, &v, sizeof(v), NNI_TYPE_DURATION));
}

int
nng_listener_set_ptr(nng_listener id, const char *n, void *v)
{
	return (listener_set(id, n, &v, sizeof(v), NNI_TYPE_POINTER));
}

int
nng_listener_set_string(nng_listener id, const char *n, const char *v)
{
	return (listener_set(
	    id, n, v, v == NULL ? 0 : strlen(v) + 1, NNI_TYPE_STRING));
}

int
nng_listener_set_addr(nng_listener id, const char *n, const nng_sockaddr *v)
{
	return (listener_set(id, n, v, sizeof(*v), NNI_TYPE_SOCKADDR));
}

static int
listener_get(
    nng_listener lid, const char *name, void *v, size_t *szp, nni_type t)
{
	nni_listener *l;
	int           rv;

	if ((rv = nni_init()) != 0) {
		return (rv);
	}
	if ((rv = nni_listener_find(&l, lid.id)) != 0) {
		return (rv);
	}
	rv = nni_listener_getopt(l, name, v, szp, t);
	nni_listener_rele(l);
	return (rv);
}

int
nng_listener_get(nng_listener id, const char *n, void *v, size_t *szp)
{
	return (listener_get(id, n, v, szp, NNI_TYPE_OPAQUE));
}

int
nng_listener_get_int(nng_listener id, const char *n, int *v)
{
	return (listener_get(id, n, v, NULL, NNI_TYPE_INT32));
}

int
nng_listener_get_bool(nng_listener id, const char *n, bool *v)
{
	return (listener_get(id, n, v, NULL, NNI_TYPE_BOOL));
}

int
nng_listener_get_size(nng_listener id, const char *n, size_t *v)
{
	return (listener_get(id, n, v, NULL, NNI_TYPE_SIZE));
}

int
nng_listener_get_uint64(nng_listener id, const char *n, uint64_t *v)
{
	return (listener_get(id, n, v, NULL, NNI_TYPE_UINT64));
}

int
nng_listener_get_string(nng_listener id, const char *n, char **v)
{
	return (listener_get(id, n, v, NULL, NNI_TYPE_STRING));
}

int
nng_listener_get_ptr(nng_listener id, const char *n, void **v)
{
	return (listener_get(id, n, v, NULL, NNI_TYPE_POINTER));
}

int
nng_listener_get_ms(nng_listener id, const char *n, nng_duration *v)
{
	return (listener_get(id, n, v, NULL, NNI_TYPE_DURATION));
}

int
nng_listener_get_addr(nng_listener id, const char *n, nng_sockaddr *v)
{
	return (listener_get(id, n, v, NULL, NNI_TYPE_SOCKADDR));
}

int
nng_dialer_close(nng_dialer did)
{
	nni_dialer *d;
	int         rv;

	if ((rv = nni_dialer_find(&d, did.id)) != 0) {
		return (rv);
	}
	nni_dialer_close(d);
	return (0);
}

int
nng_listener_close(nng_listener lid)
{
	nni_listener *l;
	int           rv;

	if ((rv = nni_listener_find(&l, lid.id)) != 0) {
		return (rv);
	}
	nni_listener_close(l);
	return (0);
}

static int
socket_set(
    nng_socket s, const char *name, const void *val, size_t sz, nni_type t)
{
	nni_sock *sock;
	int       rv;

	if ((rv = nni_init()) != 0) {
		return (rv);
	}
	if ((rv = nni_sock_find(&sock, s.id)) != 0) {
		return (rv);
	}
	rv = nni_sock_setopt(sock, name, val, sz, t);
	nni_sock_rele(sock);
	return (rv);
}

int
nng_socket_set(nng_socket id, const char *n, const void *v, size_t sz)
{
	return (socket_set(id, n, v, sz, NNI_TYPE_OPAQUE));
}

int
nng_socket_set_int(nng_socket id, const char *n, int v)
{
	return (socket_set(id, n, &v, sizeof(v), NNI_TYPE_INT32));
}

int
nng_socket_set_bool(nng_socket id, const char *n, bool v)
{
	return (socket_set(id, n, &v, sizeof(v), NNI_TYPE_BOOL));
}

int
nng_socket_set_size(nng_socket id, const char *n, size_t v)
{
	return (socket_set(id, n, &v, sizeof(v), NNI_TYPE_SIZE));
}

int
nng_socket_set_uint64(nng_socket id, const char *n, uint64_t v)
{
	return (socket_set(id, n, &v, sizeof(v), NNI_TYPE_UINT64));
}

int
nng_socket_set_ms(nng_socket id, const char *n, nng_duration v)
{
	return (socket_set(id, n, &v, sizeof(v), NNI_TYPE_DURATION));
}

int
nng_socket_set_ptr(nng_socket id, const char *n, void *v)
{
	return (socket_set(id, n, &v, sizeof(v), NNI_TYPE_POINTER));
}

int
nng_socket_set_string(nng_socket id, const char *n, const char *v)
{
	return (socket_set(
	    id, n, v, v == NULL ? 0 : strlen(v) + 1, NNI_TYPE_STRING));
}

int
nng_socket_set_addr(nng_socket id, const char *n, const nng_sockaddr *v)
{
	return (socket_set(id, n, v, sizeof(*v), NNI_TYPE_SOCKADDR));
}

static int
socket_get(nng_socket s, const char *name, void *val, size_t *szp, nni_type t)
{
	nni_sock *sock;
	int       rv;

	if ((rv = nni_init()) != 0) {
		return (rv);
	}
	if ((rv = nni_sock_find(&sock, s.id)) != 0) {
		return (rv);
	}
	rv = nni_sock_getopt(sock, name, val, szp, t);
	nni_sock_rele(sock);
	return (rv);
}

int
nng_socket_get(nng_socket id, const char *n, void *v, size_t *szp)
{
	return (socket_get(id, n, v, szp, NNI_TYPE_OPAQUE));
}

int
nng_socket_get_int(nng_socket id, const char *n, int *v)
{
	return (socket_get(id, n, v, NULL, NNI_TYPE_INT32));
}

int
nng_socket_get_bool(nng_socket id, const char *n, bool *v)
{
	return (socket_get(id, n, v, NULL, NNI_TYPE_BOOL));
}

int
nng_socket_get_size(nng_socket id, const char *n, size_t *v)
{
	return (socket_get(id, n, v, NULL, NNI_TYPE_SIZE));
}

int
nng_socket_get_uint64(nng_socket id, const char *n, uint64_t *v)
{
	return (socket_get(id, n, v, NULL, NNI_TYPE_UINT64));
}

int
nng_socket_get_string(nng_socket id, const char *n, char **v)
{
	return (socket_get(id, n, v, NULL, NNI_TYPE_STRING));
}

int
nng_socket_get_ptr(nng_socket id, const char *n, void **v)
{
	return (socket_get(id, n, v, NULL, NNI_TYPE_POINTER));
}

int
nng_socket_get_ms(nng_socket id, const char *n, nng_duration *v)
{
	return (socket_get(id, n, v, NULL, NNI_TYPE_DURATION));
}

int
nng_socket_get_addr(nng_socket id, const char *n, nng_sockaddr *v)
{
	return (socket_get(id, n, v, NULL, NNI_TYPE_SOCKADDR));
}

int
nng_pipe_notify(nng_socket s, nng_pipe_ev ev, nng_pipe_cb cb, void *arg)
{
	int       rv;
	nni_sock *sock;

	if ((rv = nni_init()) != 0) {
		return (rv);
	}
	if ((rv = nni_sock_find(&sock, s.id)) != 0) {
		return (rv);
	}

	nni_sock_set_pipe_cb(sock, ev, cb, arg);
	nni_sock_rele(sock);
	return (0);
}

int
nng_device(nng_socket s1, nng_socket s2)
{
	int       rv;
	nni_sock *sock1 = NULL;
	nni_sock *sock2 = NULL;

	if ((s1.id > 0) && (s1.id != (uint32_t) -1)) {
		if ((rv = nni_sock_find(&sock1, s1.id)) != 0) {
			return (rv);
		}
	}
	if (((s2.id > 0) && (s2.id != (uint32_t) -1)) && (s2.id != s1.id)) {
		if ((rv = nni_sock_find(&sock2, s2.id)) != 0) {
			nni_sock_rele(sock1);
			return (rv);
		}
	}

	rv = nni_device(sock1, sock2);
	if (sock1 != NULL) {
		nni_sock_rele(sock1);
	}
	if (sock2 != NULL) {
		nni_sock_rele(sock2);
	}
	return (rv);
}

static const struct {
	int         code;
	const char *msg;
} nni_errors[] = {
	// clang-format off
	{ 0, "Hunky dory" },
	{ NNG_EINTR, "Interrupted" },
	{ NNG_ENOMEM, "Out of memory" },
	{ NNG_EINVAL, "Invalid argument" },
	{ NNG_EBUSY, "Resource busy" },
	{ NNG_ETIMEDOUT, "Timed out" },
	{ NNG_ECONNREFUSED, "Connection refused" },
	{ NNG_ECLOSED, "Object closed" },
	{ NNG_EAGAIN, "Try again" },
	{ NNG_ENOTSUP, "Not supported" },
	{ NNG_EADDRINUSE, "Address in use" },
	{ NNG_ESTATE, "Incorrect state" },
	{ NNG_ENOENT, "Entry not found" },
	{ NNG_EPROTO, "Protocol error" },
	{ NNG_EUNREACHABLE, "Destination unreachable" },
	{ NNG_EADDRINVAL, "Address invalid" },
	{ NNG_EPERM, "Permission denied" },
	{ NNG_EMSGSIZE, "Message too large" },
	{ NNG_ECONNRESET, "Connection reset" },
	{ NNG_ECONNABORTED, "Connection aborted" },
	{ NNG_ECANCELED, "Operation canceled" },
	{ NNG_ENOFILES, "Out of files" },
	{ NNG_ENOSPC, "Out of space" },
	{ NNG_EEXIST, "Resource already exists" },
	{ NNG_EREADONLY, "Read only resource" },
	{ NNG_EWRITEONLY, "Write only resource" },
	{ NNG_ECRYPTO, "Cryptographic error" },
	{ NNG_EPEERAUTH, "Peer could not be authenticated" },
	{ NNG_ENOARG, "Option requires argument" },
	{ NNG_EAMBIGUOUS, "Ambiguous option" },
	{ NNG_EBADTYPE, "Incorrect type" },
	{ NNG_ECONNSHUT, "Connection shutdown" },
	{ NNG_EINTERNAL, "Internal error detected" },
	{ 0, NULL },
	// clang-format on
};

// Misc.
const char *
nng_strerror(int num)
{
	static char unknownerrbuf[32];
	for (int i = 0; nni_errors[i].msg != NULL; i++) {
		if (nni_errors[i].code == num) {
			return (nni_errors[i].msg);
		}
	}

	if (num & NNG_ESYSERR) {
		return (nni_plat_strerror(num & ~NNG_ESYSERR));
	}

	if (num & NNG_ETRANERR) {
		static char tranerrbuf[32];
		(void) snprintf(tranerrbuf, sizeof(tranerrbuf),
		    "Transport error #%d", num & ~NNG_ETRANERR);
		return (tranerrbuf);
	}

	(void) snprintf(
	    unknownerrbuf, sizeof(unknownerrbuf), "Unknown error #%d", num);
	return (unknownerrbuf);
}

static int
pipe_get(nng_pipe p, const char *name, void *val, size_t *szp, nni_type t)
{
	int       rv;
	nni_pipe *pipe;

	if ((rv = nni_init()) < 0) {
		return (rv);
	}
	if ((rv = nni_pipe_find(&pipe, p.id)) != 0) {
		return (rv);
	}
	rv = nni_pipe_getopt(pipe, name, val, szp, t);
	nni_pipe_rele(pipe);
	return (rv);
}

int
nng_pipe_get(nng_pipe id, const char *n, void *v, size_t *szp)
{
	return (pipe_get(id, n, v, szp, NNI_TYPE_OPAQUE));
}

int
nng_pipe_get_int(nng_pipe id, const char *n, int *v)
{
	return (pipe_get(id, n, v, NULL, NNI_TYPE_INT32));
}

int
nng_pipe_get_bool(nng_pipe id, const char *n, bool *v)
{
	return (pipe_get(id, n, v, NULL, NNI_TYPE_BOOL));
}

int
nng_pipe_get_size(nng_pipe id, const char *n, size_t *v)
{
	return (pipe_get(id, n, v, NULL, NNI_TYPE_SIZE));
}

int
nng_pipe_get_uint64(nng_pipe id, const char *n, uint64_t *v)
{
	return (pipe_get(id, n, v, NULL, NNI_TYPE_UINT64));
}

int
nng_pipe_get_string(nng_pipe id, const char *n, char **v)
{
	return (pipe_get(id, n, v, NULL, NNI_TYPE_STRING));
}

int
nng_pipe_get_ptr(nng_pipe id, const char *n, void **v)
{
	return (pipe_get(id, n, v, NULL, NNI_TYPE_POINTER));
}

int
nng_pipe_get_ms(nng_pipe id, const char *n, nng_duration *v)
{
	return (pipe_get(id, n, v, NULL, NNI_TYPE_DURATION));
}

int
nng_pipe_get_addr(nng_pipe id, const char *n, nng_sockaddr *v)
{
	return (pipe_get(id, n, v, NULL, NNI_TYPE_SOCKADDR));
}

nng_socket
nng_pipe_socket(nng_pipe p)
{
	nng_socket s = NNG_SOCKET_INITIALIZER;
	nni_pipe  *pipe;

	if ((nni_init() == 0) && (nni_pipe_find(&pipe, p.id) == 0)) {
		s.id = nni_pipe_sock_id(pipe);
		nni_pipe_rele(pipe);
	}
	return (s);
}

nng_dialer
nng_pipe_dialer(nng_pipe p)
{
	nng_dialer d = NNG_DIALER_INITIALIZER;
	nni_pipe  *pipe;
	if ((nni_init() == 0) && (nni_pipe_find(&pipe, p.id) == 0)) {
		d.id = nni_pipe_dialer_id(pipe);
		nni_pipe_rele(pipe);
	}
	return (d);
}

nng_listener
nng_pipe_listener(nng_pipe p)
{
	nng_listener l = NNG_LISTENER_INITIALIZER;
	nni_pipe    *pipe;
	if ((nni_init() == 0) && (nni_pipe_find(&pipe, p.id) == 0)) {
		l.id = nni_pipe_listener_id(pipe);
		nni_pipe_rele(pipe);
	}
	return (l);
}

int
nng_pipe_close(nng_pipe p)
{
	int       rv;
	nni_pipe *pipe;

	if ((rv = nni_pipe_find(&pipe, p.id)) != 0) {
		return (rv);
	}
	nni_pipe_close(pipe);
	nni_pipe_rele(pipe);
	return (0);
}

int
nng_pipe_id(nng_pipe p)
{
	return (((int) p.id > 0) ? (int) p.id : -1);
}

// Message handling.
int
nng_msg_alloc(nng_msg **msgp, size_t size)
{
	return (nni_msg_alloc(msgp, size));
}

int
nng_msg_realloc(nng_msg *msg, size_t sz)
{
	return (nni_msg_realloc(msg, sz));
}

void
nng_msg_free(nng_msg *msg)
{
	nni_msg_free(msg);
}

int
nng_msg_reserve(nng_msg *msg, size_t capacity)
{
	return (nni_msg_reserve(msg, capacity));
}

size_t
nng_msg_capacity(nng_msg *msg)
{
	return (nni_msg_capacity(msg));
}

void *
nng_msg_body(nng_msg *msg)
{
	return (nni_msg_body(msg));
}

size_t
nng_msg_len(const nng_msg *msg)
{
	return (nni_msg_len(msg));
}

void *
nng_msg_header(nng_msg *msg)
{
	return (nni_msg_header(msg));
}

size_t
nng_msg_header_len(const nng_msg *msg)
{
	return (nni_msg_header_len(msg));
}

int
nng_msg_append(nng_msg *msg, const void *data, size_t sz)
{
	return (nni_msg_append(msg, data, sz));
}

int
nng_msg_insert(nng_msg *msg, const void *data, size_t sz)
{
	return (nni_msg_insert(msg, data, sz));
}

int
nng_msg_append_u16(nng_msg *msg, uint16_t v)
{
	uint8_t buf[sizeof(v)];
	NNI_PUT16(buf, v);
	return (nni_msg_append(msg, buf, sizeof(v)));
}

int
nng_msg_append_u32(nng_msg *msg, uint32_t v)
{
	uint8_t buf[sizeof(v)];
	NNI_PUT32(buf, v);
	return (nni_msg_append(msg, buf, sizeof(v)));
}

int
nng_msg_append_u64(nng_msg *msg, uint64_t v)
{
	uint8_t buf[sizeof(v)];
	NNI_PUT64(buf, v);
	return (nni_msg_append(msg, buf, sizeof(v)));
}

int
nng_msg_insert_u16(nng_msg *msg, uint16_t v)
{
	uint8_t buf[sizeof(v)];
	NNI_PUT16(buf, v);
	return (nni_msg_insert(msg, buf, sizeof(v)));
}

int
nng_msg_insert_u32(nng_msg *msg, uint32_t v)
{
	uint8_t buf[sizeof(v)];
	NNI_PUT32(buf, v);
	return (nni_msg_insert(msg, buf, sizeof(v)));
}

int
nng_msg_insert_u64(nng_msg *msg, uint64_t v)
{
	uint8_t buf[sizeof(v)];
	NNI_PUT64(buf, v);
	return (nni_msg_insert(msg, buf, sizeof(v)));
}

int
nng_msg_header_append(nng_msg *msg, const void *data, size_t sz)
{
	return (nni_msg_header_append(msg, data, sz));
}

int
nng_msg_header_insert(nng_msg *msg, const void *data, size_t sz)
{
	return (nni_msg_header_insert(msg, data, sz));
}

int
nng_msg_header_append_u16(nng_msg *msg, uint16_t v)
{
	uint8_t buf[sizeof(v)];
	NNI_PUT16(buf, v);
	return (nni_msg_header_append(msg, buf, sizeof(v)));
}

int
nng_msg_header_append_u32(nng_msg *msg, uint32_t v)
{
	uint8_t buf[sizeof(v)];
	NNI_PUT32(buf, v);
	return (nni_msg_header_append(msg, buf, sizeof(v)));
}

int
nng_msg_header_append_u64(nng_msg *msg, uint64_t v)
{
	uint8_t buf[sizeof(v)];
	NNI_PUT64(buf, v);
	return (nni_msg_header_append(msg, buf, sizeof(v)));
}

int
nng_msg_header_insert_u16(nng_msg *msg, uint16_t v)
{
	uint8_t buf[sizeof(v)];
	NNI_PUT16(buf, v);
	return (nni_msg_header_insert(msg, buf, sizeof(v)));
}

int
nng_msg_header_insert_u32(nng_msg *msg, uint32_t v)
{
	uint8_t buf[sizeof(v)];
	NNI_PUT32(buf, v);
	return (nni_msg_header_insert(msg, buf, sizeof(v)));
}

int
nng_msg_header_insert_u64(nng_msg *msg, uint64_t v)
{
	uint8_t buf[sizeof(v)];
	NNI_PUT64(buf, v);
	return (nni_msg_header_insert(msg, buf, sizeof(v)));
}

int
nng_msg_trim(nng_msg *msg, size_t sz)
{
	return (nni_msg_trim(msg, sz));
}

int
nng_msg_chop(nng_msg *msg, size_t sz)
{
	return (nni_msg_chop(msg, sz));
}

int
nng_msg_header_trim(nng_msg *msg, size_t sz)
{
	return (nni_msg_header_trim(msg, sz));
}

int
nng_msg_header_chop(nng_msg *msg, size_t sz)
{
	return (nni_msg_header_chop(msg, sz));
}

int
nng_msg_chop_u16(nng_msg *m, uint16_t *vp)
{
	uint8_t *body;
	uint16_t v;
	if (nni_msg_len(m) < sizeof(*vp)) {
		return (NNG_EINVAL);
	}
	body = nni_msg_body(m);
	body += nni_msg_len(m);
	body -= sizeof(v);
	NNI_GET16(body, v);
	(void) nni_msg_chop(m, sizeof(v));
	*vp = v;
	return (0);
}

int
nng_msg_chop_u32(nng_msg *m, uint32_t *vp)
{
	uint8_t *body;
	uint32_t v;
	if (nni_msg_len(m) < sizeof(*vp)) {
		return (NNG_EINVAL);
	}
	body = nni_msg_body(m);
	body += nni_msg_len(m);
	body -= sizeof(v);
	NNI_GET32(body, v);
	(void) nni_msg_chop(m, sizeof(v));
	*vp = v;
	return (0);
}

int
nng_msg_chop_u64(nng_msg *m, uint64_t *vp)
{
	uint8_t *body;
	uint64_t v;
	if (nni_msg_len(m) < sizeof(*vp)) {
		return (NNG_EINVAL);
	}
	body = nni_msg_body(m);
	body += nni_msg_len(m);
	body -= sizeof(v);
	NNI_GET64(body, v);
	(void) nni_msg_chop(m, sizeof(v));
	*vp = v;
	return (0);
}

int
nng_msg_trim_u16(nng_msg *m, uint16_t *vp)
{
	uint8_t *body;
	uint16_t v;
	if (nni_msg_len(m) < sizeof(v)) {
		return (NNG_EINVAL);
	}
	body = nni_msg_body(m);
	NNI_GET16(body, v);
	(void) nni_msg_trim(m, sizeof(v));
	*vp = v;
	return (0);
}

int
nng_msg_trim_u32(nng_msg *m, uint32_t *vp)
{
	uint8_t *body;
	uint32_t v;
	if (nni_msg_len(m) < sizeof(v)) {
		return (NNG_EINVAL);
	}
	body = nni_msg_body(m);
	NNI_GET32(body, v);
	(void) nni_msg_trim(m, sizeof(v));
	*vp = v;
	return (0);
}

int
nng_msg_trim_u64(nng_msg *m, uint64_t *vp)
{
	uint8_t *body;
	uint64_t v;
	if (nni_msg_len(m) < sizeof(v)) {
		return (NNG_EINVAL);
	}
	body = nni_msg_body(m);
	NNI_GET64(body, v);
	(void) nni_msg_trim(m, sizeof(v));
	*vp = v;
	return (0);
}

int
nng_msg_header_chop_u16(nng_msg *msg, uint16_t *val)
{
	uint8_t *header;
	uint16_t v;
	if (nng_msg_header_len(msg) < sizeof(*val)) {
		return (NNG_EINVAL);
	}
	header = nng_msg_header(msg);
	header += nng_msg_header_len(msg);
	header -= sizeof(v);
	NNI_GET16(header, v);
	*val = v;
	nni_msg_header_chop(msg, sizeof(v));
	return (0);
}

int
nng_msg_header_chop_u32(nng_msg *msg, uint32_t *val)
{
	uint8_t *header;
	uint32_t v;
	if (nng_msg_header_len(msg) < sizeof(*val)) {
		return (NNG_EINVAL);
	}
	header = nng_msg_header(msg);
	header += nng_msg_header_len(msg);
	header -= sizeof(v);
	NNI_GET32(header, v);
	*val = v;
	nni_msg_header_chop(msg, sizeof(v));
	return (0);
}

int
nng_msg_header_chop_u64(nng_msg *msg, uint64_t *val)
{
	uint8_t *header;
	uint64_t v;
	if (nng_msg_header_len(msg) < sizeof(v)) {
		return (NNG_EINVAL);
	}
	header = nng_msg_header(msg);
	header += nng_msg_header_len(msg);
	header -= sizeof(v);
	NNI_GET64(header, v);
	*val = v;
	nni_msg_header_chop(msg, sizeof(*val));
	return (0);
}

int
nng_msg_header_trim_u16(nng_msg *msg, uint16_t *val)
{
	uint8_t *header = nni_msg_header(msg);
	uint16_t v;
	if (nng_msg_header_len(msg) < sizeof(v)) {
		return (NNG_EINVAL);
	}
	NNI_GET16(header, v);
	*val = v;
	nni_msg_header_trim(msg, sizeof(v));
	return (0);
}

int
nng_msg_header_trim_u32(nng_msg *msg, uint32_t *val)
{
	uint8_t *header = nni_msg_header(msg);
	uint32_t v;
	if (nng_msg_header_len(msg) < sizeof(v)) {
		return (NNG_EINVAL);
	}
	NNI_GET32(header, v);
	*val = v;
	nni_msg_header_trim(msg, sizeof(v));
	return (0);
}

int
nng_msg_header_trim_u64(nng_msg *msg, uint64_t *val)
{
	uint8_t *header = nni_msg_header(msg);
	uint64_t v;
	if (nng_msg_header_len(msg) < sizeof(v)) {
		return (NNG_EINVAL);
	}
	NNI_GET64(header, v);
	*val = v;
	nni_msg_header_trim(msg, sizeof(v));
	return (0);
}

void
nng_msg_clear(nng_msg *msg)
{
	nni_msg_clear(msg);
}

void
nng_msg_header_clear(nng_msg *msg)
{
	nni_msg_header_clear(msg);
}

int
nng_msg_dup(nng_msg **dup, const nng_msg *src)
{
	return (nni_msg_dup(dup, src));
}

nng_pipe
nng_msg_get_pipe(const nng_msg *msg)
{
	nng_pipe p;
	p.id = nni_msg_get_pipe(msg);
	return (p);
}

void
nng_msg_set_pipe(nng_msg *msg, nng_pipe p)
{
	nni_msg_set_pipe(msg, p.id);
}

int
nng_aio_alloc(nng_aio **app, void (*cb)(void *), void *arg)
{
	nng_aio *aio;
	int      rv;

	if ((rv = nni_init()) != 0) {
		return (rv);
	}
	if ((rv = nni_aio_alloc(&aio, (nni_cb) cb, arg)) == 0) {
		nng_aio_set_timeout(aio, NNG_DURATION_DEFAULT);
		*app = aio;
	}
	return (rv);
}

void
nng_aio_free(nng_aio *aio)
{
	nni_aio_free(aio);
}

void
nng_aio_reap(nng_aio *aio)
{
	nni_aio_reap(aio);
}

void
nng_sleep_aio(nng_duration ms, nng_aio *aio)
{
	nni_sleep_aio(ms, aio);
}

int
nng_aio_result(nng_aio *aio)
{
	return (nni_aio_result(aio));
}

size_t
nng_aio_count(nng_aio *aio)
{
	return (nni_aio_count(aio));
}

void
nng_aio_stop(nng_aio *aio)
{
	nni_aio_stop(aio);
}

void
nng_aio_wait(nng_aio *aio)
{
	nni_aio_wait(aio);
}

void
nng_aio_abort(nng_aio *aio, int err_code)
{
	nni_aio_abort(aio, err_code);
}

void
nng_aio_cancel(nng_aio *aio)
{
	nni_aio_abort(aio, NNG_ECANCELED);
}

void
nng_aio_set_msg(nng_aio *aio, nng_msg *msg)
{
	nni_aio_set_msg(aio, msg);
}

nng_msg *
nng_aio_get_msg(nng_aio *aio)
{
	return (nni_aio_get_msg(aio));
}

void
nng_aio_set_timeout(nng_aio *aio, nni_duration when)
{
	nni_aio_set_timeout(aio, when);
}

int
nng_aio_set_iov(nng_aio *aio, unsigned niov, const nng_iov *iov)
{
	return (nni_aio_set_iov(aio, niov, iov));
}

int
nng_aio_set_input(nng_aio *aio, unsigned index, void *arg)
{
	if (index > 3) {
		return (NNG_EINVAL);
	}
	nni_aio_set_input(aio, index, arg);
	return (0);
}
int
nng_aio_set_output(nng_aio *aio, unsigned index, void *arg)
{
	if (index > 3) {
		return (NNG_EINVAL);
	}
	nni_aio_set_output(aio, index, arg);
	return (0);
}

void *
nng_aio_get_input(nng_aio *aio, unsigned index)
{
	return (nni_aio_get_input(aio, index));
}

void *
nng_aio_get_output(nng_aio *aio, unsigned index)
{
	return (nni_aio_get_output(aio, index));
}

void *
nng_aio_get_prov_extra(nng_aio *aio, unsigned index)
{
	if (index < 2) {
		return nni_aio_get_prov_extra(aio, index);
	} else {
		return NULL;
	}
}

void
nng_aio_set_prov_extra(nng_aio *aio, unsigned index, void *data)
{
	if (index < 2) {
		nni_aio_set_prov_extra(aio, index, data);
	}
}

void
nng_aio_finish(nng_aio *aio, int rv)
{
	// Preserve the count.
	nni_aio_finish(aio, rv, nni_aio_count(aio));
}

void
nng_aio_defer(nng_aio *aio, nng_aio_cancelfn fn, void *arg)
{
	nni_aio_schedule(aio, fn, arg);
}

bool
nng_aio_begin(nng_aio *aio)
{
	if (nni_aio_begin(aio) != 0) {
		return (false);
	}
	return (true);
}

int
nng_url_parse(nng_url **result, const char *ustr)
{
	return (nni_url_parse(result, ustr));
}

void
nng_url_free(nng_url *url)
{
	nni_url_free(url);
}

int
nng_url_clone(nng_url **dstp, const nng_url *src)
{
	return (nni_url_clone(dstp, src));
}

#define xstr(a) str(a)
#define str(a) #a

const char *
nng_version(void)
{
	return (xstr(NNG_MAJOR_VERSION) "." xstr(NNG_MINOR_VERSION) "." xstr(
	    NNG_PATCH_VERSION) NNG_RELEASE_SUFFIX);
}

// NANOMQ MQTT APIs
/**
 * @brief CMD specifically for app layer acting
 *
 *
 * @param msg
 * @return int
 */
uint8_t
nng_msg_cmd_type(nng_msg *msg)
{
	return (nni_msg_cmd_type(msg));
}

/**
 * @brief get MQTT packet Type from msg header
 * 
 * @param m 
 * @return uint8_t 
 */
uint8_t
nng_msg_get_type(nng_msg *msg)
{
	return nni_msg_get_type(msg);
}

size_t
nng_msg_remaining_len(nng_msg *msg)
{
	return (nni_msg_remaining_len(msg));
}

uint8_t *
nng_msg_header_ptr(nng_msg *msg)
{
	return (nni_msg_header_ptr(msg));
}

uint8_t *
nng_msg_payload_ptr(nng_msg *msg)
{
	return (nni_msg_payload_ptr(msg));
}

void
nng_msg_set_payload_ptr(nng_msg *msg, uint8_t *ptr)
{
	nni_msg_set_payload_ptr(msg, ptr);
}

void
nng_msg_set_remaining_len(nng_msg *msg, size_t len)
{
	nni_msg_set_remaining_len(msg, len);
}

void
nng_msg_clone(nng_msg *msg)
{
	nni_msg_clone(msg);
}

nng_msg *
nng_msg_unique(nng_msg *m)
{
	nng_msg *m2;
	m2 = nni_msg_unique(m);
	return m2;
}

void *
nng_msg_get_conn_param(nng_msg *msg)
{
	return nni_msg_get_conn_param(msg);
}

void
nng_msg_set_cmd_type(nng_msg *m, uint8_t cmd)
{
	nni_msg_set_cmd_type(m, cmd);
}

const uint8_t *
conn_param_get_clientid(conn_param *cparam)
{
	return (const uint8_t *) cparam->clientid.body;
}

const uint8_t *
conn_param_get_pro_name(conn_param *cparam)
{
	return (const uint8_t *) cparam->pro_name.body;
}

const void *
conn_param_get_will_topic(conn_param *cparam)
{
	if (cparam->will_flag) {
		return (void *) &(cparam->will_topic);
	} else {
		return NULL;
	}
}

const void *
conn_param_get_will_msg(conn_param *cparam)
{
	if (cparam->will_flag) {
		return (void *) &(cparam->will_msg);
	} else {
		return NULL;
	}
}

const uint8_t *
conn_param_get_username(conn_param *cparam)
{
	if (cparam->con_flag & 0x80) {
		return (const uint8_t *) cparam->username.body;
	} else {
		return NULL;
	}
}

const uint8_t *
conn_param_get_password(conn_param *cparam)
{
	if (cparam->con_flag & 0x40) {
		return cparam->password.body;
	} else {
		return NULL;
	}
}

uint8_t
conn_param_get_con_flag(conn_param *cparam)
{
	return cparam->con_flag;
}

uint8_t
conn_param_get_clean_start(conn_param *cparam)
{
	return cparam->clean_start;
}

uint8_t
conn_param_get_will_flag(conn_param *cparam)
{
	return cparam->will_flag;
}

uint8_t
conn_param_get_will_qos(conn_param *cparam)
{
	return cparam->will_qos;
}

uint8_t
conn_param_get_will_retain(conn_param *cparam)
{
	return cparam->will_retain;
}

uint16_t
conn_param_get_keepalive(conn_param *cparam)
{
	return cparam->keepalive_mqtt;
}

uint8_t
conn_param_get_protover(conn_param *cparam)
{
	return cparam->pro_ver;
}

void *
conn_param_get_qos_db(conn_param *cparam)
{
	return (void *) (cparam->nano_qos_db);
}

void
conn_param_set_qos_db(conn_param *cparam, void *qos)
{
	cparam->nano_qos_db = qos;
}

void
nng_msg_set_timestamp(nni_msg *m, uint64_t time)
{
	nni_msg_set_timestamp(m, (nni_time) time);
}

/*
void
nng_aio_set_pipelength(nng_aio *aio, uint32_t len)
{
    nni_aio_set_pipelength(aio, len);
}

void
nng_aio_set_pipes(nng_aio *aio, uint32_t *pipes)
{
    nni_aio_set_pipes(aio, pipes);
}
*/

void
nng_aio_finish_error(nng_aio *aio, int rv)
{
	nni_aio_finish_error(aio, rv);
}

void
nng_aio_finish_sync(nng_aio *aio, int rv)
{
	nni_aio_finish_sync(aio, rv, 0);
}

int
nng_file_put(const char *name, const void *data, size_t sz)
{
	return nni_file_put(name, data, sz);
}

int
nng_file_get(const char *name, void **datap, size_t *szp)
{
	return nni_file_get(name, datap, szp);
}

int
nng_file_delete(const char *name)
{
	return nni_file_delete(name);
}

void
nng_taskq_setter(int num_taskq_threads, int max_taskq_threads)
{
	nni_taskq_setter(num_taskq_threads, max_taskq_threads);
}

#if defined(NNG_TRANSPORT_MQTT_TCP) || defined(NNG_TRANSPORT_MQTT_TLS)
int
nng_mqtt_msg_proto_data_alloc(nng_msg *msg)
{
	return nni_mqtt_msg_proto_data_alloc(msg);
}

void
nng_mqtt_msg_proto_data_free(nng_msg *msg)
{
	nni_mqtt_msg_proto_data_free(msg);
}

int
nng_mqtt_msg_alloc(nng_msg **msg, size_t sz)
{
	return nni_mqtt_msg_alloc(msg, sz);
}

int
nng_mqtt_msg_encode(nng_msg *msg)
{
	return nni_mqtt_msg_encode(msg);
}

int
nng_mqtt_msg_decode(nng_msg *msg)
{
	return nni_mqtt_msg_decode(msg);
}

void
nng_mqtt_msg_set_packet_type(nng_msg *msg, nng_mqtt_packet_type packet_type)
{
	nni_mqtt_msg_set_packet_type(msg, (nni_mqtt_packet_type) packet_type);
}

nng_mqtt_packet_type
nng_mqtt_msg_get_packet_type(nng_msg *msg)
{
	return (nng_mqtt_packet_type) nni_mqtt_msg_get_packet_type(msg);
}

void
nng_mqtt_msg_set_connect_clean_session(nng_msg *msg, bool clean_session)
{
	nni_mqtt_msg_set_connect_clean_session(msg, clean_session);
}

void
nng_mqtt_msg_set_connect_will_retain(nng_msg *msg, bool will_retain)
{
	nni_mqtt_msg_set_connect_will_retain(msg, will_retain);
}

bool
nng_mqtt_msg_get_connect_clean_session(nng_msg *msg)
{
	return nni_mqtt_msg_get_connect_clean_session(msg);
}

bool
nng_mqtt_msg_get_connect_will_retain(nng_msg *msg)
{
	return nni_mqtt_msg_get_connect_will_retain(msg);
}

void
nng_mqtt_msg_set_connect_proto_version(nng_msg *msg, uint8_t proto_version)
{
	nni_mqtt_msg_set_connect_proto_version(msg, proto_version);
}

void
nng_mqtt_msg_set_connect_keep_alive(nng_msg *msg, uint16_t keep_alive)
{
	nni_mqtt_msg_set_connect_keep_alive(msg, keep_alive);
}

void
nng_mqtt_msg_set_connect_client_id(nng_msg *msg, const char *client_id)
{
	nni_mqtt_msg_set_connect_client_id(msg, client_id);
}

void
nng_mqtt_msg_set_connect_will_topic(nng_msg *msg, const char *will_topic)
{
	nni_mqtt_msg_set_connect_will_topic(msg, will_topic);
}

void
nng_mqtt_msg_set_connect_will_msg(nng_msg *msg, const char *will_msg)
{
	nni_mqtt_msg_set_connect_will_msg(msg, will_msg);
}

void
nng_mqtt_msg_set_connect_user_name(nng_msg *msg, const char *user_name)
{
	nni_mqtt_msg_set_connect_user_name(msg, user_name);
}
void
nng_mqtt_msg_set_connect_password(nng_msg *msg, const char *password)
{
	nni_mqtt_msg_set_connect_password(msg, password);
}

uint8_t
nng_mqtt_msg_get_connect_proto_version(nng_msg *msg)
{
	return nni_mqtt_msg_get_connect_proto_version(msg);
}

uint16_t
nng_mqtt_msg_get_connect_keep_alive(nng_msg *msg)
{
	return nni_mqtt_msg_get_connect_keep_alive(msg);
}

const char *
nng_mqtt_msg_get_connect_client_id(nng_msg *msg)
{
	return nni_mqtt_msg_get_connect_client_id(msg);
}

const char *
nng_mqtt_msg_get_connect_will_topic(nng_msg *msg)
{
	return nni_mqtt_msg_get_connect_will_topic(msg);
}

const char *
nng_mqtt_msg_get_connect_will_msg(nng_msg *msg)
{
	return nni_mqtt_msg_get_connect_will_msg(msg);
}

const char *
nng_mqtt_msg_get_connect_user_name(nng_msg *msg)
{
	return nni_mqtt_msg_get_connect_user_name(msg);
}

const char *
nng_mqtt_msg_get_connect_password(nng_msg *msg)
{
	return nni_mqtt_msg_get_connect_password(msg);
}

void
nng_mqtt_msg_set_connack_return_code(nng_msg *msg, uint8_t return_code)
{
	nni_mqtt_msg_set_connack_return_code(msg, return_code);
}

void
nng_mqtt_msg_set_connack_flags(nng_msg *msg, uint8_t flags)
{
	nni_mqtt_msg_set_connack_flags(msg, flags);
}

uint8_t
nng_mqtt_msg_get_connack_return_code(nng_msg *msg)
{
	return nni_mqtt_msg_get_connack_return_code(msg);
}

uint8_t
nng_mqtt_msg_get_connack_flags(nng_msg *msg)
{
	return nni_mqtt_msg_get_connack_flags(msg);
}

void
nng_mqtt_msg_set_publish_qos(nng_msg *msg, uint8_t qos)
{
	nni_mqtt_msg_set_publish_qos(msg, qos);
}

uint8_t
nng_mqtt_msg_get_publish_qos(nng_msg *msg)
{
	return nni_mqtt_msg_get_publish_qos(msg);
}

void
nng_mqtt_msg_set_publish_retain(nng_msg *msg, bool retain)
{
	nni_mqtt_msg_set_publish_retain(msg, retain);
}

bool
nng_mqtt_msg_get_publish_retain(nng_msg *msg)
{
	return nni_mqtt_msg_get_publish_retain(msg);
}

void
nng_mqtt_msg_set_publish_dup(nng_msg *msg, bool dup)
{
	nni_mqtt_msg_set_publish_dup(msg, dup);
}

bool
nng_mqtt_msg_get_publish_dup(nng_msg *msg)
{
	return nni_mqtt_msg_get_publish_dup(msg);
}

void
nng_mqtt_msg_set_publish_topic(nng_msg *msg, const char *topic)
{
	nni_mqtt_msg_set_publish_topic(msg, topic);
}

const char *
nng_mqtt_msg_get_publish_topic(nng_msg *msg, uint32_t *topic_len)
{
	return nni_mqtt_msg_get_publish_topic(msg, topic_len);
}

void
nng_mqtt_msg_set_publish_packet_id(nng_msg *msg, uint16_t packet_id)
{
	nni_mqtt_msg_set_publish_packet_id(msg, packet_id);
}

uint16_t
nng_mqtt_msg_get_publish_packet_id(nng_msg *msg)
{
	return nni_mqtt_msg_get_publish_packet_id(msg);
}

void
nng_mqtt_msg_set_publish_payload(nng_msg *msg, uint8_t *payload, uint32_t len)
{
	nni_mqtt_msg_set_publish_payload(msg, payload, len);
}

uint8_t *
nng_mqtt_msg_get_publish_payload(nng_msg *msg, uint32_t *len)
{
	return nni_mqtt_msg_get_publish_payload(msg, len);
}

uint16_t
nng_mqtt_msg_get_puback_packet_id(nng_msg *msg)
{
	return nni_mqtt_msg_get_puback_packet_id(msg);
}

void
nng_mqtt_msg_set_puback_packet_id(nng_msg *msg, uint16_t packet_id)
{
	nni_mqtt_msg_set_puback_packet_id(msg, packet_id);
}

uint16_t
nng_mqtt_msg_get_pubrec_packet_id(nng_msg *msg)
{
	return nni_mqtt_msg_get_pubrec_packet_id(msg);
}

void
nng_mqtt_msg_set_pubrec_packet_id(nng_msg *msg, uint16_t packet_id)
{
	nni_mqtt_msg_set_pubrec_packet_id(msg, packet_id);
}

uint16_t
nng_mqtt_msg_get_pubrel_packet_id(nng_msg *msg)
{
	return nni_mqtt_msg_get_pubrel_packet_id(msg);
}

void
nng_mqtt_msg_set_pubrel_packet_id(nng_msg *msg, uint16_t packet_id)
{
	nni_mqtt_msg_set_pubrel_packet_id(msg, packet_id);
}

uint16_t
nng_mqtt_msg_get_pubcomp_packet_id(nng_msg *msg)
{
	return nni_mqtt_msg_get_pubcomp_packet_id(msg);
}

void
nng_mqtt_msg_set_pubcomp_packet_id(nng_msg *msg, uint16_t packet_id)
{
	nni_mqtt_msg_set_pubcomp_packet_id(msg, packet_id);
}

uint16_t
nng_mqtt_msg_get_subscribe_packet_id(nng_msg *msg)
{
	return nni_mqtt_msg_get_subscribe_packet_id(msg);
}

void
nng_mqtt_msg_set_subscribe_packet_id(nng_msg *msg, uint16_t packet_id)
{
	nni_mqtt_msg_set_subscribe_packet_id(msg, packet_id);
}

void
nng_mqtt_msg_set_subscribe_topics(
    nng_msg *msg, nng_mqtt_topic_qos *topics, uint32_t topics_count)
{
	nni_mqtt_msg_set_subscribe_topics(
	    msg, (nni_mqtt_topic_qos *) topics, topics_count);
}

nng_mqtt_topic_qos *
nng_mqtt_msg_get_subscribe_topics(nng_msg *msg, uint32_t *topics_count)
{
	return nni_mqtt_msg_get_subscribe_topics(msg, topics_count);
}

uint16_t
nng_mqtt_msg_get_suback_packet_id(nng_msg *msg)
{
	return nni_mqtt_msg_get_suback_packet_id(msg);
}

void
nng_mqtt_msg_set_suback_packet_id(nng_msg *msg, uint16_t packet_id)
{
	nni_mqtt_msg_set_suback_packet_id(msg, packet_id);
}
void
nng_mqtt_msg_set_suback_return_codes(
    nng_msg *msg, uint8_t *return_codes, uint32_t return_codes_count)
{
	nni_mqtt_msg_set_suback_return_codes(
	    msg, return_codes, return_codes_count);
}
uint8_t *
nng_mqtt_msg_get_suback_return_codes(
    nng_msg *msg, uint32_t *return_codes_counts)
{
	return nni_mqtt_msg_get_suback_return_codes(msg, return_codes_counts);
}

uint16_t
nng_mqtt_msg_get_unsubscribe_packet_id(nng_msg *msg)
{
	return nni_mqtt_msg_get_unsubscribe_packet_id(msg);
}

void
nng_mqtt_msg_set_unsubscribe_packet_id(nng_msg *msg, uint16_t packet_id)
{

	nni_mqtt_msg_set_unsubscribe_packet_id(msg, packet_id);
}

void
nng_mqtt_msg_set_unsubscribe_topics(
    nng_msg *msg, nng_mqtt_topic *topics, uint32_t topics_count)
{
	nni_mqtt_msg_set_unsubscribe_topics(
	    msg, (nni_mqtt_topic *) topics, topics_count);
}

nng_mqtt_topic *
nng_mqtt_msg_get_unsubscribe_topics(nng_msg *msg, uint32_t *topics_count)
{
	return nni_mqtt_msg_get_unsubscribe_topics(msg, topics_count);
}

void
nng_mqtt_msg_set_unsuback_packet_id(nng_msg *msg, uint16_t packet_id)
{
	nni_mqtt_msg_set_unsuback_packet_id(msg, packet_id);
}

uint16_t
nng_mqtt_msg_get_unsuback_packet_id(nng_msg *msg)
{
	return nni_mqtt_msg_get_unsuback_packet_id(msg);
}

void
nng_mqtt_msg_set_conn_param(nng_msg *msg)
{
	nni_mqtt_msg_set_conn_param(msg);
}

conn_param *
nng_mqtt_msg_get_conn_param(nng_msg *msg)
{
	return nni_mqtt_msg_get_conn_param(msg);
}

nng_mqtt_topic *
nng_mqtt_topic_array_create(size_t n)
{
	return nni_mqtt_topic_array_create(n);
}

void
nng_mqtt_topic_array_set(
    nng_mqtt_topic *topic, size_t n, const char *topic_name)
{
	nni_mqtt_topic_array_set(topic, n, topic_name);
}

void
nng_mqtt_topic_array_free(nng_mqtt_topic *topic, size_t n)
{
	nni_mqtt_topic_array_free(topic, n);
}

nng_mqtt_topic_qos *
nng_mqtt_topic_qos_array_create(size_t n)
{
	return nni_mqtt_topic_qos_array_create(n);
}

void
nng_mqtt_topic_qos_array_set(nng_mqtt_topic_qos *topic_qos, size_t index,
    const char *topic_name, uint8_t qos)
{
	nni_mqtt_topic_qos_array_set(topic_qos, index, topic_name, qos);
}

void
nng_mqtt_topic_qos_array_free(nng_mqtt_topic_qos *topic_qos, size_t n)
{
	nni_mqtt_topic_qos_array_free(topic_qos, n);
}

void
nng_mqtt_msg_dump(
    nng_msg *msg, uint8_t *buffer, uint32_t len, bool print_bytes)
{
	nni_mqtt_msg_dump(msg, buffer, len, print_bytes);
}

#endif // NNG_TRANSPORT_MQTT_TCP
