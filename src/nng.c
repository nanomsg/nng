//
// Copyright 2024 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "nng/nng.h"
#include "core/nng_impl.h"
#include "core/platform.h"
#include "core/socket.h"

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

	if ((rv = nni_ctx_find(&ctx, c.id)) != 0) {
		return (rv);
	}
	nni_ctx_close(ctx);
	nni_ctx_rele(ctx);
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
	int      rv;
	nni_aio  aio;
	nni_ctx *ctx;

	if ((rv = nni_ctx_find(&ctx, cid.id)) != 0) {
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

	if ((rv = nni_ctx_find(&ctx, cid.id)) != 0) {
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
	if ((rv = nni_ctx_find(&ctx, cid.id)) != 0) {
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
	int      rv;
	nni_aio  aio;
	nni_ctx *ctx;

	if (msg == NULL) {
		return (NNG_EINVAL);
	}
	if ((rv = nni_ctx_find(&ctx, cid.id)) != 0) {
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

	if ((rv = nni_ctx_find(&ctx, id.id)) != 0) {
		return (rv);
	}
	rv = nni_ctx_getopt(ctx, n, v, szp, t);
	nni_ctx_rele(ctx);
	return (rv);
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
nng_ctx_get_ms(nng_ctx id, const char *n, nng_duration *v)
{
	return (ctx_get(id, n, v, NULL, NNI_TYPE_DURATION));
}

static int
ctx_set(nng_ctx id, const char *n, const void *v, size_t sz, nni_type t)
{
	nni_ctx *ctx;
	int      rv;

	if ((rv = nni_ctx_find(&ctx, id.id)) != 0) {
		return (rv);
	}
	rv = nni_ctx_setopt(ctx, n, v, sz, t);
	nni_ctx_rele(ctx);
	return (rv);
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
		nni_dialer_rele(d);
		nni_sock_rele(s);
		return (rv);
	}
	if (dp != NULL) {
		nng_dialer did;
		did.id = nni_dialer_id(d);
		*dp    = did;
	}
	nni_dialer_rele(d);
	nni_sock_rele(s);
	return (0);
}

int
nng_dial_url(nng_socket sid, const nng_url *url, nng_dialer *dp, int flags)
{
	nni_dialer *d;
	int         rv;
	nni_sock   *s;

	if ((rv = nni_sock_find(&s, sid.id)) != 0) {
		return (rv);
	}
	if ((rv = nni_dialer_create_url(&d, s, url)) != 0) {
		nni_sock_rele(s);
		return (rv);
	}
	if ((rv = nni_dialer_start(d, flags)) != 0) {
		nni_dialer_close(d);
		nni_dialer_rele(d);
		nni_sock_rele(s);
		return (rv);
	}
	if (dp != NULL) {
		nng_dialer did;
		did.id = nni_dialer_id(d);
		*dp    = did;
	}
	nni_dialer_rele(d);
	nni_sock_rele(s);
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
		nni_listener_rele(l);
		nni_sock_rele(s);
		return (rv);
	}

	if (lp != NULL) {
		nng_listener lid;
		lid.id = nni_listener_id(l);
		*lp    = lid;
	}
	nni_listener_rele(l);
	nni_sock_rele(s);
	return (rv);
}

int
nng_listen_url(nng_socket sid, const nng_url *url, nng_listener *lp, int flags)
{
	int           rv;
	nni_sock     *s;
	nni_listener *l;

	if ((rv = nni_sock_find(&s, sid.id)) != 0) {
		return (rv);
	}
	if ((rv = nni_listener_create_url(&l, s, url)) != 0) {
		nni_sock_rele(s);
		return (rv);
	}
	if ((rv = nni_listener_start(l, flags)) != 0) {
		nni_listener_close(l);
		nni_listener_rele(l);
		nni_sock_rele(s);
		return (rv);
	}

	if (lp != NULL) {
		nng_listener lid;
		lid.id = nni_listener_id(l);
		*lp    = lid;
	}
	nni_listener_rele(l);
	nni_sock_rele(s);
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
	nni_sock_rele(s);
	return (0);
}

int
nng_listener_create_url(nng_listener *lp, nng_socket sid, const nng_url *url)
{
	nni_sock     *s;
	int           rv;
	nni_listener *l;
	nng_listener  lid;

	if ((rv = nni_sock_find(&s, sid.id)) != 0) {
		return (rv);
	}
	if ((rv = nni_listener_create_url(&l, s, url)) != 0) {
		nni_sock_rele(s);
		return (rv);
	}
	lid.id = nni_listener_id(l);
	*lp    = lid;
	nni_listener_rele(l);
	nni_sock_rele(s);
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
	nni_sock_rele(s);
	return (0);
}

int
nng_dialer_create_url(nng_dialer *dp, nng_socket sid, const nng_url *url)
{
	nni_sock   *s;
	nni_dialer *d;
	int         rv;
	nng_dialer  did;

	if ((rv = nni_sock_find(&s, sid.id)) != 0) {
		return (rv);
	}
	if ((rv = nni_dialer_create_url(&d, s, url)) != 0) {
		nni_sock_rele(s);
		return (rv);
	}
	did.id = nni_dialer_id(d);
	*dp    = did;
	nni_dialer_rele(d);
	nni_sock_rele(s);
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

	if ((rv = nni_dialer_find(&d, id.id)) != 0) {
		return (rv);
	}
	rv = nni_dialer_setopt(d, n, v, sz, t);
	nni_dialer_rele(d);
	return (rv);
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

	if ((rv = nni_dialer_find(&d, id.id)) != 0) {
		return (rv);
	}
	rv = nni_dialer_getopt(d, n, v, szp, t);
	nni_dialer_rele(d);
	return (rv);
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
nng_dialer_get_ms(nng_dialer id, const char *n, nng_duration *v)
{
	return (dialer_get(id, n, v, NULL, NNI_TYPE_DURATION));
}

int
nng_dialer_get_addr(nng_dialer id, const char *n, nng_sockaddr *v)
{
	return (dialer_get(id, n, v, NULL, NNI_TYPE_SOCKADDR));
}

int
nng_dialer_get_tls(nng_dialer id, nng_tls_config **cfgp)
{
	int         rv;
	nni_dialer *d;
	if ((rv = nni_dialer_find(&d, id.id)) != 0) {
		return (rv);
	}
	rv = nni_dialer_get_tls(d, cfgp);
	nni_dialer_rele(d);
	return (rv);
}

int
nng_dialer_set_tls(nng_dialer id, nng_tls_config *cfg)
{
	int         rv;
	nni_dialer *d;
	if ((rv = nni_dialer_find(&d, id.id)) != 0) {
		return (rv);
	}
	rv = nni_dialer_set_tls(d, cfg);
	nni_dialer_rele(d);
	return (rv);
}

static int
listener_set(
    nng_listener lid, const char *name, const void *v, size_t sz, nni_type t)
{
	nni_listener *l;
	int           rv;

	if ((rv = nni_listener_find(&l, lid.id)) != 0) {
		return (rv);
	}
	rv = nni_listener_setopt(l, name, v, sz, t);
	nni_listener_rele(l);
	return (rv);
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

	if ((rv = nni_listener_find(&l, lid.id)) != 0) {
		return (rv);
	}
	rv = nni_listener_getopt(l, name, v, szp, t);
	nni_listener_rele(l);
	return (rv);
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
nng_listener_get_tls(nng_listener id, nng_tls_config **cfgp)
{
	int           rv;
	nni_listener *l;
	if ((rv = nni_listener_find(&l, id.id)) != 0) {
		return (rv);
	}
	rv = nni_listener_get_tls(l, cfgp);
	nni_listener_rele(l);
	return (rv);
}

int
nng_listener_set_tls(nng_listener id, nng_tls_config *cfg)
{
	int           rv;
	nni_listener *l;
	if ((rv = nni_listener_find(&l, id.id)) != 0) {
		return (rv);
	}
	rv = nni_listener_set_tls(l, cfg);
	nni_listener_rele(l);
	return (rv);
}

int
nng_listener_set_security_descriptor(nng_listener id, void *cfg)
{
	int           rv;
	nni_listener *l;
	if ((rv = nni_listener_find(&l, id.id)) != 0) {
		return (rv);
	}
	rv = nni_listener_set_security_descriptor(l, cfg);
	nni_listener_rele(l);
	return (rv);
}

int
nng_dialer_get_url(nng_dialer id, const nng_url **urlp)
{
	int         rv;
	nni_dialer *d;
	if ((rv = nni_dialer_find(&d, id.id)) != 0) {
		return (rv);
	}
	*urlp = nni_dialer_url(d);
	nni_dialer_rele(d);
	return (0);
}

int
nng_listener_get_url(nng_listener id, const nng_url **urlp)
{
	int           rv;
	nni_listener *l;
	if ((rv = nni_listener_find(&l, id.id)) != 0) {
		return (rv);
	}
	*urlp = nni_listener_url(l);
	nni_listener_rele(l);
	return (0);
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
	nni_dialer_rele(d);
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

	if ((rv = nni_sock_find(&sock, s.id)) != 0) {
		return (rv);
	}
	rv = nni_sock_setopt(sock, name, val, sz, t);
	nni_sock_rele(sock);
	return (rv);
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

static int
socket_get(nng_socket s, const char *name, void *val, size_t *szp, nni_type t)
{
	nni_sock *sock;
	int       rv;

	if ((rv = nni_sock_find(&sock, s.id)) != 0) {
		return (rv);
	}
	rv = nni_sock_getopt(sock, name, val, szp, t);
	nni_sock_rele(sock);
	return (rv);
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
nng_socket_get_ms(nng_socket id, const char *n, nng_duration *v)
{
	return (socket_get(id, n, v, NULL, NNI_TYPE_DURATION));
}

int
nng_socket_get_recv_poll_fd(nng_socket id, int *fdp)
{
	int       rv;
	nni_sock *sock;

	if ((rv = nni_sock_find(&sock, id.id)) != 0) {
		return (rv);
	}

	rv = nni_sock_get_recv_fd(sock, fdp);
	nni_sock_rele(sock);
	return (rv);
}

int
nng_socket_get_send_poll_fd(nng_socket id, int *fdp)
{
	int       rv;
	nni_sock *sock;

	if ((rv = nni_sock_find(&sock, id.id)) != 0) {
		return (rv);
	}

	rv = nni_sock_get_send_fd(sock, fdp);
	nni_sock_rele(sock);
	return (rv);
}

int
nng_socket_proto_id(nng_socket id, uint16_t *idp)
{
	int       rv;
	nni_sock *sock;

	if ((rv = nni_sock_find(&sock, id.id)) != 0) {
		return (rv);
	}

	*idp = nni_sock_proto_id(sock);
	nni_sock_rele(sock);
	return (0);
}

int
nng_socket_peer_id(nng_socket id, uint16_t *idp)
{
	int       rv;
	nni_sock *sock;

	if ((rv = nni_sock_find(&sock, id.id)) != 0) {
		return (rv);
	}

	*idp = nni_sock_peer_id(sock);
	nni_sock_rele(sock);
	return (0);
}

int
nng_socket_proto_name(nng_socket id, const char **name)
{
	int       rv;
	nni_sock *sock;

	if ((rv = nni_sock_find(&sock, id.id)) != 0) {
		return (rv);
	}

	*name = nni_sock_proto_name(sock);
	nni_sock_rele(sock);
	return (0);
}

int
nng_socket_peer_name(nng_socket id, const char **name)
{
	int       rv;
	nni_sock *sock;

	if ((rv = nni_sock_find(&sock, id.id)) != 0) {
		return (rv);
	}

	*name = nni_sock_peer_name(sock);
	nni_sock_rele(sock);
	return (0);
}

int
nng_socket_raw(nng_socket id, bool *rawp)
{
	int       rv;
	nni_sock *sock;

	if ((rv = nni_sock_find(&sock, id.id)) != 0) {
		return (rv);
	}
	*rawp = nni_sock_raw(sock);
	nni_sock_rele(sock);
	return (0);
}

int
nng_pipe_notify(nng_socket s, nng_pipe_ev ev, nng_pipe_cb cb, void *arg)
{
	int       rv;
	nni_sock *sock;

	if ((rv = nni_sock_find(&sock, s.id)) != 0) {
		return (rv);
	}

	nni_sock_set_pipe_cb(sock, ev, cb, arg);
	nni_sock_rele(sock);
	return (0);
}

void
nng_device_aio(nng_aio *aio, nng_socket s1, nng_socket s2)
{
	int       rv;
	nni_sock *sock1 = NULL;
	nni_sock *sock2 = NULL;

	if ((s1.id > 0) && (s1.id != (uint32_t) -1)) {
		if ((rv = nni_sock_find(&sock1, s1.id)) != 0) {
			if (nni_aio_begin(aio) == 0) {
				nni_aio_finish_error(aio, rv);
			}
			return;
		}
	}
	if (((s2.id > 0) && (s2.id != (uint32_t) -1)) && (s2.id != s1.id)) {
		if ((rv = nni_sock_find(&sock2, s2.id)) != 0) {
			nni_sock_rele(sock1);
			if (nni_aio_begin(aio) == 0) {
				nni_aio_finish_error(aio, rv);
			}
			return;
		}
	}

	nni_device(aio, sock1, sock2);
	if (sock1 != NULL) {
		nni_sock_rele(sock1);
	}
	if (sock2 != NULL) {
		nni_sock_rele(sock2);
	}
}

int
nng_device(nng_socket s1, nng_socket s2)
{
	nni_aio aio;
	int     rv;
	nni_aio_init(&aio, NULL, NULL);
	nng_device_aio(&aio, s1, s2);
	nni_aio_wait(&aio);
	rv = nni_aio_result(&aio);
	nni_aio_fini(&aio);
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

	if ((rv = nni_pipe_find(&pipe, p.id)) != 0) {
		return (rv);
	}
	rv = nni_pipe_getopt(pipe, name, val, szp, t);
	nni_pipe_rele(pipe);
	return (rv);
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

	if (nni_pipe_find(&pipe, p.id) == 0) {
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
	if (nni_pipe_find(&pipe, p.id) == 0) {
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
	if (nni_pipe_find(&pipe, p.id) == 0) {
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

bool
nng_aio_busy(nng_aio *aio)
{
	return (nni_aio_busy(aio));
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

void
nng_aio_set_expire(nng_aio *aio, nng_time when)
{
	nni_aio_set_expire(aio, when);
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

#define xstr(a) str(a)
#define str(a) #a

const char *
nng_version(void)
{
	return (xstr(NNG_MAJOR_VERSION) "." xstr(NNG_MINOR_VERSION) "." xstr(
	    NNG_PATCH_VERSION) NNG_RELEASE_SUFFIX);
}

nng_time
nng_clock(void)
{
	return (nni_clock());
}

// Sleep for specified msecs.
void
nng_msleep(nng_duration dur)
{
	nni_msleep(dur);
}

// Create and start a thread.  Note that on some platforms, this might
// actually be a coroutine, with limitations about what system APIs
// you can call.  Therefore, these threads should only be used with the
// I/O APIs provided by nng.  The thread runs until completion.
int
nng_thread_create(nng_thread **thrp, void (*func)(void *), void *arg)
{
	nni_thr *thr;
	int      rv;

	if ((thr = NNI_ALLOC_STRUCT(thr)) == NULL) {
		return (NNG_ENOMEM);
	}
	*thrp = (void *) thr;
	if ((rv = nni_thr_init(thr, func, arg)) != 0) {
		return (rv);
	}
	nni_thr_run(thr);
	return (0);
}

void
nng_thread_set_name(nng_thread *thr, const char *name)
{
	nni_thr_set_name((void *) thr, name);
}

// Destroy a thread (waiting for it to complete.)  When this function
// returns all resources for the thread are cleaned up.
void
nng_thread_destroy(nng_thread *thr)
{
	nni_thr *t = (void *) thr;
	nni_thr_fini(t);
	NNI_FREE_STRUCT(t);
}

struct nng_mtx {
	nni_mtx m;
};

int
nng_mtx_alloc(nng_mtx **mpp)
{
	nng_mtx *mp;

	if ((mp = NNI_ALLOC_STRUCT(mp)) == NULL) {
		return (NNG_ENOMEM);
	}
	nni_mtx_init(&mp->m);
	*mpp = mp;
	return (0);
}

void
nng_mtx_free(nng_mtx *mp)
{
	if (mp != NULL) {
		nni_mtx_fini(&mp->m);
		NNI_FREE_STRUCT(mp);
	}
}

void
nng_mtx_lock(nng_mtx *mp)
{
	nni_mtx_lock(&mp->m);
}

void
nng_mtx_unlock(nng_mtx *mp)
{
	nni_mtx_unlock(&mp->m);
}

struct nng_cv {
	nni_cv c;
};

int
nng_cv_alloc(nng_cv **cvp, nng_mtx *mx)
{
	nng_cv *cv;

	if ((cv = NNI_ALLOC_STRUCT(cv)) == NULL) {
		return (NNG_ENOMEM);
	}
	nni_cv_init(&cv->c, &mx->m);
	*cvp = cv;
	return (0);
}

void
nng_cv_free(nng_cv *cv)
{
	if (cv != NULL) {
		nni_cv_fini(&cv->c);
		NNI_FREE_STRUCT(cv);
	}
}

void
nng_cv_wait(nng_cv *cv)
{
	nni_cv_wait(&cv->c);
}

int
nng_cv_until(nng_cv *cv, nng_time when)
{
	return (nni_cv_until(&cv->c, (nni_time) when));
}

void
nng_cv_wake(nng_cv *cv)
{
	nni_cv_wake(&cv->c);
}

void
nng_cv_wake1(nng_cv *cv)
{
	nni_cv_wake1(&cv->c);
}

uint32_t
nng_random(void)
{
	return (nni_random());
}

int
nng_socket_pair(int fds[2])
{
	return (nni_socket_pair(fds));
}

int
nng_udp_open(nng_udp **udp, nng_sockaddr *sa)
{
	return (nni_plat_udp_open((nni_plat_udp **) udp, sa));
}

void
nng_udp_close(nng_udp *udp)
{
	nni_plat_udp_close((nni_plat_udp *) udp);
}

int
nng_udp_sockname(nng_udp *udp, nng_sockaddr *sa)
{
	return (nni_plat_udp_sockname((nni_plat_udp *) udp, sa));
}

void
nng_udp_send(nng_udp *udp, nng_aio *aio)
{
	nni_plat_udp_send((nni_plat_udp *) udp, aio);
}

void
nng_udp_recv(nng_udp *udp, nng_aio *aio)
{
	nni_plat_udp_recv((nni_plat_udp *) udp, aio);
}

int
nng_udp_multicast_membership(nng_udp *udp, nng_sockaddr *sa, bool join)
{
	return (
	    nni_plat_udp_multicast_membership((nni_plat_udp *) udp, sa, join));
}
