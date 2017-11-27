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
nng_close(nng_socket sid)
{
	int       rv;
	nni_sock *sock;

	// Close is special, because we still want to be able to get
	// a hold on the socket even if shutdown was called.
	if ((rv = nni_sock_find(&sock, sid)) != 0) {
		return (rv);
	}
	// No release -- close releases it.
	nni_sock_close(sock);
	return (rv);
}

void
nng_closeall(void)
{
	nni_sock_closeall();
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

int
nng_recv(nng_socket sid, void *buf, size_t *szp, int flags)
{
	nng_msg *msg;
	int      rv;

	// Note that while it would be nice to make this a zero copy operation,
	// its not normally possible if a size was specified.
	if ((rv = nng_recvmsg(sid, &msg, flags & ~(NNG_FLAG_ALLOC))) != 0) {
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

		if ((nbuf = nni_alloc(nng_msg_len(msg))) == NULL) {
			nng_msg_free(msg);
			return (NNG_ENOMEM);
		}

		*(void **) buf = nbuf;
		memcpy(nbuf, nni_msg_body(msg), nni_msg_len(msg));
		*szp = nng_msg_len(msg);
	}
	nni_msg_free(msg);
	return (0);
}

int
nng_recvmsg(nng_socket sid, nng_msg **msgp, int flags)
{
	int      rv;
	nng_aio *ap;

	if ((rv = nng_aio_alloc(&ap, NULL, NULL)) != 0) {
		return (rv);
	}
	if (flags & NNG_FLAG_NONBLOCK) {
		nng_aio_set_timeout(ap, NNG_DURATION_ZERO);
	} else {
		nng_aio_set_timeout(ap, NNG_DURATION_DEFAULT);
	}

	nng_recv_aio(sid, ap);
	nng_aio_wait(ap);

	if ((rv = nng_aio_result(ap)) == 0) {
		*msgp = nng_aio_get_msg(ap);

	} else if ((rv == NNG_ETIMEDOUT) && (flags == NNG_FLAG_NONBLOCK)) {
		rv = NNG_EAGAIN;
	}
	nng_aio_free(ap);

	return (rv);
}

int
nng_send(nng_socket sid, void *buf, size_t len, int flags)
{
	nng_msg *msg;
	int      rv;

	if ((rv = nng_msg_alloc(&msg, len)) != 0) {
		return (rv);
	}
	memcpy(nng_msg_body(msg), buf, len);
	if ((rv = nng_sendmsg(sid, msg, flags)) != 0) {
		nng_msg_free(msg);
	}
	if (flags & NNG_FLAG_ALLOC) {
		nni_free(buf, len);
	}
	return (rv);
}

int
nng_sendmsg(nng_socket sid, nng_msg *msg, int flags)
{
	int      rv;
	nng_aio *ap;

	if ((rv = nng_aio_alloc(&ap, NULL, NULL)) != 0) {
		return (rv);
	}
	if (flags & NNG_FLAG_NONBLOCK) {
		nng_aio_set_timeout(ap, NNG_DURATION_ZERO);
	} else {
		nng_aio_set_timeout(ap, NNG_DURATION_DEFAULT);
	}

	nng_aio_set_msg(ap, msg);
	nng_send_aio(sid, ap);
	nng_aio_wait(ap);

	rv = nng_aio_result(ap);
	nng_aio_free(ap);

	// Possibly massage nonblocking attempt.  Note that nonblocking is
	// still done asynchronously, and the calling thread loses context.
	if ((rv == NNG_ETIMEDOUT) && (flags == NNG_FLAG_NONBLOCK)) {
		rv = NNG_EAGAIN;
	}

	return (rv);
}

void
nng_recv_aio(nng_socket sid, nng_aio *ap)
{
	nni_aio * aio = (nni_aio *) ap;
	nni_sock *sock;
	int       rv;

	if ((rv = nni_sock_find(&sock, sid)) != 0) {
		nni_aio_finish_error(aio, rv);
		return;
	}
	nni_sock_recv(sock, aio);
	nni_sock_rele(sock);
}

void
nng_send_aio(nng_socket sid, nng_aio *ap)
{
	nni_aio * aio = (nni_aio *) ap;
	nni_sock *sock;
	int       rv;

	if ((rv = nni_sock_find(&sock, sid)) != 0) {
		nni_aio_finish_error(aio, rv);
		return;
	}
	nni_sock_send(sock, aio);
	nni_sock_rele(sock);
}

int
nng_dial(nng_socket sid, const char *addr, nng_dialer *dp, int flags)
{
	nni_ep *  ep;
	int       rv;
	nni_sock *sock;

	if ((rv = nni_sock_find(&sock, sid)) != 0) {
		return (rv);
	}
	if ((rv = nni_ep_create_dialer(&ep, sock, addr)) != 0) {
		nni_sock_rele(sock);
		return (rv);
	}
	if ((rv = nni_ep_dial(ep, flags)) != 0) {
		nni_ep_close(ep);
		nni_sock_rele(sock);
		return (rv);
	}
	if (dp != NULL) {
		*dp = nni_ep_id(ep);
	}
	nni_ep_rele(ep);
	nni_sock_rele(sock);
	return (0);
}

int
nng_listen(nng_socket sid, const char *addr, nng_listener *lp, int flags)
{
	nni_ep *  ep;
	int       rv;
	nni_sock *sock;

	if ((rv = nni_sock_find(&sock, sid)) != 0) {
		return (rv);
	}
	if ((rv = nni_ep_create_listener(&ep, sock, addr)) != 0) {
		nni_sock_rele(sock);
		return (rv);
	}
	if ((rv = nni_ep_listen(ep, flags)) != 0) {
		nni_ep_close(ep);
		nni_sock_rele(sock);
		return (rv);
	}

	if (lp != NULL) {
		*lp = nni_ep_id(ep);
	}
	nni_ep_rele(ep);
	nni_sock_rele(sock);
	return (rv);
}

int
nng_listener_create(nng_listener *lp, nng_socket sid, const char *addr)
{
	nni_sock *s;
	nni_ep *  ep;
	int       rv;

	if ((rv = nni_sock_find(&s, sid)) != 0) {
		return (rv);
	}
	if ((rv = nni_ep_create_listener(&ep, s, addr)) != 0) {
		nni_sock_rele(s);
		return (rv);
	}
	*lp = nni_ep_id(ep);
	nni_ep_rele(ep);
	nni_sock_rele(s);
	return (0);
}

int
nng_listener_start(nng_listener id, int flags)
{
	nni_ep *ep;
	int     rv;

	if ((rv = nni_ep_find(&ep, id)) != 0) {
		return (rv);
	}
	rv = nni_ep_listen(ep, flags);
	nni_ep_rele(ep);
	return (rv);
}

int
nng_dialer_create(nng_dialer *dp, nng_socket sid, const char *addr)
{
	nni_sock *s;
	nni_ep *  ep;
	int       rv;

	if ((rv = nni_sock_find(&s, sid)) != 0) {
		return (rv);
	}
	if ((rv = nni_ep_create_dialer(&ep, s, addr)) != 0) {
		nni_sock_rele(s);
		return (rv);
	}
	*dp = nni_ep_id(ep);
	nni_ep_rele(ep);
	nni_sock_rele(s);
	return (0);
}

int
nng_dialer_start(nng_dialer id, int flags)
{
	nni_ep *ep;
	int     rv;

	if ((rv = nni_ep_find(&ep, id)) != 0) {
		return (rv);
	}
	rv = nni_ep_dial(ep, flags);
	nni_ep_rele(ep);
	return (rv);
}

static int
nng_ep_setopt(
    uint32_t id, const char *name, const void *val, size_t sz, int mode)
{
	nni_ep *ep;
	int     rv;

	if ((rv = nni_init()) != 0) {
		return (rv);
	}
	if ((rv = nni_ep_find(&ep, id)) != 0) {
		return (rv);
	}
	if (nni_ep_mode(ep) == mode) {
		rv = nni_ep_setopt(ep, name, val, sz);
	} else {
		rv = NNG_ENOENT;
	}
	nni_ep_rele(ep);
	return (rv);
}

static int
nng_ep_getopt(uint32_t id, const char *name, void *val, size_t *szp, int mode)
{
	nni_ep *ep;
	int     rv;

	if ((rv = nni_init()) != 0) {
		return (rv);
	}
	if ((rv = nni_ep_find(&ep, id)) != 0) {
		return (rv);
	}
	if (nni_ep_mode(ep) == mode) {
		rv = nni_ep_getopt(ep, name, val, szp);
	} else {
		rv = NNG_ENOENT;
	}
	nni_ep_rele(ep);
	return (rv);
}

int
nng_dialer_setopt(nng_dialer id, const char *name, const void *v, size_t sz)
{
	return (nng_ep_setopt(id, name, v, sz, NNI_EP_MODE_DIAL));
}

int
nng_dialer_setopt_int(nng_dialer id, const char *name, int val)
{
	return (nng_dialer_setopt(id, name, &val, sizeof(val)));
}

int
nng_dialer_setopt_size(nng_dialer id, const char *name, size_t val)
{
	return (nng_dialer_setopt(id, name, &val, sizeof(val)));
}

int
nng_dialer_setopt_ms(nng_dialer id, const char *name, nng_duration val)
{
	return (nng_dialer_setopt(id, name, &val, sizeof(val)));
}

int
nng_dialer_setopt_uint64(nng_dialer id, const char *name, uint64_t val)
{
	return (nng_dialer_setopt(id, name, &val, sizeof(val)));
}

int
nng_dialer_getopt(nng_dialer id, const char *name, void *val, size_t *szp)
{
	return (nng_ep_getopt(id, name, val, szp, NNI_EP_MODE_DIAL));
}

int
nng_dialer_getopt_int(nng_dialer id, const char *name, int *valp)
{
	size_t sz = sizeof(*valp);
	return (nng_dialer_getopt(id, name, valp, &sz));
}

int
nng_dialer_getopt_size(nng_dialer id, const char *name, size_t *valp)
{
	size_t sz = sizeof(*valp);
	return (nng_dialer_getopt(id, name, valp, &sz));
}

int
nng_dialer_getopt_uint64(nng_dialer id, const char *name, uint64_t *valp)
{
	size_t sz = sizeof(*valp);
	return (nng_dialer_getopt(id, name, valp, &sz));
}

int
nng_dialer_getopt_ms(nng_dialer id, const char *name, nng_duration *valp)
{
	size_t sz = sizeof(*valp);
	return (nng_dialer_getopt(id, name, valp, &sz));
}

int
nng_listener_setopt(
    nng_listener id, const char *name, const void *v, size_t sz)
{
	return (nng_ep_setopt(id, name, v, sz, NNI_EP_MODE_LISTEN));
}

int
nng_listener_setopt_int(nng_listener id, const char *name, int val)
{
	return (nng_listener_setopt(id, name, &val, sizeof(val)));
}

int
nng_listener_setopt_size(nng_listener id, const char *name, size_t val)
{
	return (nng_listener_setopt(id, name, &val, sizeof(val)));
}

int
nng_listener_setopt_ms(nng_listener id, const char *name, nng_duration val)
{
	return (nng_listener_setopt(id, name, &val, sizeof(val)));
}

int
nng_listener_setopt_uint64(nng_listener id, const char *name, uint64_t val)
{
	return (nng_listener_setopt(id, name, &val, sizeof(val)));
}

int
nng_listener_getopt(nng_listener id, const char *name, void *val, size_t *szp)
{
	return (nng_ep_getopt(id, name, val, szp, NNI_EP_MODE_LISTEN));
}

int
nng_listener_getopt_int(nng_listener id, const char *name, int *valp)
{
	size_t sz = sizeof(*valp);
	return (nng_listener_getopt(id, name, valp, &sz));
}

int
nng_listener_getopt_size(nng_listener id, const char *name, size_t *valp)
{
	size_t sz = sizeof(*valp);
	return (nng_listener_getopt(id, name, valp, &sz));
}

int
nng_listener_getopt_uint64(nng_listener id, const char *name, uint64_t *valp)
{
	size_t sz = sizeof(*valp);
	return (nng_listener_getopt(id, name, valp, &sz));
}

int
nng_listener_getopt_ms(nng_listener id, const char *name, nng_duration *valp)
{
	size_t sz = sizeof(*valp);
	return (nng_listener_getopt(id, name, valp, &sz));
}

static int
nng_ep_close(uint32_t id)
{
	nni_ep *ep;
	int     rv;

	if ((rv = nni_ep_find(&ep, id)) != 0) {
		return (rv);
	}
	nni_ep_close(ep);
	return (0);
}

int
nng_dialer_close(nng_dialer d)
{
	return (nng_ep_close((uint32_t) d));
}

int
nng_listener_close(nng_listener l)
{
	return (nng_ep_close((uint32_t) l));
}

int
nng_setopt(nng_socket sid, const char *name, const void *val, size_t sz)
{
	nni_sock *sock;
	int       rv;

	if ((rv = nni_init()) != 0) {
		return (rv);
	}
	if ((rv = nni_sock_find(&sock, sid)) != 0) {
		return (rv);
	}
	rv = nni_sock_setopt(sock, name, val, sz);
	nni_sock_rele(sock);
	return (rv);
}

int
nng_getopt(nng_socket sid, const char *name, void *val, size_t *szp)
{
	nni_sock *sock;
	int       rv;

	if ((rv = nni_init()) != 0) {
		return (rv);
	}
	if ((rv = nni_sock_find(&sock, sid)) != 0) {
		return (rv);
	}
	rv = nni_sock_getopt(sock, name, val, szp);
	nni_sock_rele(sock);
	return (rv);
}

// Convenience option wrappers.
int
nng_setopt_int(nng_socket sid, const char *name, int val)
{
	return (nng_setopt(sid, name, &val, sizeof(val)));
}

int
nng_setopt_size(nng_socket sid, const char *name, size_t val)
{
	return (nng_setopt(sid, name, &val, sizeof(val)));
}

int
nng_setopt_ms(nng_socket sid, const char *name, nng_duration val)
{
	return (nng_setopt(sid, name, &val, sizeof(val)));
}

int
nng_setopt_uint64(nng_socket sid, const char *name, uint64_t val)
{
	return (nng_setopt(sid, name, &val, sizeof(val)));
}

int
nng_getopt_int(nng_socket sid, const char *name, int *valp)
{
	size_t sz = sizeof(*valp);
	return (nng_getopt(sid, name, valp, &sz));
}

int
nng_getopt_size(nng_socket sid, const char *name, size_t *valp)
{
	size_t sz = sizeof(*valp);
	return (nng_getopt(sid, name, valp, &sz));
}

int
nng_getopt_uint64(nng_socket sid, const char *name, uint64_t *valp)
{
	size_t sz = sizeof(*valp);
	return (nng_getopt(sid, name, valp, &sz));
}

int
nng_getopt_ms(nng_socket sid, const char *name, nng_duration *valp)
{
	size_t sz = sizeof(*valp);
	return (nng_getopt(sid, name, valp, &sz));
}

int
nng_device(nng_socket s1, nng_socket s2)
{
	int       rv;
	nni_sock *sock1 = NULL;
	nni_sock *sock2 = NULL;

	if ((s1 > 0) && (s1 != (nng_socket) -1)) {
		if ((rv = nni_sock_find(&sock1, s1)) != 0) {
			return (rv);
		}
	}
	if (((s2 > 0) && (s2 != (nng_socket) -1)) && (s2 != s1)) {
		if ((rv = nni_sock_find(&sock2, s2)) != 0) {
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

int
nng_pipe_getopt(nng_pipe id, const char *name, void *val, size_t *sizep)
{
	int       rv;
	nni_pipe *p;

	if ((rv = nni_init()) < 0) {
		return (rv);
	}
	if ((rv = nni_pipe_find(&p, id)) != 0) {
		return (rv);
	}
	rv = nni_pipe_getopt(p, name, val, sizep);
	nni_pipe_rele(p);
	return (rv);
}

int
nng_pipe_getopt_int(nng_pipe id, const char *name, int *valp)
{
	size_t sz = sizeof(*valp);
	return (nng_pipe_getopt(id, name, valp, &sz));
}

int
nng_pipe_getopt_size(nng_pipe id, const char *name, size_t *valp)
{
	size_t sz = sizeof(*valp);
	return (nng_pipe_getopt(id, name, valp, &sz));
}

int
nng_pipe_getopt_uint64(nng_pipe id, const char *name, uint64_t *valp)
{
	size_t sz = sizeof(*valp);
	return (nng_pipe_getopt(id, name, valp, &sz));
}

int
nng_pipe_getopt_ms(nng_pipe id, const char *name, nng_duration *valp)
{
	size_t sz = sizeof(*valp);
	return (nng_pipe_getopt(id, name, valp, &sz));
}

int
nng_pipe_close(nng_pipe id)
{
	int       rv;
	nni_pipe *p;

	if ((rv = nni_pipe_find(&p, id)) != 0) {
		return (rv);
	}
	nni_pipe_close(p);
	nni_pipe_rele(p);
	return (0);
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
nng_msg_header_append(nng_msg *msg, const void *data, size_t sz)
{
	return (nni_msg_header_append(msg, data, sz));
}

int
nng_msg_header_append_u32(nng_msg *msg, uint32_t val)
{
	return (nni_msg_header_append_u32(msg, val));
}

int
nng_msg_header_insert_u32(nng_msg *msg, uint32_t val)
{
	return (nni_msg_header_insert_u32(msg, val));
}

int
nng_msg_header_chop_u32(nng_msg *msg, uint32_t *valp)
{
	if (nni_msg_header_len(msg) < sizeof(uint32_t)) {
		return (NNG_EINVAL);
	}
	*valp = nni_msg_header_chop_u32(msg);
	return (0);
}

int
nng_msg_header_trim_u32(nng_msg *msg, uint32_t *valp)
{
	if (nni_msg_header_len(msg) < sizeof(uint32_t)) {
		return (NNG_EINVAL);
	}
	*valp = nni_msg_header_trim_u32(msg);
	return (0);
}

int
nng_msg_append_u32(nng_msg *msg, uint32_t val)
{
	return (nni_msg_append_u32(msg, val));
}

int
nng_msg_insert_u32(nng_msg *msg, uint32_t val)
{
	return (nni_msg_insert_u32(msg, val));
}

int
nng_msg_chop_u32(nng_msg *msg, uint32_t *valp)
{
	if (nni_msg_len(msg) < sizeof(uint32_t)) {
		return (NNG_EINVAL);
	}
	*valp = nni_msg_chop_u32(msg);
	return (0);
}

int
nng_msg_trim_u32(nng_msg *msg, uint32_t *valp)
{
	if (nni_msg_len(msg) < sizeof(uint32_t)) {
		return (NNG_EINVAL);
	}
	*valp = nni_msg_trim_u32(msg);
	return (0);
}

int
nng_msg_header_insert(nng_msg *msg, const void *data, size_t sz)
{
	return (nni_msg_header_insert(msg, data, sz));
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
	return (nni_msg_get_pipe(msg));
}

void
nng_msg_set_pipe(nng_msg *msg, nng_pipe p)
{
	nni_msg_set_pipe(msg, p);
}

int
nng_msg_getopt(nng_msg *msg, int opt, void *ptr, size_t *szp)
{
	return (nni_msg_getopt(msg, opt, ptr, szp));
}

int
nng_aio_alloc(nng_aio **app, void (*cb)(void *), void *arg)
{
	nni_aio *aio;
	int      rv;

	if ((rv = nni_init()) != 0) {
		return (rv);
	}
	if ((rv = nni_aio_init(&aio, (nni_cb) cb, arg)) == 0) {
		*app = (nng_aio *) aio;
	}
	aio->a_timeout = NNG_DURATION_DEFAULT;
	return (rv);
}

void
nng_aio_free(nng_aio *ap)
{
	nni_aio_fini((nni_aio *) ap);
}

int
nng_aio_result(nng_aio *ap)
{
	return (nni_aio_result((nni_aio *) ap));
}

void
nng_aio_stop(nng_aio *ap)
{
	nni_aio_stop((nni_aio *) ap);
}

void
nng_aio_wait(nng_aio *ap)
{
	nni_aio_wait((nni_aio *) ap);
}

void
nng_aio_cancel(nng_aio *ap)
{
	nni_aio_cancel((nni_aio *) ap, NNG_ECANCELED);
}

void
nng_aio_set_msg(nng_aio *ap, nng_msg *msg)
{
	nni_aio_set_msg((nni_aio *) ap, msg);
}

nng_msg *
nng_aio_get_msg(nng_aio *ap)
{
	return ((nng_msg *) (nni_aio_get_msg((nni_aio *) ap)));
}

void
nng_aio_set_timeout(nng_aio *ap, nng_duration dur)
{
	// Durations here are relative, since we have no notion of a
	// common clock..
	nni_aio_set_timeout((nni_aio *) ap, dur);
}

#if 0
int
nng_snapshot_create(nng_socket sock, nng_snapshot **snapp)
{
	// Stats TBD.
	return (NNG_ENOTSUP);
}

void
nng_snapshot_destroy(nng_snapshot *snap)
{
	// Stats TBD.
}

int
nng_snapshot_update(nng_snapshot *snap)
{
	// Stats TBD.
	return (NNG_ENOTSUP);
}

int
nng_snapshot_next(nng_snapshot *snap, nng_stat **statp)
{
	// Stats TBD.
	*statp = NULL;
	return (NNG_ENOTSUP);
}

const char *
nng_stat_name(nng_stat *stat)
{
	// Stats TBD.
	return (NULL);
}

int
nng_stat_type(nng_stat *stat)
{
	// Stats TBD.
	return (0);
}

int64_t
nng_stat_value(nng_stat *stat)
{
	// Stats TBD.
	return (0);
}
#endif

// These routines exist as utility functions, exposing some of our
// "guts" to the external world for the purposes of test code and
// bundled utilities. They should not be considered part of our public
// API, and applications should refrain from their use.

void
nng_msleep(nng_duration ms)
{
	nni_msleep(ms);
}

// nng_thread_create creates a thread structure, and starts it running.
// Unlike the internals, this allocates stuff dynamically, and does not
// wait to start.
int
nng_thread_create(void **thrp, void (*func)(void *), void *arg)
{
	nni_thr *thr;
	int      rv;

	(void) nni_init();

	if ((thr = NNI_ALLOC_STRUCT(thr)) == NULL) {
		return (NNG_ENOMEM);
	}
	memset(thr, 0, sizeof(*thr));
	*thrp = thr;
	if ((rv = nni_thr_init(thr, func, arg)) != 0) {
		return (rv);
	}
	nni_thr_run(thr);
	return (0);
}

void
nng_thread_destroy(void *arg)
{
	nni_thr *thr = arg;

	nni_thr_fini(thr);

	NNI_FREE_STRUCT(thr);
}
