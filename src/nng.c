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

#include <string.h>

void
nng_fini(void)
{
	nni_fini();
}

int
nng_shutdown(nng_socket sid)
{
	int       rv;
	nni_sock *sock;

	if ((rv = nni_sock_find(&sock, sid)) != 0) {
		return (rv);
	}
	rv = nni_sock_shutdown(sock);
	nni_sock_rele(sock);
	return (rv);
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

uint16_t
nng_protocol(nng_socket sid)
{
	int       rv;
	uint16_t  pnum;
	nni_sock *sock;

	if ((rv = nni_sock_find(&sock, sid)) != 0) {
		return (rv);
	}
	pnum = nni_sock_proto(sock);
	nni_sock_rele(sock);
	return (pnum);
}

uint16_t
nng_peer(nng_socket sid)
{
	int       rv;
	uint16_t  pnum;
	nni_sock *sock;

	if ((rv = nni_sock_find(&sock, sid)) != 0) {
		return (rv);
	}
	pnum = nni_sock_peer(sock);
	nni_sock_rele(sock);
	return (pnum);
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
	nni_time  expire;
	int       rv;
	nni_sock *sock;

	if ((rv = nni_sock_find(&sock, sid)) != 0) {
		return (rv);
	}
	if ((flags == NNG_FLAG_NONBLOCK) || (sock->s_rcvtimeo == 0)) {
		expire = NNI_TIME_ZERO;
	} else if (sock->s_rcvtimeo < 0) {
		expire = NNI_TIME_NEVER;
	} else {
		expire = nni_clock();
		expire += sock->s_rcvtimeo;
	}

	rv = nni_sock_recvmsg(sock, msgp, expire);
	nni_sock_rele(sock);

	// Possibly massage nonblocking attempt.  Note that nonblocking is
	// still done asynchronously, and the calling thread loses context.
	if ((rv == NNG_ETIMEDOUT) && (expire == NNI_TIME_ZERO)) {
		rv = NNG_EAGAIN;
	}

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
nng_sendmsg(nng_socket sid, nng_msg *msg, int flags)
{
	nni_time  expire;
	int       rv;
	nni_sock *sock;

	if ((rv = nni_sock_find(&sock, sid)) != 0) {
		return (rv);
	}
	if ((flags == NNG_FLAG_NONBLOCK) || (sock->s_sndtimeo == 0)) {
		expire = NNI_TIME_ZERO;
	} else if (sock->s_sndtimeo < 0) {
		expire = NNI_TIME_NEVER;
	} else {
		expire = nni_clock();
		expire += sock->s_sndtimeo;
	}

	rv = nni_sock_sendmsg(sock, msg, expire);
	nni_sock_rele(sock);

	// Possibly massage nonblocking attempt.  Note that nonblocking is
	// still done asynchronously, and the calling thread loses context.
	if ((rv == NNG_ETIMEDOUT) && (expire == NNI_TIME_ZERO)) {
		rv = NNG_EAGAIN;
	}

	return (rv);
}

int
nng_dial(nng_socket sid, const char *addr, nng_endpoint *epp, int flags)
{
	nni_ep *  ep;
	int       rv;
	nni_sock *sock;

	if ((rv = nni_sock_find(&sock, sid)) != 0) {
		return (rv);
	}
	if ((rv = nni_sock_dial(sock, addr, &ep, flags)) == 0) {
		if (epp != NULL) {
			*epp = nni_ep_id(ep);
		}
	}
	nni_sock_rele(sock);
	return (rv);
}

int
nng_listen(nng_socket sid, const char *addr, nng_endpoint *epp, int flags)
{
	nni_ep *  ep;
	int       rv;
	nni_sock *sock;

	if ((rv = nni_sock_find(&sock, sid)) != 0) {
		return (rv);
	}
	if ((rv = nni_sock_listen(sock, addr, &ep, flags)) == 0) {
		if (epp != NULL) {
			*epp = nni_ep_id(ep);
		}
	}
	nni_sock_rele(sock);
	return (rv);
}

int
nng_endpoint_close(nng_endpoint eid)
{
	// XXX: reimplement this properly.
	NNI_ARG_UNUSED(eid);
	return (NNG_ENOTSUP);
}

int
nng_setopt(nng_socket sid, int opt, const void *val, size_t sz)
{
	nni_sock *sock;
	int       rv;

	if ((rv = nni_sock_find(&sock, sid)) != 0) {
		return (rv);
	}
	rv = nni_sock_setopt(sock, opt, val, sz);
	nni_sock_rele(sock);
	return (rv);
}

int
nng_getopt(nng_socket sid, int opt, void *val, size_t *szp)
{
	nni_sock *sock;
	int       rv;

	if ((rv = nni_sock_find(&sock, sid)) != 0) {
		return (rv);
	}
	rv = nni_sock_getopt(sock, opt, val, szp);
	nni_sock_rele(sock);
	return (rv);
}

nng_notify *
nng_setnotify(nng_socket sid, int mask, nng_notify_func fn, void *arg)
{
	nni_sock *  sock;
	nng_notify *notify;
	int         rv;

	if ((rv = nni_sock_find(&sock, sid)) != 0) {
		return (NULL);
	}
	notify = nni_sock_notify(sock, mask, fn, arg);
	nni_sock_rele(sock);
	return (notify);
}

void
nng_unsetnotify(nng_socket sid, nng_notify *notify)
{
	nni_sock *sock;
	int       rv;

	if ((rv = nni_sock_find(&sock, sid)) != 0) {
		return;
	}
	nni_sock_unnotify(sock, notify);
	nni_sock_rele(sock);
}

nng_socket
nng_event_socket(nng_event *ev)
{
	// XXX: FOR NOW....  maybe evnet should contain socket Id instead?
	return (nni_sock_id(ev->e_sock));
}

int
nng_event_type(nng_event *ev)
{
	return (ev->e_type);
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
	{ 0, NULL }
	// clang-format on
};

// Misc.
const char *
nng_strerror(int num)
{
	for (int i = 0; nni_errors[i].msg != NULL; i++) {
		if (nni_errors[i].code == num) {
			return (nni_errors[i].msg);
		}
	}

	if (num & NNG_ESYSERR) {
		return (nni_plat_strerror(num & ~NNG_ESYSERR));
	}

	return ("Unknown error");
}

#if 0
int
nng_pipe_getopt(nng_pipe *pipe, int opt, void *val, size_t *sizep)
{
	int rv;

	rv = nni_pipe_getopt(pipe, opt, val, sizep);
	if (rv == ENOTSUP) {
		// Maybe its a generic socket option.
		rv = nni_sock_getopt(pipe->p_sock, opt, val, sizep);
	}
	return (rv);
}


int
nng_pipe_close(nng_pipe *pipe)
{
	nni_pipe_close(pipe);
	return (0);
}

#endif

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

// These routines exist as utility functions, exposing some of our "guts"
// to the external world for the purposes of test code and bundled utilities.
// They should not be considered part of our public API, and applications
// should refrain from their use.

void
nng_usleep(uint64_t usec)
{
	nni_usleep(usec);
}

uint64_t
nng_clock(void)
{
	return ((uint64_t) nni_clock());
}

// nng_thread_create creates a thread structure, and starts it running.
// Unlike the internals, this allocates stuff dynamically, and does not
// wait to start.
int
nng_thread_create(void **thrp, void (*func)(void *), void *arg)
{
	nni_thr *thr;
	int      rv;

	nni_init();

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
