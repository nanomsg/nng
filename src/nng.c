//
// Copyright 2017 Garrett D'Amore <garrett@damore.org>
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

#define NNI_INIT_INT()			     \
	do {				     \
		if (nni_init() != 0) {	     \
			return (NNG_ENOMEM); \
		}			     \
	}				     \
	while (0)

#define NNI_INIT_VOID()	\
	(void) nni_init()

int
nng_open(nng_socket *sidp, uint16_t proto)
{
	int rv;
	nni_sock *sock;

	if ((rv = nni_sock_open(&sock, proto)) != 0) {
		return (rv);
	}
	*sidp = nni_sock_id(sock);
	nni_sock_rele(sock);
	return (0);
}


int
nng_shutdown(nng_socket sid)
{
	int rv;
	nni_sock *sock;

	if ((rv = nni_sock_hold(&sock, sid)) != 0) {
		return (rv);
	}
	rv = nni_sock_shutdown(sock);
	nni_sock_rele(sock);
	return (rv);
}


int
nng_close(nng_socket sid)
{
	int rv;
	nni_sock *sock;

	if ((rv = nni_sock_hold(&sock, sid)) != 0) {
		return (rv);
	}
	// No release -- close releases it.
	nni_sock_close(sock);
	return (rv);
}


uint16_t
nng_protocol(nng_socket sid)
{
	int rv;
	uint16_t pnum;
	nni_sock *sock;

	if ((rv = nni_sock_hold(&sock, sid)) != 0) {
		return (rv);
	}
	pnum = nni_sock_proto(sock);
	nni_sock_rele(sock);
	return (pnum);
}


uint16_t
nng_peer(nng_socket sid)
{
	int rv;
	uint16_t pnum;
	nni_sock *sock;

	if ((rv = nni_sock_hold(&sock, sid)) != 0) {
		return (rv);
	}
	pnum = nni_sock_peer(sock);
	nni_sock_rele(sock);
	return (pnum);
}


int
nng_recvmsg(nng_socket sid, nng_msg **msgp, int flags)
{
	nni_time expire;
	int rv;
	nni_sock *sock;

	if ((rv = nni_sock_hold(&sock, sid)) != 0) {
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
	return (rv);
}


int
nng_sendmsg(nng_socket sid, nng_msg *msg, int flags)
{
	nni_time expire;
	int rv;
	nni_sock *sock;

	if ((rv = nni_sock_hold(&sock, sid)) != 0) {
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
	return (rv);
}


int
nng_dial(nng_socket sid, const char *addr, nng_endpoint *epp, int flags)
{
	nni_ep *ep;
	int rv;
	nni_sock *sock;

	if ((rv = nni_sock_hold(&sock, sid)) != 0) {
		return (rv);
	}
	if ((rv = nni_sock_dial(sock, addr, &ep, flags)) == 0) {
		if (epp != NULL) {
			*epp = ep->ep_id;
		}
	}
	nni_sock_rele(sock);
	return (rv);
}


int
nng_listen(nng_socket sid, const char *addr, nng_endpoint *epp, int flags)
{
	nni_ep *ep;
	int rv;
	nni_sock *sock;

	if ((rv = nni_sock_hold(&sock, sid)) != 0) {
		return (rv);
	}
	if ((rv = nni_sock_listen(sock, addr, &ep, flags)) == 0) {
		if (epp != NULL) {
			*epp = ep->ep_id;
		}
	}
	nni_sock_rele(sock);
	return (rv);
}


int
nng_setopt(nng_socket sid, int opt, const void *val, size_t sz)
{
	nni_sock *sock;
	int rv;

	if ((rv = nni_sock_hold(&sock, sid)) != 0) {
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
	int rv;

	if ((rv = nni_sock_hold(&sock, sid)) != 0) {
		return (rv);
	}
	rv = nni_sock_getopt(sock, opt, val, szp);
	nni_sock_rele(sock);
	return (rv);
}


nng_notify *
nng_setnotify(nng_socket sid, int mask, nng_notify_func fn, void *arg)
{
	nni_sock *sock;
	nng_notify *notify;
	int rv;

	if ((rv = nni_sock_hold(&sock, sid)) != 0) {
		return (NULL);
	}
	notify = nni_add_notify(sock, mask, fn, arg);
	nni_sock_rele(sock);
	return (notify);
}


void
nng_unsetnotify(nng_socket sid, nng_notify *notify)
{
	nni_sock *sock;
	int rv;

	if ((rv = nni_sock_hold(&sock, sid)) != 0) {
		return;
	}
	nni_rem_notify(sock, notify);
	nni_sock_rele(sock);
}


nng_socket
nng_event_socket(nng_event *ev)
{
	// FOR NOW....  maybe evnet should contain socket Id instead?
	return (nni_sock_id(ev->e_sock));
}


int
nng_event_type(nng_event *ev)
{
	return (ev->e_type);
}


// Misc.
const char *
nng_strerror(int num)
{
	switch (num) {
	case 0:
		return ("Hunky dory");  // What did you expect?

	case NNG_EINTR:
		return ("Interrupted");

	case NNG_ENOMEM:
		return ("Out of memory");

	case NNG_EINVAL:
		return ("Invalid argument");

	case NNG_EBUSY:
		return ("Resource busy");

	case NNG_ETIMEDOUT:
		return ("Timed out");

	case NNG_ECONNREFUSED:
		return ("Connection refused");

	case NNG_ECLOSED:
		return ("Object closed");

	case NNG_EAGAIN:
		return ("Try again");

	case NNG_ENOTSUP:
		return ("Not supported");

	case NNG_EADDRINUSE:
		return ("Address in use");

	case NNG_ESTATE:
		return ("Incorrect state");

	case NNG_ENOENT:
		return ("Entry not found");

	case NNG_EPROTO:
		return ("Protocol error");

	case NNG_EUNREACHABLE:
		return ("Destination unreachable");

	case NNG_EADDRINVAL:
		return ("Address invalid");

	case NNG_EPERM:
		return ("Permission denied");

	case NNG_EMSGSIZE:
		return ("Message too large");

	case NNG_ECONNRESET:
		return ("Connection reset");

	case NNG_ECONNABORTED:
		return ("Connection aborted");
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

	NNI_INIT_INT();
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
	NNI_INIT_INT();
	nni_pipe_close(pipe);
	return (0);
}


#endif


// Message handling.
int
nng_msg_alloc(nng_msg **msgp, size_t size)
{
	NNI_INIT_VOID();
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
nng_msg_len(nng_msg *msg)
{
	return (nni_msg_len(msg));
}


void *
nng_msg_header(nng_msg *msg)
{
	return (nni_msg_header(msg));
}


size_t
nng_msg_header_len(nng_msg *msg)
{
	return (nni_msg_header_len(msg));
}


int
nng_msg_append(nng_msg *msg, const void *data, size_t sz)
{
	return (nni_msg_append(msg, data, sz));
}


int
nng_msg_prepend(nng_msg *msg, const void *data, size_t sz)
{
	return (nni_msg_prepend(msg, data, sz));
}


int
nng_msg_append_header(nng_msg *msg, const void *data, size_t sz)
{
	return (nni_msg_append_header(msg, data, sz));
}


int
nng_msg_prepend_header(nng_msg *msg, const void *data, size_t sz)
{
	return (nni_msg_prepend_header(msg, data, sz));
}


int
nng_msg_trim(nng_msg *msg, size_t sz)
{
	return (nni_msg_trim(msg, sz));
}


int
nng_msg_trunc(nng_msg *msg, size_t sz)
{
	return (nni_msg_trunc(msg, sz));
}


int
nng_msg_trim_header(nng_msg *msg, size_t sz)
{
	return (nni_msg_trim_header(msg, sz));
}


int
nng_msg_trunc_header(nng_msg *msg, size_t sz)
{
	return (nni_msg_trunc_header(msg, sz));
}


int
nng_msg_getopt(nng_msg *msg, int opt, void *ptr, size_t *szp)
{
	return (nni_msg_getopt(msg, opt, ptr, szp));
}


int
nng_snapshot_create(nng_snapshot **snapp)
{
	// Stats TBD.
	NNI_INIT_INT();
	return (NNG_ENOTSUP);
}


void
nng_snapshot_destroy(nng_snapshot *snap)
{
	NNI_INIT_VOID();
	// Stats TBD.
}


int
nng_snapshot_update(nng_socket sock, nng_snapshot *snap)
{
	// Stats TBD.
	NNI_INIT_INT();
	return (NNG_ENOTSUP);
}


int
nng_snapshot_next(nng_snapshot *snap, nng_stat **statp)
{
	// Stats TBD.
	NNI_INIT_INT();
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


int
nng_device(nng_socket sock1, nng_socket sock2)
{
	// Device TBD.
	NNI_INIT_INT();
	return (NNG_ENOTSUP);
}
