//
// Copyright 2018 Garrett D'Amore <garrett@damore.org>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "nn.h"
#include "nng.h"
#include "protocol/bus0/bus.h"
#include "protocol/pair0/pair.h"
#include "protocol/pipeline0/pull.h"
#include "protocol/pipeline0/push.h"
#include "protocol/pubsub0/pub.h"
#include "protocol/pubsub0/sub.h"
#include "protocol/reqrep0/rep.h"
#include "protocol/reqrep0/req.h"
#include "protocol/survey0/respond.h"
#include "protocol/survey0/survey.h"

#include <stdio.h>
#include <string.h>

// This file supplies the legacy compatibility API.  Applications should
// avoid using these if at all possible, and instead use the new style APIs.

static const struct {
	int nerr;
	int perr;
} nn_errnos[] = {
	// clang-format off
	{ NNG_EINTR,	    EINTR	  },
	{ NNG_ENOMEM,	    ENOMEM	  },
	{ NNG_EINVAL,	    EINVAL	  },
	{ NNG_EBUSY,	    EBUSY	  },
	{ NNG_ETIMEDOUT,    ETIMEDOUT	  },
	{ NNG_ECONNREFUSED, ECONNREFUSED  },
	{ NNG_ECLOSED,	    EBADF	  },
	{ NNG_EAGAIN,	    EAGAIN	  },
	{ NNG_ENOTSUP,	    ENOTSUP	  },
	{ NNG_EADDRINUSE,   EADDRINUSE	  },
	{ NNG_ESTATE,	    EFSM	  },
	{ NNG_ENOENT,	    ENOENT	  },
	{ NNG_EPROTO,	    EPROTO	  },
	{ NNG_EUNREACHABLE, EHOSTUNREACH  },
	{ NNG_EADDRINVAL,   EADDRNOTAVAIL },
	{ NNG_EPERM,	    EACCES	  },
	{ NNG_EMSGSIZE,	    EMSGSIZE	  },
	{ NNG_ECONNABORTED, ECONNABORTED  },
	{ NNG_ECONNRESET,   ECONNRESET	  },
	{ NNG_ECANCELED,    EBADF         },
	{		 0,		0 },
	// clang-format on
};

const char *
nn_strerror(int err)
{
	int         i;
	static char msgbuf[32];

	for (i = 0; nn_errnos[i].perr != 0; i++) {
		if (nn_errnos[i].perr == err) {
			return (nng_strerror(nn_errnos[i].nerr));
		}
	}
	if (err == EIO) {
		return ("Unknown I/O error");
	}

	// Arguably we could use strerror() here, but we should only
	// be getting errnos we understand at this point.
	(void) snprintf(msgbuf, sizeof(msgbuf), "Unknown error %d", err);
	return (msgbuf);
}

static void
nn_seterror(int err)
{
	int i;

	for (i = 0; nn_errnos[i].nerr != 0; i++) {
		if (nn_errnos[i].nerr == err) {
			errno = nn_errnos[i].perr;
			return;
		}
	}
	// No idea...
	errno = EIO;
}

int
nn_errno(void)
{
	return (errno);
}

static const struct {
	uint16_t p_id;
	int (*p_open)(nng_socket *);
} nn_protocols[] = {
// clang-format off
#ifdef NNG_HAVE_BUS0
	{ NN_BUS, nng_bus0_open },
#endif
#ifdef NNG_HAVE_PAIR0
	{ NN_PAIR, nng_pair0_open },
#endif
#ifdef NNG_HAVE_PUSH0
	{ NN_PUSH, nng_push0_open },
#endif
#ifdef NNG_HAVE_PULL0
	{ NN_PULL, nng_pull0_open },
#endif
#ifdef NNG_HAVE_PUB0
	{ NN_PUB, nng_pub0_open },
#endif
#ifdef NNG_HAVE_SUB0
	{ NN_SUB, nng_sub0_open },
#endif
#ifdef NNG_HAVE_REQ0
	{ NN_REQ, nng_req0_open },
#endif
#ifdef NNG_HAVE_REP0
	{ NN_REP, nng_rep0_open },
#endif
#ifdef NNG_HAVE_SURVEYOR0
	{ NN_SURVEYOR, nng_surveyor0_open },
#endif
#ifdef NNG_HAVE_RESPONDENT0
	{ NN_RESPONDENT, nng_respondent0_open },
#endif
	{ 0, NULL },
	// clang-format on
};

int
nn_socket(int domain, int protocol)
{
	nng_socket sock;
	int        rv;
	int        i;

	if ((domain != AF_SP) && (domain != AF_SP_RAW)) {
		errno = EAFNOSUPPORT;
		return (-1);
	}

	for (i = 0; nn_protocols[i].p_id != 0; i++) {
		if (nn_protocols[i].p_id == protocol) {
			break;
		}
	}
	if (nn_protocols[i].p_open == NULL) {
		errno = ENOTSUP;
		return (-1);
	}

	if ((rv = nn_protocols[i].p_open(&sock)) != 0) {
		nn_seterror(rv);
		return (-1);
	}
	if (domain == AF_SP_RAW) {
		if ((rv = nng_setopt_bool(sock, NNG_OPT_RAW, true)) != 0) {
			nn_seterror(rv);
			nng_close(sock);
			return (-1);
		}
	}
	return ((int) sock);
}

int
nn_close(int s)
{
	int rv;

	if ((rv = nng_close((nng_socket) s)) != 0) {
		nn_seterror(rv);
		return (-1);
	}
	return (0);
}

int
nn_bind(int s, const char *addr)
{
	int          rv;
	nng_listener l;

	if ((rv = nng_listen((nng_socket) s, addr, &l, 0)) != 0) {
		nn_seterror(rv);
		return (-1);
	}
	return ((int) l);
}

int
nn_connect(int s, const char *addr)
{
	int        rv;
	nng_dialer d;

	if ((rv = nng_dial((nng_socket) s, addr, &d, NNG_FLAG_NONBLOCK)) !=
	    0) {
		nn_seterror(rv);
		return (-1);
	}
	return ((int) d);
}

int
nn_shutdown(int s, int ep)
{
	int rv;
	(void) s; // Unused

	// Socket is wired into the endpoint... so passing a bad endpoint
	// ID can result in affecting the wrong socket.  But this requires
	// a buggy application, and because we don't recycle endpoints
	// until wrap, its unlikely to actually come up in practice.
	// Note that listeners and dialers share the same namespace
	// in the core, so we can close either one this way.

	if (((rv = nng_dialer_close((nng_dialer) ep)) != 0) &&
	    ((rv = nng_listener_close((nng_listener) ep)) != 0)) {
		nn_seterror(rv);
		return (-1);
	}
	return (0);
}

void *
nn_allocmsg(size_t size, int type)
{
	nng_msg *msg;
	int      rv;

	// Validate type and non-zero size.  This also checks for overflow.
	if ((type != 0) || (size < 1) || ((size + sizeof(msg) < size))) {
		nn_seterror(NNG_EINVAL);
		return (NULL);
	}

	// So our "messages" from nn are really going to be nng messages
	// but to make this work, we use a bit of headroom in the message
	// to stash the message header.
	if ((rv = nng_msg_alloc(&msg, size + (sizeof(msg)))) != 0) {
		nn_seterror(rv);
		return (NULL);
	}

	// This counts on message bodies being aligned sensibly.
	*(nng_msg **) (nng_msg_body(msg)) = msg;

	// We are counting on the implementation of nn_msg_trim to not
	// reallocate the message but just to leave the prefix inplace.
	(void) nng_msg_trim(msg, sizeof(msg));

	return (nng_msg_body(msg));
}

int
nn_freemsg(void *ptr)
{
	nng_msg *msg;

	msg = *(nng_msg **) (((char *) ptr) - sizeof(msg));
	nng_msg_free(msg);
	return (0);
}

void *
nn_reallocmsg(void *ptr, size_t len)
{
	nng_msg *msg;
	int      rv;

	if ((len + sizeof(msg)) < len) {
		// overflowed!
		nn_seterror(NNG_EINVAL);
		return (NULL);
	}

	// This counts on message bodies being aligned sensibly.
	msg = *(nng_msg **) (((char *) ptr) - sizeof(msg));

	// We need to realloc the requested len, plus size for our header.
	if ((rv = nng_msg_realloc(msg, len + sizeof(msg))) != 0) {
		// We don't free the old message.  Code is free to cope
		// as it sees fit.
		nn_seterror(rv);
		return (NULL);
	}
	// Stash the msg header pointer
	*(nng_msg **) (nng_msg_body(msg)) = msg;
	nng_msg_trim(msg, sizeof(msg));
	return (nng_msg_body(msg));
}

static int
nn_flags(int flags)
{
	switch (flags) {
	case 0:
		return (0);

	case NN_DONTWAIT:
		return (NNG_FLAG_NONBLOCK);

	default:
		nn_seterror(NNG_EINVAL);
		return (-1);
	}
}

int
nn_send(int s, const void *buf, size_t len, int flags)
{
	struct nn_iovec  iov;
	struct nn_msghdr hdr;

	iov.iov_base = (void *) buf;
	iov.iov_len  = len;

	hdr.msg_iov        = &iov;
	hdr.msg_iovlen     = 1;
	hdr.msg_control    = NULL;
	hdr.msg_controllen = 0;

	return (nn_sendmsg(s, &hdr, flags));
}

int
nn_recv(int s, void *buf, size_t len, int flags)
{
	struct nn_iovec  iov;
	struct nn_msghdr hdr;

	iov.iov_base = buf;
	iov.iov_len  = len;

	hdr.msg_iov        = &iov;
	hdr.msg_iovlen     = 1;
	hdr.msg_control    = NULL;
	hdr.msg_controllen = 0;

	return (nn_recvmsg(s, &hdr, flags));
}

int
nn_recvmsg(int s, struct nn_msghdr *mh, int flags)
{
	int      rv;
	nng_msg *msg;
	size_t   len;
	int      keep = 0;

	if ((flags = nn_flags(flags)) == -1) {
		return (-1);
	}
	if (mh == NULL) {
		nn_seterror(NNG_EINVAL);
		return (-1);
	}
	if (mh->msg_iovlen < 0) {
		nn_seterror(NNG_EMSGSIZE);
		return (-1);
	}

	if ((rv = nng_recvmsg((nng_socket) s, &msg, flags)) != 0) {
		nn_seterror(rv);
		return (-1);
	}
	if ((mh->msg_iovlen == 1) && (mh->msg_iov[0].iov_len == NN_MSG)) {
		// Receiver wants to have a dynamically allocated message.
		// There can only be one of these.
		if ((rv = nng_msg_insert(msg, &msg, sizeof(msg))) != 0) {
			nng_msg_free(msg);
			nn_seterror(rv);
			return (-1);
		}
		nng_msg_trim(msg, sizeof(msg));
		*(void **) (mh->msg_iov[0].iov_base) = nng_msg_body(msg);
		len                                  = nng_msg_len(msg);
		keep = 1; // Do not discard message!
	} else {
		// copyout to multiple iovecs.
		char * ptr = nng_msg_body(msg);
		int    i;
		size_t n;
		len = nng_msg_len(msg);

		for (i = 0; i < mh->msg_iovlen; i++) {
			if ((n = mh->msg_iov[i].iov_len) == NN_MSG) {
				// This is forbidden!
				nn_seterror(NNG_EINVAL);
				nng_msg_free(msg);
				return (-1);
			}
			if (n > len) {
				n = len;
			}
			memcpy(mh->msg_iov[i].iov_base, ptr, n);
			len -= n;
			ptr += n;
		}

		// If we copied everything, len will be zero, otherwise,
		// it represents the amount of data that we were unable to
		// copyout.  The caller is responsible for noticing this,
		// as there is no API to pass this information out.
		len = nng_msg_len(msg);
	}

	// If the caller has requested control information (header details),
	// we grab it.
	if (mh->msg_control != NULL) {
		char *             cdata;
		size_t             clen;
		size_t             tlen;
		size_t             spsz;
		struct nn_cmsghdr *hdr;
		unsigned char *    ptr;

		spsz = nng_msg_header_len(msg);
		clen = NN_CMSG_SPACE(sizeof(spsz) + spsz);

		if ((tlen = mh->msg_controllen) == NN_MSG) {
			// Ideally we'd use the same msg, but we would need
			// to set up reference counts on the message, so
			// instead we just make a new message.
			nng_msg *nmsg;

			rv = nng_msg_alloc(&nmsg, clen + sizeof(nmsg));
			if (rv != 0) {
				nng_msg_free(msg);
				nn_seterror(rv);
				return (-1);
			}
			memcpy(nng_msg_body(nmsg), &nmsg, sizeof(nmsg));
			nng_msg_trim(nmsg, sizeof(nmsg));
			cdata                      = nng_msg_body(nmsg);
			*(void **) mh->msg_control = cdata;
			tlen                       = clen;
		} else {
			cdata = mh->msg_control;
			memset(cdata, 0,
			    tlen > sizeof(*hdr) ? sizeof(*hdr) : tlen);
		}

		if (clen <= tlen) {
			ptr             = NN_CMSG_DATA(cdata);
			hdr             = (void *) cdata;
			hdr->cmsg_len   = clen;
			hdr->cmsg_level = PROTO_SP;
			hdr->cmsg_type  = SP_HDR;

			memcpy(ptr, &spsz, sizeof(spsz));
			ptr += sizeof(spsz);
			memcpy(ptr, nng_msg_header(msg), spsz);
		}
	}

	if (!keep) {
		nng_msg_free(msg);
	}
	return ((int) len);
}

int
nn_sendmsg(int s, const struct nn_msghdr *mh, int flags)
{
	nng_msg *msg  = NULL;
	nng_msg *cmsg = NULL;
	char *   cdata;
	int      keep = 0;
	size_t   sz;
	int      rv;

	if ((flags = nn_flags(flags)) == -1) {
		return (-1);
	}

	if (mh == NULL) {
		nn_seterror(NNG_EINVAL);
		return (-1);
	}

	if (mh->msg_iovlen < 0) {
		nn_seterror(NNG_EMSGSIZE);
		return (-1);
	}

	if ((mh->msg_iovlen == 1) && (mh->msg_iov[0].iov_len == NN_MSG)) {
		char *bufp = *(char **) (mh->msg_iov[0].iov_base);

		msg  = *(nng_msg **) (bufp - sizeof(msg));
		keep = 1; // keep the message on error
	} else {
		char *ptr;
		int   i;

		sz = 0;
		// Get the total message size.
		for (i = 0; i < mh->msg_iovlen; i++) {
			sz += mh->msg_iov[i].iov_len;
		}
		if ((rv = nng_msg_alloc(&msg, sz)) != 0) {
			nn_seterror(rv);
			return (-1);
		}
		// Now copy it out.
		ptr = nng_msg_body(msg);
		for (i = 0; i < mh->msg_iovlen; i++) {
			memcpy(ptr, mh->msg_iov[i].iov_base,
			    mh->msg_iov[i].iov_len);
			ptr += mh->msg_iov[i].iov_len;
		}
	}

	// Now suck up the control data...
	// This POSIX-inspired API is one of the most painful for
	// usability we've ever seen.
	cmsg = NULL;
	if ((cdata = mh->msg_control) != NULL) {
		size_t             clen;
		size_t             offs;
		size_t             spsz;
		struct nn_cmsghdr *chdr;
		unsigned char *    data;

		if ((clen = mh->msg_controllen) == NN_MSG) {
			// Underlying data is a message.  This is awkward,
			// because we have to copy the data, but we should
			// only free this message on success.  So we save the
			// message now.
			cdata = *(void **) cdata;
			cmsg  = *(nng_msg **) (cdata - sizeof(cmsg));
			clen  = nng_msg_len(cmsg);
		} else {
			clen = mh->msg_controllen;
		}

		offs = 0;
		while ((offs + sizeof(NN_CMSG_LEN(0))) < clen) {
			chdr = (void *) (cdata + offs);
			if ((chdr->cmsg_level != PROTO_SP) ||
			    (chdr->cmsg_type != SP_HDR)) {
				offs += chdr->cmsg_len;
			}

			// SP header in theory.  Starts with size, then
			// any backtrace details.
			if (chdr->cmsg_len < sizeof(size_t)) {
				offs += chdr->cmsg_len;
				continue;
			}
			data = NN_CMSG_DATA(chdr);
			memcpy(&spsz, data, sizeof(spsz));
			if ((spsz + sizeof(spsz)) > chdr->cmsg_len) {
				// Truncated header?  Ignore it.
				offs += chdr->cmsg_len;
				continue;
			}
			data += sizeof(spsz);
			rv = nng_msg_header_append(msg, data, spsz);
			if (rv != 0) {
				if (!keep) {
					nng_msg_free(msg);
				}
				nn_seterror(rv);
				return (-1);
			}

			break;
		}
	}

	sz = nng_msg_len(msg);
	if ((rv = nng_sendmsg((nng_socket) s, msg, flags)) != 0) {
		if (!keep) {
			nng_msg_free(msg);
		}
		nn_seterror(rv);
		return (-1);
	}

	if (cmsg != NULL) {
		// We sent successfully, so free up the control message.
		nng_msg_free(cmsg);
	}
	return ((int) sz);
}

// options which we convert -- most of the array is initialized at run time.
static const struct {
	int         nnlevel;
	int         nnopt;
	const char *opt;
} options[] = {
	{ NN_SOL_SOCKET, NN_LINGER, NNG_OPT_LINGER }, // review
	{ NN_SOL_SOCKET, NN_SNDBUF, NNG_OPT_SENDBUF },
	{ NN_SOL_SOCKET, NN_RCVBUF, NNG_OPT_RECVBUF },
	{ NN_SOL_SOCKET, NN_RECONNECT_IVL, NNG_OPT_RECONNMINT },
	{ NN_SOL_SOCKET, NN_RECONNECT_IVL_MAX, NNG_OPT_RECONNMAXT },
	{ NN_SOL_SOCKET, NN_SNDFD, NNG_OPT_SENDFD },
	{ NN_SOL_SOCKET, NN_RCVFD, NNG_OPT_RECVFD },
	{ NN_SOL_SOCKET, NN_RCVMAXSIZE, NNG_OPT_RECVMAXSZ },
	{ NN_SOL_SOCKET, NN_MAXTTL, NNG_OPT_MAXTTL },
	{ NN_SOL_SOCKET, NN_RCVTIMEO, NNG_OPT_RECVTIMEO },
	{ NN_SOL_SOCKET, NN_SNDTIMEO, NNG_OPT_SENDTIMEO },
	{ NN_SOL_SOCKET, NN_SOCKET_NAME, NNG_OPT_SOCKNAME },
	{ NN_REQ, NN_REQ_RESEND_IVL, NNG_OPT_REQ_RESENDTIME },
	{ NN_SUB, NN_SUB_SUBSCRIBE, NNG_OPT_SUB_SUBSCRIBE },
	{ NN_SUB, NN_SUB_UNSUBSCRIBE, NNG_OPT_SUB_UNSUBSCRIBE },
	{ NN_SURVEYOR, NN_SURVEYOR_DEADLINE, NNG_OPT_SURVEYOR_SURVEYTIME },
	// XXX: IPV4ONLY, SNDPRIO, RCVPRIO
};

static int
nn_getdomain(int s, void *valp, size_t *szp)
{
	int  i;
	bool b;
	int  rv;

	if ((rv = nng_getopt_bool((nng_socket) s, NNG_OPT_RAW, &b)) != 0) {
		nn_seterror(rv);
		return (-1);
	}
	i = b ? AF_SP_RAW : AF_SP;
	memcpy(valp, &i, *szp < sizeof(int) ? *szp : sizeof(int));
	*szp = sizeof(int);
	return (0);
}

int
nn_getsockopt(int s, int nnlevel, int nnopt, void *valp, size_t *szp)
{
	const char *name = NULL;
	int         rv;

	for (unsigned i = 0; i < sizeof(options) / sizeof(options[0]); i++) {
		if ((options[i].nnlevel == nnlevel) &&
		    (options[i].nnopt == nnopt)) {
			name = options[i].opt;
			break;
		}
	}

	if (name == NULL) {
		if (nnlevel == NN_SOL_SOCKET && nnopt == NN_DOMAIN) {
			return (nn_getdomain(s, valp, szp));
		}

		errno = ENOPROTOOPT;
		return (-1);
	}

	if ((rv = nng_getopt((nng_socket) s, name, valp, szp)) != 0) {
		nn_seterror(rv);
		return (-1);
	}

	return (0);
}

int
nn_setsockopt(int s, int nnlevel, int nnopt, const void *valp, size_t sz)
{
	const char *name = NULL;
	int         rv;

	for (unsigned i = 0; i < sizeof(options) / sizeof(options[0]); i++) {
		if ((options[i].nnlevel == nnlevel) &&
		    (options[i].nnopt == nnopt)) {
			name = options[i].opt;
			break;
		}
	}
	if (name == NULL) {
		return (ENOPROTOOPT);
	}

	if ((rv = nng_setopt((nng_socket) s, name, valp, sz)) != 0) {
		nn_seterror(rv);
		return (-1);
	}
	return (0);
}

struct nn_cmsghdr *
nn_cmsg_next(struct nn_msghdr *mh, struct nn_cmsghdr *first)
{
	size_t clen;
	char * data;

	// We only support SP headers, so there can be at most one header.
	if (first != NULL) {
		return (NULL);
	}
	if ((clen = mh->msg_controllen) == NN_MSG) {
		nng_msg *msg;
		data = *((void **) (mh->msg_control));
		msg  = *(nng_msg **) (data - sizeof(msg));
		clen = nng_msg_len(msg);
	} else {
		data = mh->msg_control;
	}

	if (first == NULL) {
		first = (void *) data;
	} else {
		first = first + first->cmsg_len;
	}

	if (((char *) first + sizeof(*first)) > (data + clen)) {
		return (NULL);
	}
	return (first);
}

int
nn_device(int s1, int s2)
{
	int rv;

	rv = nng_device((nng_socket) s1, (nng_socket) s2);
	// rv must always be nonzero
	nn_seterror(rv);
	return (-1);
}

// nn_term is suitable only for shutting down the entire library,
// and is not thread-safe with other functions.
void
nn_term(void)
{
	// This function is relatively toxic, since it can affect
	// all sockets in the process, including those
	// in use by libraries, etc.  Accordingly, do not use this
	// in a library -- only e.g. atexit() and similar.
	nng_closeall();
}
