//
// Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "nng/compat/nanomsg/nn.h"

// transports
#include "nng/compat/nanomsg/inproc.h"
#include "nng/compat/nanomsg/ipc.h"
#include "nng/compat/nanomsg/tcp.h"
#include "nng/compat/nanomsg/ws.h"

// protocols
#include "nng/compat/nanomsg/bus.h"
#include "nng/compat/nanomsg/pair.h"
#include "nng/compat/nanomsg/pipeline.h"
#include "nng/compat/nanomsg/pubsub.h"
#include "nng/compat/nanomsg/reqrep.h"
#include "nng/compat/nanomsg/survey.h"

// underlying NNG headers
#include "nng/nng.h"
#include "nng/protocol/bus0/bus.h"
#include "nng/protocol/pair0/pair.h"
#include "nng/protocol/pipeline0/pull.h"
#include "nng/protocol/pipeline0/push.h"
#include "nng/protocol/pubsub0/pub.h"
#include "nng/protocol/pubsub0/sub.h"
#include "nng/protocol/reqrep0/rep.h"
#include "nng/protocol/reqrep0/req.h"
#include "nng/protocol/survey0/respond.h"
#include "nng/protocol/survey0/survey.h"

#include "core/nng_impl.h"

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
	{ NNG_EADDRINVAL,   EINVAL        },
	{ NNG_EPERM,	    EACCES	  },
	{ NNG_EMSGSIZE,	    EMSGSIZE	  },
	{ NNG_ECONNABORTED, ECONNABORTED  },
	{ NNG_ECONNRESET,   ECONNRESET	  },
	{ NNG_ECANCELED,    EBADF         },
	{ NNG_EEXIST,       EEXIST        },
	{ NNG_EWRITEONLY,   EACCES        },
	{ NNG_EREADONLY,    EACCES        },
	{ NNG_ECRYPTO,      EACCES        },
	{ NNG_EPEERAUTH,    EACCES        },
	{ NNG_EBADTYPE,     EINVAL        },
	{ NNG_EAMBIGUOUS,   EINVAL        },
	{ NNG_ENOFILES,     EMFILE        },
	{ NNG_ENOSPC,       ENOSPC        },
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
	int (*p_open_raw)(nng_socket *);
} nn_protocols[] = {
#ifdef NNG_HAVE_BUS0
	{
	    .p_id       = NN_BUS,
	    .p_open     = nng_bus0_open,
	    .p_open_raw = nng_bus0_open_raw,
	},
#endif
#ifdef NNG_HAVE_PAIR0
	{
	    .p_id       = NN_PAIR,
	    .p_open     = nng_pair0_open,
	    .p_open_raw = nng_pair0_open_raw,
	},
#endif
#ifdef NNG_HAVE_PULL0
	{
	    .p_id       = NN_PULL,
	    .p_open     = nng_pull0_open,
	    .p_open_raw = nng_pull0_open_raw,
	},
#endif
#ifdef NNG_HAVE_PUSH0
	{
	    .p_id       = NN_PUSH,
	    .p_open     = nng_push0_open,
	    .p_open_raw = nng_push0_open_raw,
	},
#endif
#ifdef NNG_HAVE_PUB0
	{
	    .p_id       = NN_PUB,
	    .p_open     = nng_pub0_open,
	    .p_open_raw = nng_pub0_open_raw,
	},
#endif
#ifdef NNG_HAVE_SUB0
	{
	    .p_id       = NN_SUB,
	    .p_open     = nng_sub0_open,
	    .p_open_raw = nng_sub0_open_raw,
	},
#endif
#ifdef NNG_HAVE_REQ0
	{
	    .p_id       = NN_REQ,
	    .p_open     = nng_req0_open,
	    .p_open_raw = nng_req0_open_raw,
	},
#endif
#ifdef NNG_HAVE_REP0
	{
	    .p_id       = NN_REP,
	    .p_open     = nng_rep0_open,
	    .p_open_raw = nng_rep0_open_raw,
	},
#endif
#ifdef NNG_HAVE_SURVEYOR0
	{
	    .p_id       = NN_SURVEYOR,
	    .p_open     = nng_surveyor0_open,
	    .p_open_raw = nng_surveyor0_open_raw,
	},
#endif
#ifdef NNG_HAVE_RESPONDENT0
	{
	    .p_id       = NN_RESPONDENT,
	    .p_open     = nng_respondent0_open,
	    .p_open_raw = nng_respondent0_open_raw,
	},
#endif
	{
	    .p_id = 0,
	},
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

	if (domain == AF_SP_RAW) {
		rv = nn_protocols[i].p_open_raw(&sock);
	} else {
		rv = nn_protocols[i].p_open(&sock);
	}
	if (rv != 0) {
		nn_seterror(rv);
		return (-1);
	}

	// Legacy sockets have nodelay disabled.
	(void) nng_setopt_bool(sock, NNG_OPT_TCP_NODELAY, false);
	return ((int) sock.id);
}

int
nn_close(int s)
{
	int        rv;
	nng_socket sid;

	sid.id = (uint32_t) s;

	if ((rv = nng_close(sid)) != 0) {
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
	nng_socket   sid;

	sid.id = (uint32_t) s;
	if ((rv = nng_listen(sid, addr, &l, 0)) != 0) {
		nn_seterror(rv);
		return (-1);
	}
	return ((int) l.id);
}

int
nn_connect(int s, const char *addr)
{
	int        rv;
	nng_dialer d;
	nng_socket sid;

	sid.id = (uint32_t) s;
	if ((rv = nng_dial(sid, addr, &d, NNG_FLAG_NONBLOCK)) != 0) {
		nn_seterror(rv);
		return (-1);
	}
	return ((int) d.id);
}

int
nn_shutdown(int s, int ep)
{
	int rv;
	(void) s; // Unused
	nng_dialer   d;
	nng_listener l;

	// Socket is wired into the endpoint... so passing a bad endpoint
	// ID can result in affecting the wrong socket.  But this requires
	// a buggy application, and because we don't recycle endpoints
	// until wrap, its unlikely to actually come up in practice.
	// Note that listeners and dialers share the same namespace
	// in the core, so we can close either one this way.

	d.id = l.id = (uint32_t) ep;
	if (((rv = nng_dialer_close(d)) != 0) &&
	    ((rv = nng_listener_close(l)) != 0)) {
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
	int        rv;
	nng_msg *  msg;
	size_t     len;
	int        keep = 0;
	nng_socket sid;

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

	sid.id = (uint32_t) s;
	if ((rv = nng_recvmsg(sid, &msg, flags)) != 0) {
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
		char *ptr = nng_msg_body(msg);
		len       = nng_msg_len(msg);

		for (int i = 0; i < mh->msg_iovlen; i++) {
			size_t n;
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
			uint8_t *ptr    = NN_CMSG_DATA(cdata);
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
	nng_msg *  msg  = NULL;
	nng_msg *  cmsg = NULL;
	nng_socket sid;
	char *     cdata;
	int        keep = 0;
	size_t     sz;
	int        rv;

	sid.id = (uint32_t) s;

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
		size_t         clen;
		size_t         offs;
		size_t         spsz;
		unsigned char *data;

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
			struct nn_cmsghdr *chdr = (void *) (cdata + offs);
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
	if ((rv = nng_sendmsg(sid, msg, flags)) != 0) {
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

static int
nn_getdomain(nng_socket s, void *valp, size_t *szp)
{
	int  i;
	bool b;
	int  rv;

	if ((rv = nng_getopt_bool(s, NNG_OPT_RAW, &b)) != 0) {
		nn_seterror(rv);
		return (-1);
	}
	i = b ? AF_SP_RAW : AF_SP;
	memcpy(valp, &i, *szp < sizeof(int) ? *szp : sizeof(int));
	*szp = sizeof(int);
	return (0);
}

#ifndef NNG_PLATFORM_WINDOWS
#define SOCKET int
#endif

static int
nn_getfd(nng_socket s, void *valp, size_t *szp, const char *opt)
{
	int    ifd;
	int    rv;
	SOCKET sfd;

	if ((rv = nng_getopt_int(s, opt, &ifd)) != 0) {
		nn_seterror(rv);
		return (-1);
	}
	sfd = (SOCKET) ifd;
	memcpy(valp, &sfd, *szp < sizeof(sfd) ? *szp : sizeof(sfd));
	*szp = sizeof(sfd);
	return (0);
}

static int
nn_getrecvfd(nng_socket s, void *valp, size_t *szp)
{
	return (nn_getfd(s, valp, szp, NNG_OPT_RECVFD));
}

static int
nn_getsendfd(nng_socket s, void *valp, size_t *szp)
{
	return (nn_getfd(s, valp, szp, NNG_OPT_SENDFD));
}

static int
nn_getzero(nng_socket s, void *valp, size_t *szp)
{
	int zero = 0;
	NNI_ARG_UNUSED(s);
	memcpy(valp, &zero, *szp < sizeof(zero) ? *szp : sizeof(zero));
	*szp = sizeof(zero);
	return (0);
}

static int
nn_setignore(nng_socket s, const void *valp, size_t sz)
{
	NNI_ARG_UNUSED(valp);
	NNI_ARG_UNUSED(s);
	if (sz != sizeof(int)) {
		nn_seterror(NNG_EINVAL);
		return (-1);
	}
	return (0);
}

static int
nn_getwsmsgtype(nng_socket s, void *valp, size_t *szp)
{
	int val = NN_WS_MSG_TYPE_BINARY;
	NNI_ARG_UNUSED(s);
	memcpy(valp, &val, *szp < sizeof(val) ? *szp : sizeof(val));
	*szp = sizeof(val);
	return (0);
}

static int
nn_setwsmsgtype(nng_socket s, const void *valp, size_t sz)
{
	int val;
	NNI_ARG_UNUSED(s);
	if (sz != sizeof(val)) {
		nn_seterror(NNG_EINVAL);
		return (-1);
	}
	memcpy(&val, valp, sizeof(val));
	if (val != NN_WS_MSG_TYPE_BINARY) {
		nn_seterror(NNG_EINVAL);
		return (-1);
	}
	return (0);
}

static int
nn_settcpnodelay(nng_socket s, const void *valp, size_t sz)
{
	bool val;
	int  ival;
	int  rv;

	if (sz != sizeof(ival)) {
		errno = EINVAL;
		return (-1);
	}
	memcpy(&ival, valp, sizeof(ival));
	switch (ival) {
	case 0:
		val = false;
		break;
	case 1:
		val = true;
		break;
	default:
		nn_seterror(NNG_EINVAL);
		return (-1);
	}

	if ((rv = nng_setopt_bool(s, NNG_OPT_TCP_NODELAY, val)) != 0) {
		nn_seterror(rv);
		return (-1);
	}
	return (0);
}

static int
nn_gettcpnodelay(nng_socket s, void *valp, size_t *szp)
{
	bool val;
	int  ival;
	int  rv;

	if ((rv = nng_getopt_bool(s, NNG_OPT_TCP_NODELAY, &val)) != 0) {
		nn_seterror(rv);
		return (-1);
	}
	ival = val ? 1 : 0;
	memcpy(valp, &ival, *szp < sizeof(ival) ? *szp : sizeof(ival));
	*szp = sizeof(ival);
	return (0);
}

static int
nn_getrcvbuf(nng_socket s, void *valp, size_t *szp)
{
	int cnt;
	int rv;

	if ((rv = nng_getopt_int(s, NNG_OPT_RECVBUF, &cnt)) != 0) {
		nn_seterror(rv);
		return (-1);
	}
	cnt *= 1024;
	memcpy(valp, &cnt, *szp < sizeof(cnt) ? *szp : sizeof(cnt));
	*szp = sizeof(cnt);
	return (0);
}

static int
nn_setrcvbuf(nng_socket s, const void *valp, size_t sz)
{
	int cnt;
	int rv;

	if (sz != sizeof(cnt)) {
		errno = EINVAL;
		return (-1);
	}
	memcpy(&cnt, valp, sizeof(cnt));
	// Round up to a whole number of kilobytes, then divide by kB to
	// go from buffer size in bytes to messages.  This is a coarse
	// estimate, and assumes messages are 1kB on average.
	cnt += 1023;
	cnt /= 1024;
	if ((rv = nng_setopt_int(s, NNG_OPT_RECVBUF, cnt)) != 0) {
		nn_seterror(rv);
		return (-1);
	}
	return (0);
}

static int
nn_getsndbuf(nng_socket s, void *valp, size_t *szp)
{
	int cnt;
	int rv;

	if ((rv = nng_getopt_int(s, NNG_OPT_SENDBUF, &cnt)) != 0) {
		nn_seterror(rv);
		return (-1);
	}
	cnt *= 1024;
	memcpy(valp, &cnt, *szp < sizeof(cnt) ? *szp : sizeof(cnt));
	*szp = sizeof(cnt);
	return (0);
}

static int
nn_setsndbuf(nng_socket s, const void *valp, size_t sz)
{
	int cnt;
	int rv;

	if (sz != sizeof(cnt)) {
		errno = EINVAL;
		return (-1);
	}
	memcpy(&cnt, valp, sizeof(cnt));
	// Round up to a whole number of kilobytes, then divide by kB to
	// go from buffer size in bytes to messages.  This is a coarse
	// estimate, and assumes messages are 1kB on average.
	cnt += 1023;
	cnt /= 1024;
	if ((rv = nng_setopt_int(s, NNG_OPT_SENDBUF, cnt)) != 0) {
		nn_seterror(rv);
		return (-1);
	}
	return (0);
}

static int
nn_setrcvmaxsz(nng_socket s, const void *valp, size_t sz)
{
	int    ival;
	size_t val;
	int    rv;

	if (sz != sizeof(ival)) {
		errno = EINVAL;
		return (-1);
	}
	memcpy(&ival, valp, sizeof(ival));
	if (ival == -1) {
		val = 0;
	} else if (ival >= 0) {
		// Note that if the user sets 0, it disables the limit.
		// This is a different semantic.
		val = (size_t) ival;
	} else {
		errno = EINVAL;
		return (-1);
	}
	if ((rv = nng_setopt_size(s, NNG_OPT_RECVMAXSZ, val)) != 0) {
		nn_seterror(rv);
		return (-1);
	}
	return (0);
}

static int
nn_getrcvmaxsz(nng_socket s, void *valp, size_t *szp)
{
	int    ival;
	int    rv;
	size_t val;

	if ((rv = nng_getopt_size(s, NNG_OPT_RECVMAXSZ, &val)) != 0) {
		nn_seterror(rv);
		return (-1);
	}
	// Legacy uses -1 to mean unlimited.  New code uses 0.  Note that
	// as a consequence, we can't set a message limit of zero.
	// We report any size beyond 2GB as effectively unlimited.
	// There is an implicit assumption here that ints are 32-bits,
	// but that's generally true of any platform we support.
	if ((val == 0) || (val > 0x7FFFFFFF)) {
		ival = -1;
	} else {
		ival = (int) val;
	}
	memcpy(valp, &ival, *szp < sizeof(ival) ? *szp : sizeof(ival));
	*szp = sizeof(ival);
	return (0);
}

// options which we convert -- most of the array is initialized at run time.
static const struct {
	int         nnlevel;
	int         nnopt;
	const char *opt;
	int (*get)(nng_socket, void *, size_t *);
	int (*set)(nng_socket, const void *, size_t);
} options[] = {
	{
	    .nnlevel = NN_SOL_SOCKET,
	    .nnopt   = NN_LINGER,
	    .get     = nn_getzero,
	    .set     = nn_setignore,
	}, // review
	{
	    .nnlevel = NN_SOL_SOCKET,
	    .nnopt   = NN_DOMAIN,
	    .get     = nn_getdomain,
	    .set     = NULL,
	},
	{
	    .nnlevel = NN_SOL_SOCKET,
	    .nnopt   = NN_RCVBUF,
	    .get     = nn_getrcvbuf,
	    .set     = nn_setrcvbuf,
	},
	{
	    .nnlevel = NN_SOL_SOCKET,
	    .nnopt   = NN_SNDBUF,
	    .get     = nn_getsndbuf,
	    .set     = nn_setsndbuf,
	},
	{
	    .nnlevel = NN_SOL_SOCKET,
	    .nnopt   = NN_RECONNECT_IVL,
	    .opt     = NNG_OPT_RECONNMINT,
	},
	{
	    .nnlevel = NN_SOL_SOCKET,
	    .nnopt   = NN_RECONNECT_IVL_MAX,
	    .opt     = NNG_OPT_RECONNMAXT,
	},
	{
	    .nnlevel = NN_SOL_SOCKET,
	    .nnopt   = NN_SNDFD,
	    .opt     = NNG_OPT_SENDFD,
	    .get     = nn_getsendfd,
	},
	{
	    .nnlevel = NN_SOL_SOCKET,
	    .nnopt   = NN_RCVFD,
	    .opt     = NNG_OPT_RECVFD,
	    .get     = nn_getrecvfd,
	},
	{
	    .nnlevel = NN_SOL_SOCKET,
	    .nnopt   = NN_RCVMAXSIZE,
	    .get     = nn_getrcvmaxsz,
	    .set     = nn_setrcvmaxsz,
	},
	{
	    .nnlevel = NN_SOL_SOCKET,
	    .nnopt   = NN_MAXTTL,
	    .opt     = NNG_OPT_MAXTTL,
	},
	{
	    .nnlevel = NN_SOL_SOCKET,
	    .nnopt   = NN_RCVTIMEO,
	    .opt     = NNG_OPT_RECVTIMEO,
	},
	{
	    .nnlevel = NN_SOL_SOCKET,
	    .nnopt   = NN_SNDTIMEO,
	    .opt     = NNG_OPT_SENDTIMEO,
	},
	{
	    .nnlevel = NN_SOL_SOCKET,
	    .nnopt   = NN_PROTOCOL,
	    .opt     = NNG_OPT_PROTO,
	},
	{
	    .nnlevel = NN_SOL_SOCKET,
	    .nnopt   = NN_SOCKET_NAME,
	    .opt     = NNG_OPT_SOCKNAME,
	},
	{
	    .nnlevel = NN_REQ,
	    .nnopt   = NN_REQ_RESEND_IVL,
	    .opt     = NNG_OPT_REQ_RESENDTIME,
	},
	{
	    .nnlevel = NN_SUB,
	    .nnopt   = NN_SUB_SUBSCRIBE,
	    .opt     = NNG_OPT_SUB_SUBSCRIBE,
	},
	{
	    .nnlevel = NN_SUB,
	    .nnopt   = NN_SUB_UNSUBSCRIBE,
	    .opt     = NNG_OPT_SUB_UNSUBSCRIBE,
	},
	{
	    .nnlevel = NN_SURVEYOR,
	    .nnopt   = NN_SURVEYOR_DEADLINE,
	    .opt     = NNG_OPT_SURVEYOR_SURVEYTIME,
	},
	{
	    .nnlevel = NN_TCP,
	    .nnopt   = NN_TCP_NODELAY,
	    .get     = nn_gettcpnodelay,
	    .set     = nn_settcpnodelay,
	},
	{
	    .nnlevel = NN_WS,
	    .nnopt   = NN_WS_MSG_TYPE,
	    .get     = nn_getwsmsgtype,
	    .set     = nn_setwsmsgtype,
	}
	// XXX: IPV4ONLY, SNDPRIO, RCVPRIO
};

int
nn_getsockopt(int s, int nnlevel, int nnopt, void *valp, size_t *szp)
{
	const char *name                         = NULL;
	int (*get)(nng_socket, void *, size_t *) = NULL;
	int        rv;
	nng_socket sid;

	sid.id = (uint32_t) s;

	for (unsigned i = 0; i < sizeof(options) / sizeof(options[0]); i++) {
		if ((options[i].nnlevel == nnlevel) &&
		    (options[i].nnopt == nnopt)) {
			get  = options[i].get;
			name = options[i].opt;
			break;
		}
	}

	if (get != NULL) {
		return (get(sid, valp, szp));
	}

	if (name == NULL) {
		errno = ENOPROTOOPT;
		return (-1);
	}

	if ((rv = nng_getopt(sid, name, valp, szp)) != 0) {
		nn_seterror(rv);
		return (-1);
	}

	return (0);
}

int
nn_setsockopt(int s, int nnlevel, int nnopt, const void *valp, size_t sz)
{
	nng_socket  sid;
	const char *name                             = NULL;
	int (*set)(nng_socket, const void *, size_t) = NULL;
	int rv;

	sid.id = (uint32_t) s;

	for (unsigned i = 0; i < sizeof(options) / sizeof(options[0]); i++) {
		if ((options[i].nnlevel == nnlevel) &&
		    (options[i].nnopt == nnopt)) {

			set  = options[i].set;
			name = options[i].opt;
			break;
		}
	}

	if (set != NULL) {
		return (set(sid, valp, sz));
	}

	if (name == NULL) {
		errno = ENOPROTOOPT;
		return (-1);
	}

	if ((rv = nng_setopt(sid, name, valp, sz)) != 0) {
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
	int        rv;
	nng_socket sid1;
	nng_socket sid2;

	sid1.id = (uint32_t) s1;
	sid2.id = (uint32_t) s2;

	rv = nng_device(sid1, sid2);
	// rv must always be nonzero
	nn_seterror(rv);
	return (-1);
}

// Windows stuff.
#ifdef NNG_PLATFORM_WINDOWS
#define poll WSAPoll
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <mswsock.h>
#elif defined NNG_PLATFORM_POSIX
#include <poll.h>
#endif

int
nn_poll(struct nn_pollfd *fds, int nfds, int timeout)
{
// This function is rather unfortunate.  poll() is available
// on POSIX, and on Windows as WSAPoll.  On other systems it might
// not exist at all.  We could also benefit from using a notification
// that didn't have to access file descriptors... sort of access to
// the pollable element on the socket.  We don't have that, so we
// just use poll.  This function is definitely suboptimal compared to
// using callbacks.
#if defined(NNG_PLATFORM_WINDOWS) || defined(NNG_PLATFORM_POSIX)
	struct pollfd *pfd;
	int            npfd;
	int            rv;

	if ((pfd = NNI_ALLOC_STRUCTS(pfd, nfds * 2)) == NULL) {
		errno = ENOMEM;
		return (-1);
	}

	// First prepare the master polling structure.
	npfd = 0;
	for (int i = 0; i < nfds; i++) {
		int fd;
		if (fds[i].events & NN_POLLIN) {
			nng_socket s;
			s.id = fds[i].fd;
			if ((rv = nng_getopt_int(s, NNG_OPT_RECVFD, &fd)) !=
			    0) {
				nn_seterror(rv);
				NNI_FREE_STRUCTS(pfd, nfds * 2);
				return (-1);
			}
#ifdef NNG_PLATFORM_WINDOWS
			pfd[npfd].fd = (SOCKET) fd;
#else
			pfd[npfd].fd = fd;
#endif
			pfd[npfd].events = POLLIN;
			npfd++;
		}
		if (fds[i].events & NN_POLLOUT) {
			nng_socket s;
			s.id = fds[i].fd;
			if ((rv = nng_getopt_int(s, NNG_OPT_SENDFD, &fd)) !=
			    0) {
				nn_seterror(rv);
				NNI_FREE_STRUCTS(pfd, nfds * 2);
				return (-1);
			}
#ifdef NNG_PLATFORM_WINDOWS
			pfd[npfd].fd = (SOCKET) fd;
#else
			pfd[npfd].fd = fd;
#endif
			pfd[npfd].events = POLLIN;
			npfd++;
		}
	}

	rv = poll(pfd, npfd, timeout);
	if (rv < 0) {
		int e = errno;
		NNI_FREE_STRUCTS(pfd, nfds * 2);
		errno = e;
		return (-1);
	}

	// Now update the nn_poll from the system poll.
	npfd = 0;
	rv   = 0;
	for (int i = 0; i < nfds; i++) {
		fds[i].revents = 0;
		if (fds[i].events & NN_POLLIN) {
			if (pfd[npfd].revents & POLLIN) {
				fds[i].revents |= NN_POLLIN;
			}
			npfd++;
		}
		if (fds[i].events & NN_POLLOUT) {
			if (pfd[npfd].revents & POLLIN) {
				fds[i].revents |= NN_POLLOUT;
			}
			npfd++;
		}
		if (fds[i].revents) {
			rv++;
		}
	}
	NNI_FREE_STRUCTS(pfd, nfds * 2);
	return (rv);

#else // NNG_PLATFORM_WINDOWS or NNG_PLATFORM_POSIX
	NNI_ARG_UNUSED(pfds);
	NNI_ARG_UNUSED(npfd);
	NNI_ARG_UNUSED(timeout);
	errno = ENOTSUP;
	return (-1);
#endif
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

uint64_t
nn_get_statistic(int x, int y)
{
	(void) x;
	(void) y;

	return (0);
}
