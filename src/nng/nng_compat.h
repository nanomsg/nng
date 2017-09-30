//
// Copyright 2017 Garrett D'Amore <garrett@damore.org>
// Copyright 2017 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#ifndef NNG_COMPAT_H
#define NNG_COMPAT_H

// This header contains interfaces that are intended to offer compatibility
// with nanomsg v1.0.  These are not the "preferred" interfaces for nng,
// and consumers should only use thse if they are porting software that
// previously used nanomsg.  New programs should use the nng native APIs.

// Note that compatibility promises are limited to public portions of the
// nanomsg API, and specifically do NOT extend to the ABI.  Furthermore,
// there may be other limitations around less commonly used portions of the
// API; for example only SP headers may be transported in control data for
// messages, there is almost no compatibility offered for statistics.
// Error values may differ from those returned by nanomsg as well; the nng
// error reporting facility expresses only a subset of the possibilities of
// nanomsg.

// Note that unlinke nanomsg, nng does not aggressively recycle socket or
// endpoint IDs, which means applications which made assumptions that these
// would be relatively small integers (e.g. to use them as array indices)
// may break.  (No promise about values was ever made.)

#ifdef __cplusplus
extern "C" {
#endif

#include <errno.h>
#include <stddef.h>
#include <stdint.h>

// clang-format gets in the way of most of this file.
// We turn it off, at least until it gets smarter about aligning
// macro definitions or we adopt enums or somesuch.
// clang-format off

// NNG_DECL is used on declarations to deal with scope.
// For building Windows DLLs, it should be the appropriate
// __declspec().  (We recommend *not* building this library
// as a DLL, but instead linking it statically for your projects
// to minimize questions about link dependencies later.)
#ifndef NN_DECL
#if defined(_WIN32) && !defined(NNG_STATIC_LIB)
#if defined(NNG_SHARED_LIB)
#define NN_DECL		__declspec(dllexport)
#else
#define NN_DECL		__declspec(dllimport)
#endif // NNG_SHARED_LIB
#else
#define NN_DECL		extern
#endif  // _WIN32 && !NNG_STATIC_LIB
#endif  // NN_DECL

#define AF_SP			1
#define AF_SP_RAW		2

// Protocol stuff
#define NN_PROTO_PAIR		1
#define NN_PROTO_PUBSUB		2
#define NN_PROTO_REQREP		3
#define NN_PROTO_PIPELINE	5
#define NN_PROTO_SURVEY		6
#define NN_PROTO_BUS		7

#define NN_PAIR			(NN_PROTO_PAIR * 16 + 0)
#define NN_PAIR_v0		(NN_PROTO_PAIR * 16 + 0)
#define NN_PAIR_V1		(NN_PROTO_PAIR * 16 + 1)
#define NN_PUB			(NN_PROTO_PUBSUB * 16 + 0)
#define NN_SUB			(NN_PROTO_PUBSUB * 16 + 1)
#define NN_REQ			(NN_PROTO_REQREP * 16 + 0)
#define NN_REP			(NN_PROTO_REQREP * 16 + 1)
#define NN_PUSH			(NN_PROTO_PIPELINE * 16 + 0)
#define NN_PULL			(NN_PROTO_PIPELINE * 16 + 1)
#define NN_SURVEYOR		(NN_PROTO_SURVEY * 16 + 2)
#define NN_RESPONDENT		(NN_PROTO_SURVEY * 16 + 3)
#define NN_BUS			(NN_PROTO_BUS * 16 + 0)

#define NN_SOCKADDR_MAX		128
#define NN_SOL_SOCKET		0

// Flag for send/recv (nonblocking)
#define NN_DONTWAIT		1

// CMSG data type
#define PROTO_SP		1
#define SP_HDR			1

// Errnos.  Legacy nanomsg uses posix errnos where possible.
// If a define is not set, use add NN_ERRBASE.  nng does not
// return all of these values, so there may be some loss of
// of information for edge cases, but we don't expect that to be
// a problem really.
#define NN_ERRBASE		(0x10000000)
#ifndef ENOTSUP
#define ENOTSUP			(NN_ERRBASE+1)
#endif
#ifndef EPROTONOSUPPORT
#define EPROTONOSUPPORT		(NN_ERRBASE+2)
#endif
#ifndef ENOBUFS
#define ENOBUFS			(NN_ERRBASE+3)
#endif
#ifndef ENETDOWN
#define ENETDOWN		(NN_ERRBASE+4)
#endif
#ifndef EADDRINUSE
#define EADDRINUSE		(NN_ERRBASE+5)
#endif
#ifndef EADDRNOTAVAIL
#define EADDRNOTAVAIL		(NN_ERRBASE+6)
#endif
#ifndef ENOTSOCK
#define ENOTSOCK		(NN_ERRBASE+7)
#endif
#ifndef EAGAIN
#define EAGAIN			(NN_ERRBASE+8)
#endif
#ifndef EBADF
#define EBADF			(NN_ERRBASE+9)
#endif
#ifndef EINVAL
#define EINVAL			(NN_ERRBASE+10)
#endif
#ifndef EMFILE
#define EMFILE			(NN_ERRBASE+11)
#endif
#ifndef EFAULT
#define EFAULT			(NN_ERRBASE+12)
#endif
#ifndef EACCES
#define EACCES			(NN_ERRBASE+13)
#endif
#ifndef ENETRESET
#define ENETRESET		(NN_ERRBASE+14)
#endif
#ifndef ENETUNREACH
#define ENETUNREACH		(NN_ERRBASE+15)
#endif
#ifndef EHOSTUNREACH
#define EHOSTUNREACH		(NN_ERRBASE+16)
#endif
#ifndef EAFNOSUPPORT
#define EAFNOSUPPORT		(NN_ERRBASE+17)
#endif
#ifndef EINPROGRESS
#define EINPROGRESS		(NN_ERRBASE+18)
#endif
#ifndef EPROTO
#define EPROTO			(NN_ERRBASE+19)
#endif
#ifndef ECONNREFUSED
#define ECONNREFUSED		(NN_ERRBASE+20)
#endif
#ifndef ENOTCONN
#define ENOTCONN		(NN_ERRBASE+21)
#endif
#ifndef EMSGSIZE
#define EMSGSIZE		(NN_ERRBASE+22)
#endif
#ifndef ETIMEDOUT
#define ETIMEDOUT		(NN_ERRBASE+23)
#endif
#ifndef ECONNABORTED
#define ECONNABORTED		(NN_ERRBASE+24)
#endif
#ifndef ECONNRESET
#define ECONNRESET		(NN_ERRBASE+25)
#endif
#ifndef ENOPROTOOPT
#define ENOPROTOOPT		(NN_ERRBASE+26)
#endif
#ifndef EISCONN
#define EISCONN			(NN_ERRBASE+27)
#endif
#ifndef ESOCKNOSUPPORT
#define ESOCKNOSPPORT		(NN_ERRBASE+28)
#endif
#ifndef ETERM
#define ETERM			(NN_ERRBASE+29)
#endif
#ifndef EFSM
#define EFSM			(NN_ERRBASE+30)
#endif
#ifndef ENOENT
#define ENOENT			(NN_ERRBASE+31)
#endif
#ifndef EIO
#define EIO			(NN_ERRBASE+32)
#endif

// Socket options
#define NN_LINGER		1
#define NN_SNDBUF		2
#define NN_RCVBUF		3
#define NN_SNDTIMEO		4
#define NN_RCVTIMEO		5
#define NN_RECONNECT_IVL	6
#define NN_RECONNECT_IVL_MAX	7
#define NN_SNDPRIO		8
#define NN_RCVPRIO		9
#define NN_SNDFD		10
#define NN_RCVFD		11
#define NN_DOMAIN		12
#define NN_PROTOCOL		13
#define NN_IPV4ONLY		14
#define NN_SOCKET_NAME		15
#define NN_RCVMAXSIZE		16
#define NN_MAXTTL		17

// Protocol-specific options.  To simplify thins we encode the protocol
// level in the option.
#define NN_SUB_SUBSCRIBE		(NN_SUB * 16 + 1)
#define NN_SUB_UNSUBSCRIBE		(NN_SUB * 16 + 2)
#define NN_REQ_RESEND_IVL		(NN_REQ * 16 + 1)
#define NN_SURVEYOR_DEADLINE		(NN_SURVEYOR * 16 + 1)

// Level options for tranports
#define NN_INPROC			(-1)
#define NN_IPC				(-2)
#define NN_IPC_SEC_ATTR			1
#define NN_IPC_OUTBUFSZ			2
#define NN_IPC_INBUFSZ			3
#define NN_TCP				(-3)
#define NN_TCP_NODELAY			1
#define NN_WS				(-4)
#define NN_WS_MSG_TYPE			1
#define NN_WS_MSG_TYPE_TEXT		1
#define NN_WS_MSG_TYPE_BINARY		2

// from this point on formatting is fine
// clang-format on

// Poll stuff
#define NN_POLLIN 1
#define NN_POLLOUT 2
struct nn_pollfd {
	int      fd;
	uint16_t events;
	uint16_t revents;
};

// Magical size for allocation
#define NN_MSG ((size_t) -1)

struct nn_iovec {
	void * iov_base;
	size_t iov_len;
};

struct nn_msghdr {
	struct nn_iovec *msg_iov;
	int              msg_iovlen;
	void *           msg_control;
	size_t           msg_controllen;
};

struct nn_cmsghdr {
	size_t cmsg_len;
	int    cmsg_level;
	int    cmsg_type;
};

#define NN_CMSG_ALIGN(len) \
	(((len) + sizeof(size_t) - 1) & (size_t) ~(sizeof(size_t) - 1))

// Unlike old nanomsg, we explicitly only support the SP header as attached
// cmsg data.  It turns out that old nanomsg didn't really store anything
// useful otherwise anyway.  (One specific exception was that it stored the
// message type of text or binary for the websocket transport.  We don't think
// anyone used that in practice though.)
#define NN_CMSG_FIRSTHDR(mh) nn_cmsg_next((struct nn_msghdr *) (mh), NULL)
#define NN_CMSG_NXTHDR(mh, ch) \
	nn_cmsg_next((struct nn_msghdr *) (mh), (struct nn_cmsghdr *) ch)
#define NN_CMSG_DATA(ch) ((unsigned char *) (((struct nn_cmsghdr *) (ch)) + 1))
#define NN_CMSG_SPACE(len) \
	(NN_CMSG_ALIGN(len) + NN_CMSG_ALIGN(sizeof(struct nn_cmsghdr)))
#define NN_CMSG_LEN(len) (NN_CMSG_ALIGN(sizeof(struct nn_cmsghdr)) + (len))

NN_DECL struct nn_cmsghdr *nn_cmsg_next(
    struct nn_msghdr *, struct nn_cmsghdr *);
NN_DECL int nn_socket(int, int);
NN_DECL int nn_setsockopt(int, int, int, const void *, size_t);
NN_DECL int nn_getsockopt(int, int, int, void *, size_t *);
NN_DECL int nn_bind(int, const char *);
NN_DECL int nn_connect(int, const char *);
NN_DECL int nn_shutdown(int, int);
NN_DECL int nn_send(int, const void *, size_t, int);
NN_DECL int nn_recv(int, void *, size_t, int);
NN_DECL int nn_sendmsg(int, const struct nn_msghdr *, int);
NN_DECL int nn_recvmsg(int, struct nn_msghdr *, int);
NN_DECL int nn_close(int);
NN_DECL int nn_poll(struct nn_pollfd *, int, int);
NN_DECL int nn_device(int, int);
NN_DECL uint64_t    nn_get_statistic(int, int);
NN_DECL void *      nn_allocmsg(size_t, int);
NN_DECL void *      nn_reallocmsg(void *, size_t);
NN_DECL int         nn_freemsg(void *);
NN_DECL int         nn_errno(void);
NN_DECL const char *nn_strerror(int);
NN_DECL void        nn_term(void);

#ifdef __cplusplus
}
#endif

#endif // NNG_COMPAT_H
