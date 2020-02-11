//
// Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#ifndef NNG_COMPAT_NN_H
#define NNG_COMPAT_NN_H

// This header contains interfaces that are intended to offer compatibility
// with nanomsg v1.0.  These are not the "preferred" interfaces for nng,
// and consumers should only use these if they are porting software that
// previously used nanomsg.  New programs should use the nng native APIs.

// Note that compatibility promises are limited to public portions of the
// nanomsg API, and specifically do NOT extend to the ABI.  Furthermore,
// there may be other limitations around less commonly used portions of the
// API; for example only SP headers may be transported in control data for
// messages, there is almost no compatibility offered for statistics.
// Error values may differ from those returned by nanomsg as well; the nng
// error reporting facility expresses only a subset of the possibilities of
// nanomsg.

// Note that unlike nanomsg, nng does not aggressively recycle socket or
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
// For building Windows DLLs, it should be the appropriate __declspec().
// For shared libraries with platforms that support hidden visibility,
// it should evaluate to __attribute__((visibility("default"))).
#ifndef NN_DECL
#if defined(_WIN32) && !defined(NNG_STATIC_LIB)
#if defined(NNG_SHARED_LIB)
#define NN_DECL		__declspec(dllexport)
#else
#define NN_DECL		__declspec(dllimport)
#endif // NNG_SHARED_LIB
#else
#if defined(NNG_SHARED_LIB) && defined(NNG_HIDDEN_VISIBILITY)
#define NN_DECL __attribute__((visibility("default")))
#else
#define NN_DECL extern
#endif
#endif // _WIN32 && !NNG_STATIC_LIB
#endif  // NN_DECL

#define AF_SP			1
#define AF_SP_RAW		2

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
#ifndef EEXIST
#define EEXIST			(NN_ERRBASE+33)
#endif
#ifndef ENOSPC
#define ENOSPC			(NN_ERRBASE+34)
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

#endif // NNG_COMPAT_NN_H
