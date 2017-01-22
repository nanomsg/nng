//
// Copyright 2017 Garrett D'Amore <garrett@damore.org>
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

#ifdef __cplusplus
extern "C" {
#endif

#include <errno.h>
#include <stddef.h>
#include <stdint.h>

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

#define NN_SOCKADDR_MAX		128
#define NN_SOL_SOCKET		0

// Flag for send/recv (nonblocking)
#define NN_DONTWAIT		1

// CMSG data type
#define PROTO_SP		1
#define SP_HDR			1

// Socket options
#define NN_LINGER		1
#define NN_SNDBUF		2
#define NN_RCVBUF		3
#define NN_SNDTIMEO		5
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

// Poll stuff
#define NN_POLLIN		1
#define NN_POLLOUT		2
struct nn_pollfd {
	int		fd;
	uint16_t	events;
	uint16_t	revents;
}

// Magical size for allocation
#define NN_MSG    ((size_t) -1)

struct nn_iovec {
	void *	iov_base;
	size_t	iov_len;
};

struct nn_msghdr {
	struct nn_iovec *	msg_iov;
	int			msg_iovlen;
	void *			msg_control;
	size_t			msg_controllen;
};

struct nn_cmsghdr {
	size_t	cmsg_len;
	int	cmsg_level;
	int	cmsg_type;
};

#define NN_ALIGN(len) \
	(((len) + sizeof (size_t) - 1) & (size_t) ~(sizeof (size_t) - 1))
#define NN_CMSG_FIRSTHDR(mh) \
	nn_cmsg_nexthdr((struct nn_msghdr *) (mh), NULL)
#define NN_CMSG_NEXTHDR(mh, ch)	\
	nn_cmsg_nexthdr((struct nn_msghdr *) (mh), (struct nn_cmsghdr *) ch)
#define NN_CMSG_DATA(ch) \
	((unsigned char *) (((struct cmsghdr *) (ch)) + 1))
#define NN_CMSG_SPACE(len) \
	(NN_ALIGN(len) + NN_ALIGN(sizeof (struct nn_cmsghdr)))
#define NN_CMSG_LEN(len) \
	(NN_ALIGN(sizeof (nn_cmsghdr)) + (len))

NN_DECL struct cmsg_hdr *nn_cmsg_nexthdr(const struct nn_msghdr *,
    const struct nn_cmsghdr *);
NN_DECL int nn_socket(int, int);
NN_DECL int nn_setsockopt(int, int, int, const void *, size_t);
NN_DECL int nn_getsockopt(int, int, int, void *, size_t *);
NN_DECL int nn_bind(int, const char *);
NN_DECL int nn_connect(int, const char *);
NN_DECL int nn_shutdown(int, int);
NN_DECL int nn_send(int, const void *, size_t, int);
NN_DECL int nn_recv(int, void *, size_t, int);
NN_DECL int nn_sendmsg(int, const struct nn_msghdr *, int);
NN_DECL int nn_recvcmsg(int, struct nn_msghdr *, int);
NN_DECL int nn_close(int);
NN_DECL int nn_poll(struct nn_pollfd *, int, int);
NN_DECL int nn_device(int, int);
NN_DECL uint64_t nn_get_statistic(int, int);
NN_DECL void *nn_allocmsg(size_t, int);
NN_DECL void *nn_reallocmsg(void *, size_t);
NN_DECL int nn_freemsg(void *);

#ifdef __cplusplus
}
#endif

#endif // NNG_COMPAT_H
