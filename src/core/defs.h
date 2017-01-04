//
// Copyright 2016 Garrett D'Amore <garrett@damore.org>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#ifndef CORE_DEFS_H
#define CORE_DEFS_H

#include <stdint.h>

// C compilers may get unhappy when named arguments are not used.  While
// there are things like __attribute__((unused)) which are arguably
// superior, support for such are not universal.
#define NNI_ARG_UNUSED(x)    ((void) x);

// These types are common but have names shared with user space.
typedef struct nng_socket	nni_sock;
typedef struct nng_endpoint	nni_ep;
typedef struct nng_pipe		nni_pipe;
typedef struct nng_msg		nni_msg;
typedef struct nng_sockaddr	nni_sockaddr;

// These are our own names.
typedef struct nni_tran		nni_tran;
typedef struct nni_tran_ep	nni_tran_ep;
typedef struct nni_tran_pipe	nni_tran_pipe;

typedef struct nni_proto_pipe	nni_proto_pipe;
typedef struct nni_proto	nni_proto;


typedef int			nni_signal;     // Turnstile/wakeup channel.
typedef uint64_t		nni_time;       // Absolute time (usec).
typedef int64_t			nni_duration;   // Relative time (usec).

// Used by transports for scatter gather I/O.
typedef struct {
	void *	iov_buf;
	size_t	iov_len;
} nni_iov;

// Some default timing things.
#define NNI_TIME_NEVER		((nni_time) -1)
#define NNI_TIME_ZERO		((nni_time) 0)
#define NNI_SECOND		(1000000)

// Structure allocation conveniences.
#define NNI_ALLOC_STRUCT(s)	nni_alloc(sizeof (*s))
#define NNI_FREE_STRUCT(s)	nni_free((s), sizeof (*s))

#define NNI_PUT32(ptr, u)				   \
	do {						   \
		ptr[0] = (uint8_t) (((uint32_t) u) >> 24); \
		ptr[1] = (uint8_t) (((uint32_t) u) >> 16); \
		ptr[2] = (uint8_t) (((uint32_t) u) >> 8);  \
		ptr[3] = (uint8_t) ((uint32_t) u);	   \
	}						   \
	while (0)

#define NNI_PUT64(ptr, u)				   \
	do {						   \
		ptr[0] = (uint8_t) (((uint64_t) u) >> 56); \
		ptr[1] = (uint8_t) (((uint64_t) u) >> 48); \
		ptr[2] = (uint8_t) (((uint64_t) u) >> 40); \
		ptr[3] = (uint8_t) (((uint64_t) u) >> 32); \
		ptr[4] = (uint8_t) (((uint64_t) u) >> 24); \
		ptr[5] = (uint8_t) (((uint64_t) u) >> 16); \
		ptr[6] = (uint8_t) (((uint64_t) u) >> 8);  \
		ptr[7] = (uint8_t) ((uint64_t) u);	   \
	}						   \
	while (0)

#define NNI_GET32(ptr, v)			      \
	v = (((uint32_t) ((uint8_t) ptr[0])) << 24) + \
	    (((uint32_t) ((uint8_t) ptr[1])) << 16) + \
	    (((uint32_t) ((uint8_t) ptr[2])) << 8) +  \
	    (((uint32_t) (uint8_t) ptr[3]))

#define NNI_GET64(ptr, v)			      \
	v = (((uint64_t) ((uint8_t) ptr[0])) << 56) + \
	    (((uint64_t) ((uint8_t) ptr[1])) << 48) + \
	    (((uint64_t) ((uint8_t) ptr[2])) << 40) + \
	    (((uint64_t) ((uint8_t) ptr[3])) << 32) + \
	    (((uint64_t) ((uint8_t) ptr[4])) << 24) + \
	    (((uint64_t) ((uint8_t) ptr[5])) << 16) + \
	    (((uint64_t) ((uint8_t) ptr[6])) << 8) +  \
	    (((uint64_t) (uint8_t) ptr[7]))

// A few assorted other items.
#define NNI_FLAG_IPV4ONLY    1

#endif  // CORE_DEFS_H
