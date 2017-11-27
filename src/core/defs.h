//
// Copyright 2017 Garrett D'Amore <garrett@damore.org>
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
#define NNI_ARG_UNUSED(x) ((void) x);

#ifndef NDEBUG
#define NNI_ASSERT(x) \
	if (!(x))     \
	nni_panic("%s: %d: assert err: %s", __FILE__, __LINE__, #x)
#else
#define NNI_ASSERT(x)
#endif

// Returns the size of an array in elements. (Convenience.)
#define NNI_NUM_ELEMENTS(x) (sizeof(x) / sizeof((x)[0]))

// These types are common but have names shared with user space.
typedef struct nng_msg      nni_msg;
typedef struct nng_sockaddr nni_sockaddr;
typedef struct nng_event    nni_event;
typedef struct nng_notify   nni_notify;

// These are our own names.
typedef struct nni_socket           nni_sock;
typedef struct nni_ep               nni_ep;
typedef struct nni_pipe             nni_pipe;
typedef struct nni_tran             nni_tran;
typedef struct nni_tran_ep          nni_tran_ep;
typedef struct nni_tran_ep_option   nni_tran_ep_option;
typedef struct nni_tran_pipe        nni_tran_pipe;
typedef struct nni_tran_pipe_option nni_tran_pipe_option;

typedef struct nni_proto_sock_ops    nni_proto_sock_ops;
typedef struct nni_proto_pipe_ops    nni_proto_pipe_ops;
typedef struct nni_proto_sock_option nni_proto_sock_option;
typedef struct nni_proto             nni_proto;

typedef struct nni_plat_mtx nni_mtx;
typedef struct nni_plat_cv  nni_cv;
typedef struct nni_idhash   nni_idhash;
typedef struct nni_thr      nni_thr;
typedef void (*nni_thr_func)(void *);

typedef int      nni_signal;   // Wakeup channel.
typedef uint64_t nni_time;     // Abs. time (ms).
typedef int32_t  nni_duration; // Rel. time (ms).

typedef struct nni_aio nni_aio;

typedef void (*nni_cb)(void *);

// Used by transports for scatter gather I/O.
typedef struct {
	uint8_t *iov_buf;
	size_t   iov_len;
} nni_iov;

// Notify descriptor.
typedef struct {
	int sn_wfd; // written to in order to flag an event
	int sn_rfd; // read from in order to clear an event
	int sn_init;
} nni_notifyfd;

// Some default timing things.
#define NNI_TIME_NEVER ((nni_time) -1)
#define NNI_TIME_ZERO ((nni_time) 0)
#define NNI_SECOND (1000)

// Structure allocation conveniences.
#define NNI_ALLOC_STRUCT(s) nni_alloc(sizeof(*s))
#define NNI_FREE_STRUCT(s) nni_free((s), sizeof(*s))
#define NNI_ALLOC_STRUCTS(s, n) nni_alloc(sizeof(*s) * n)
#define NNI_FREE_STRUCTS(s, n) nni_free(s, sizeof(*s) * n)

#define NNI_PUT16(ptr, u)                                   \
	do {                                                \
		(ptr)[0] = (uint8_t)(((uint16_t)(u)) >> 8); \
		(ptr)[1] = (uint8_t)((uint16_t)(u));        \
	} while (0)

#define NNI_PUT32(ptr, u)                                    \
	do {                                                 \
		(ptr)[0] = (uint8_t)(((uint32_t)(u)) >> 24); \
		(ptr)[1] = (uint8_t)(((uint32_t)(u)) >> 16); \
		(ptr)[2] = (uint8_t)(((uint32_t)(u)) >> 8);  \
		(ptr)[3] = (uint8_t)((uint32_t)(u));         \
	} while (0)

#define NNI_PUT64(ptr, u)                                    \
	do {                                                 \
		(ptr)[0] = (uint8_t)(((uint64_t)(u)) >> 56); \
		(ptr)[1] = (uint8_t)(((uint64_t)(u)) >> 48); \
		(ptr)[2] = (uint8_t)(((uint64_t)(u)) >> 40); \
		(ptr)[3] = (uint8_t)(((uint64_t)(u)) >> 32); \
		(ptr)[4] = (uint8_t)(((uint64_t)(u)) >> 24); \
		(ptr)[5] = (uint8_t)(((uint64_t)(u)) >> 16); \
		(ptr)[6] = (uint8_t)(((uint64_t)(u)) >> 8);  \
		(ptr)[7] = (uint8_t)((uint64_t)(u));         \
	} while (0)

#define NNI_GET16(ptr, v)                            \
	v = (((uint32_t)((uint8_t)(ptr)[0])) << 8) + \
	    (((uint32_t)(uint8_t)(ptr)[1]))

#define NNI_GET32(ptr, v)                             \
	v = (((uint32_t)((uint8_t)(ptr)[0])) << 24) + \
	    (((uint32_t)((uint8_t)(ptr)[1])) << 16) + \
	    (((uint32_t)((uint8_t)(ptr)[2])) << 8) +  \
	    (((uint32_t)(uint8_t)(ptr)[3]))

#define NNI_GET64(ptr, v)                             \
	v = (((uint64_t)((uint8_t)(ptr)[0])) << 56) + \
	    (((uint64_t)((uint8_t)(ptr)[1])) << 48) + \
	    (((uint64_t)((uint8_t)(ptr)[2])) << 40) + \
	    (((uint64_t)((uint8_t)(ptr)[3])) << 32) + \
	    (((uint64_t)((uint8_t)(ptr)[4])) << 24) + \
	    (((uint64_t)((uint8_t)(ptr)[5])) << 16) + \
	    (((uint64_t)((uint8_t)(ptr)[6])) << 8) +  \
	    (((uint64_t)(uint8_t)(ptr)[7]))

// A few assorted other items.
#define NNI_FLAG_IPV4ONLY 1

#endif // CORE_DEFS_H
