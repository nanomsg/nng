//
// Copyright 2020 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitoar.com>
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
#define NNI_ARG_UNUSED(x) ((void) x)

#ifndef NDEBUG
#define NNI_ASSERT(x) \
	if (!(x))     \
	nni_panic("%s: %d: assert err: %s", __FILE__, __LINE__, #x)
#else
#define NNI_ASSERT(x) (0)
#endif

// Returns the size of an array in elements. (Convenience.)
#define NNI_NUM_ELEMENTS(x) ((unsigned) (sizeof(x) / sizeof((x)[0])))

// These types are common but have names shared with user space.
// Internal code should use these names when possible.
typedef nng_msg           nni_msg;
typedef nng_sockaddr      nni_sockaddr;
typedef nng_url           nni_url;
typedef nng_iov           nni_iov;
typedef nng_aio           nni_aio;
typedef struct nng_event  nni_event;
typedef struct nng_notify nni_notify;

// These are our own names.
typedef struct nni_socket   nni_sock;
typedef struct nni_ctx      nni_ctx;
typedef struct nni_dialer   nni_dialer;
typedef struct nni_listener nni_listener;
typedef struct nni_pipe     nni_pipe;

typedef struct nni_tran              nni_tran;
typedef struct nni_tran_dialer_ops   nni_tran_dialer_ops;
typedef struct nni_tran_listener_ops nni_tran_listener_ops;
typedef struct nni_tran_pipe_ops     nni_tran_pipe_ops;

typedef struct nni_proto_ctx_ops  nni_proto_ctx_ops;
typedef struct nni_proto_sock_ops nni_proto_sock_ops;
typedef struct nni_proto_pipe_ops nni_proto_pipe_ops;
typedef struct nni_proto          nni_proto;

typedef struct nni_plat_mtx nni_mtx;
typedef struct nni_plat_cv  nni_cv;
typedef struct nni_thr      nni_thr;
typedef void (*nni_thr_func)(void *);

typedef int      nni_signal;   // Wakeup channel.
typedef uint64_t nni_time;     // Abs. time (ms).
typedef int32_t  nni_duration; // Rel. time (ms).

typedef void (*nni_cb)(void *);

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
#define NNI_ALLOC_STRUCT(s) nni_zalloc(sizeof(*s))
#define NNI_FREE_STRUCT(s) nni_free((s), sizeof(*s))
#define NNI_ALLOC_STRUCTS(s, n) nni_zalloc(sizeof(*s) * n)
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
	v = (((uint16_t)((uint8_t)(ptr)[0])) << 8) + \
	    (((uint16_t)(uint8_t)(ptr)[1]))

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

// This increments a pointer a fixed number of byte cells.
#define NNI_INCPTR(ptr, n) ((ptr) = (void *) ((char *) (ptr) + (n)))

// Alignment -- this is used when allocating adjacent objects to ensure
// that each object begins on a natural alignment boundary.
#define NNI_ALIGN_SIZE sizeof(void *)
#define NNI_ALIGN_MASK (NNI_ALIGN_SIZE - 1)
#define NNI_ALIGN_UP(sz) (((sz) + NNI_ALIGN_MASK) & ~NNI_ALIGN_MASK)

// A few assorted other items.
#define NNI_FLAG_IPV4ONLY 1

// Types.  These are used to provide more structured access to options
// (and maybe later statistics).  For now these are internal only.
typedef enum {
	NNI_TYPE_OPAQUE,
	NNI_TYPE_BOOL,
	NNI_TYPE_INT32,
	NNI_TYPE_UINT32,
	NNI_TYPE_INT64,
	NNI_TYPE_UINT64,
	NNI_TYPE_SIZE,
	NNI_TYPE_DURATION,
	NNI_TYPE_STRING,
	NNI_TYPE_SOCKADDR,
	NNI_TYPE_POINTER,
} nni_type;

typedef nni_type nni_opt_type;

// NNI_MAX_MAX_TTL is the maximum value that MAX_TTL can be set to -
// i.e. the number of nng_device boundaries that a message can traverse.
// This value drives the size of pre-allocated headers and back-trace
// buffers -- we need 4 bytes for each hop, plus 4 bytes for the request
// identifier.  Thus, it is recommended not to set this value too large.
// (It is possible to scale out to inconceivably large networks with
// only a few hops - we have yet to see more than 4 in practice.)
#ifndef NNI_MAX_MAX_TTL
#define NNI_MAX_MAX_TTL 15
#endif

// NNI_MAX_HEADER_SIZE is our header size.
#define NNI_MAX_HEADER_SIZE ((NNI_MAX_MAX_TTL + 1) * sizeof(uint32_t))

#endif // CORE_DEFS_H
