//
// Copyright 2025 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitoar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#ifndef CORE_DEFS_H
#define CORE_DEFS_H

#include <stdbool.h>
#include <stdint.h>

#include <nng/nng.h>

// C compilers may get unhappy when named arguments are not used.  While
// there are things like __attribute__((unused)) which are arguably
// superior, support for such are not universal.
#define NNI_ARG_UNUSED(x) ((void) x)

#ifndef NDEBUG
#define NNI_ASSERT(x) \
	if (!(x))     \
	nni_panic("%s: %d: assert err: %s", __FILE__, __LINE__, #x)
#else
#define NNI_ASSERT(x) ((void) (0))
#endif

// Returns the size of an array in elements. (Convenience.)
#define NNI_NUM_ELEMENTS(x) ((unsigned) (sizeof(x) / sizeof((x)[0])))

// These types are common but have names shared with user space.
// Internal code should use these names when possible.
typedef nng_msg      nni_msg;
typedef nng_sockaddr nni_sockaddr;
typedef nng_iov      nni_iov;
typedef nng_aio      nni_aio;

// These are our own names.
typedef struct nni_socket   nni_sock;
typedef struct nni_ctx      nni_ctx;
typedef struct nni_dialer   nni_dialer;
typedef struct nni_listener nni_listener;
typedef struct nni_pipe     nni_pipe;

typedef struct nni_sp_tran         nni_sp_tran;
typedef struct nni_sp_dialer_ops   nni_sp_dialer_ops;
typedef struct nni_sp_listener_ops nni_sp_listener_ops;
typedef struct nni_sp_pipe_ops     nni_sp_pipe_ops;

typedef struct nni_proto_ctx_ops  nni_proto_ctx_ops;
typedef struct nni_proto_sock_ops nni_proto_sock_ops;
typedef struct nni_proto_pipe_ops nni_proto_pipe_ops;
typedef struct nni_proto          nni_proto;

typedef struct nni_plat_mtx nni_mtx;
typedef struct nni_plat_cv  nni_cv;
typedef struct nni_thr      nni_thr;
typedef void (*nni_thr_func)(void *);

typedef uint64_t nni_time;     // Abs. time (ms).
typedef int32_t  nni_duration; // Rel. time (ms).

typedef void (*nni_cb)(void *);

// Some default timing things.
#define NNI_TIME_NEVER ((nni_time) - 1)
#define NNI_TIME_ZERO ((nni_time) 0)
#define NNI_SECOND (1000)

// Structure allocation conveniences.
#define NNI_ALLOC_STRUCT(s) nni_zalloc(sizeof(*s))
#define NNI_FREE_STRUCT(s) nni_free((s), sizeof(*s))
#define NNI_ALLOC_STRUCTS(s, n) nni_zalloc(sizeof(*s) * n)
#define NNI_FREE_STRUCTS(s, n) nni_free(s, sizeof(*s) * n)

#define NNI_PUT16(ptr, u)                                      \
	do {                                                   \
		(ptr)[0] = (uint8_t) (((uint16_t) (u)) >> 8u); \
		(ptr)[1] = (uint8_t) ((uint16_t) (u));         \
	} while (0)

#define NNI_PUT32(ptr, u)                                       \
	do {                                                    \
		(ptr)[0] = (uint8_t) (((uint32_t) (u)) >> 24u); \
		(ptr)[1] = (uint8_t) (((uint32_t) (u)) >> 16u); \
		(ptr)[2] = (uint8_t) (((uint32_t) (u)) >> 8u);  \
		(ptr)[3] = (uint8_t) ((uint32_t) (u));          \
	} while (0)

#define NNI_PUT64(ptr, u)                                       \
	do {                                                    \
		(ptr)[0] = (uint8_t) (((uint64_t) (u)) >> 56u); \
		(ptr)[1] = (uint8_t) (((uint64_t) (u)) >> 48u); \
		(ptr)[2] = (uint8_t) (((uint64_t) (u)) >> 40u); \
		(ptr)[3] = (uint8_t) (((uint64_t) (u)) >> 32u); \
		(ptr)[4] = (uint8_t) (((uint64_t) (u)) >> 24u); \
		(ptr)[5] = (uint8_t) (((uint64_t) (u)) >> 16u); \
		(ptr)[6] = (uint8_t) (((uint64_t) (u)) >> 8u);  \
		(ptr)[7] = (uint8_t) ((uint64_t) (u));          \
	} while (0)

#define NNI_GET16(ptr, v)                                   \
	v = (((uint16_t) (((uint8_t *) (ptr))[0])) << 8u) + \
	    ((uint16_t) ((uint8_t *) (ptr))[1])

#define NNI_GET32(ptr, v)                                  \
	v = (((uint32_t) ((uint8_t *) (ptr))[0]) << 24u) + \
	    (((uint32_t) ((uint8_t *) (ptr))[1]) << 16u) + \
	    (((uint32_t) ((uint8_t *) (ptr))[2]) << 8u) +  \
	    ((uint32_t) ((uint8_t *) (ptr))[3])

#define NNI_GET64(ptr, v)                                  \
	v = (((uint64_t) ((uint8_t *) (ptr))[0]) << 56u) + \
	    (((uint64_t) ((uint8_t *) (ptr))[1]) << 48u) + \
	    (((uint64_t) ((uint8_t *) (ptr))[2]) << 40u) + \
	    (((uint64_t) ((uint8_t *) (ptr))[3]) << 32u) + \
	    (((uint64_t) ((uint8_t *) (ptr))[4]) << 24u) + \
	    (((uint64_t) ((uint8_t *) (ptr))[5]) << 16u) + \
	    (((uint64_t) ((uint8_t *) (ptr))[6]) << 8u) +  \
	    ((uint64_t) ((uint8_t *) (ptr))[7])

// Modern CPUs are all little endian.  Let's stop paying the endian tax.

#define NNI_PUT16LE(ptr, u)                                    \
	do {                                                   \
		((uint8_t *)ptr)[1] = (uint8_t) (((uint16_t) (u)) >> 8u); \
		((uint8_t *)ptr)[0] = (uint8_t) ((uint16_t) (u));         \
	} while (0)

#define NNI_PUT32LE(ptr, u)                                     \
	do {                                                    \
		((uint8_t *)ptr)[3] = (uint8_t) (((uint32_t) (u)) >> 24u); \
		((uint8_t *)ptr)[2] = (uint8_t) (((uint32_t) (u)) >> 16u); \
		((uint8_t *)ptr)[1] = (uint8_t) (((uint32_t) (u)) >> 8u);  \
		((uint8_t *)ptr)[0] = (uint8_t) ((uint32_t) (u));          \
	} while (0)

#define NNI_PUT64LE(ptr, u)                                     \
	do {                                                    \
		((uint8_t *)ptr)[7] = (uint8_t) (((uint64_t) (u)) >> 56u); \
		((uint8_t *)ptr)[6] = (uint8_t) (((uint64_t) (u)) >> 48u); \
		((uint8_t *)ptr)[5] = (uint8_t) (((uint64_t) (u)) >> 40u); \
		((uint8_t *)ptr)[4] = (uint8_t) (((uint64_t) (u)) >> 32u); \
		((uint8_t *)ptr)[3] = (uint8_t) (((uint64_t) (u)) >> 24u); \
		((uint8_t *)ptr)[2] = (uint8_t) (((uint64_t) (u)) >> 16u); \
		((uint8_t *)ptr)[1] = (uint8_t) (((uint64_t) (u)) >> 8u);  \
		((uint8_t *)ptr)[0] = (uint8_t) ((uint64_t) (u));          \
	} while (0)

#define NNI_GET16LE(ptr, v)                                 \
	v = (((uint16_t) (((uint8_t *) (ptr))[1])) << 8u) + \
	    ((uint16_t) ((uint8_t *) (ptr))[0])

#define NNI_GET32LE(ptr, v)                                  \
	v = (((uint32_t) (((uint8_t *) (ptr))[3])) << 24u) + \
	    (((uint32_t) (((uint8_t *) (ptr))[2])) << 16u) + \
	    (((uint32_t) (((uint8_t *) (ptr))[1])) << 8u) +  \
	    (((uint32_t) ((uint8_t *) (ptr))[0]))

#define NNI_GET64LE(ptr, v)                                  \
	v = (((uint64_t) (((uint8_t *) (ptr))[7])) << 56u) + \
	    (((uint64_t) (((uint8_t *) (ptr))[6])) << 48u) + \
	    (((uint64_t) (((uint8_t *) (ptr))[5])) << 40u) + \
	    (((uint64_t) (((uint8_t *) (ptr))[4])) << 32u) + \
	    (((uint64_t) (((uint8_t *) (ptr))[3])) << 24u) + \
	    (((uint64_t) (((uint8_t *) (ptr))[2])) << 16u) + \
	    (((uint64_t) (((uint8_t *) (ptr))[1])) << 8u) +  \
	    (((uint64_t) ((uint8_t *) (ptr))[0]))

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
	NNI_TYPE_NONE, // DO NOT USE
	NNI_TYPE_BOOL,
	NNI_TYPE_INT32,
	NNI_TYPE_SIZE,
	NNI_TYPE_DURATION,
	NNI_TYPE_STRING,
	NNI_TYPE_SOCKADDR,
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

// NNI_EXPIRE_BATCH lets us handle expiration in batches,
// reducing the number of traverses of the expiration list we perform.
#ifndef NNI_EXPIRE_BATCH
#define NNI_EXPIRE_BATCH 100
#endif

#if __GNUC__ > 3
// NNI_GCC_VERSION is used to indicate a GNU version.  It is used
// to trigger certain cases like atomics that might be compiler specific.
#define NNI_GCC_VERSION \
	(__GNUC__ * 10000 + __GNUC_MINOR__ * 100 + __GNUC_PATCHLEVEL__)
#endif

#if !defined(NNG_BIG_ENDIAN) && !defined(NNG_LITTLE_ENDIAN)
#if defined(__BYTE_ORDER__)
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define NNG_BIG_ENDIAN 1
#elif __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define NNG_LITTLE_ENDIAN 1
#else // middle-endian? (aka PDP-11)
#error "Unsupported or unknown endian"
#endif // __BYTE_ORDER__
#else  // defined(__BYTE_ORDER__)
#define NNG_LITTLE_ENDIAN 1
#error "Unknown endian: specify -DNNG_BIG_ENDIAN=1 or -DNNG_LITTLE_ENDIAN=1"
#endif // defined(__BYTE_ORDER)
#endif // defined() endianness

// nni_alloc allocates memory.  In most cases this can just be malloc().
// However, you may provide a different allocator, for example it is
// possible to use a slab allocator or somesuch.  It is permissible for this
// to return NULL if memory cannot be allocated.
extern void *nni_alloc(size_t);

// nni_zalloc is just like nni_alloc, but ensures that memory is
// initialized to zero.  It is a separate function because some platforms
// can use a more efficient zero-based allocation.
extern void *nni_zalloc(size_t);

// nni_free frees memory allocated with nni_alloc or nni_zalloc. It takes
// a size because some allocators do not track size, or can operate more
// efficiently if the size is provided with the free call.  Examples of this
// are slab allocators like this found in Solaris/illumos (see libumem).
// This routine does nothing if supplied with a NULL pointer and zero size.
// Most implementations can just call free() here.
extern void nni_free(void *, size_t);

#endif // CORE_DEFS_H
