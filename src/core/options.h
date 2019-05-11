//
// Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
// Copyright 2018 Devolutions <info@devolutions.net>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#ifndef CORE_OPTIONS_H
#define CORE_OPTIONS_H

// Integer limits.
#define NNI_MAXINT ((int) 2147483647)
#define NNI_MININT ((int) -2147483648)

// We limit the maximum size to 4GB.  That's intentional because some of the
// underlying protocols cannot cope with anything bigger than 32-bits.
#define NNI_MINSZ (0)
#define NNI_MAXSZ ((size_t) 0xffffffff)

// Option helpers.  These can be called from protocols or transports
// in their own option handling, centralizing the logic for dealing with
// variable sized options.

extern int nni_copyin_ms(nni_duration *, const void *, size_t, nni_type);
extern int nni_copyin_bool(bool *, const void *, size_t, nni_type);
extern int nni_copyin_int(int *, const void *, size_t, int, int, nni_type);
extern int nni_copyin_size(
    size_t *, const void *, size_t, size_t, size_t, nni_type);
extern int nni_copyin_str(char *, const void *, size_t, size_t, nni_type);
extern int nni_copyin_ptr(void **, const void *, size_t, nni_type);
extern int nni_copyin_u64(uint64_t *, const void *, size_t, nni_type);
extern int nni_copyin_sockaddr(nng_sockaddr *, const void *, size_t, nni_type);

// nni_copyout_xxx copies out a type of the named value.  It assumes that
// the type is aligned and the size correct, unless NNI_TYPE_OPAQUE is passed.
extern int nni_copyout(const void *, size_t, void *, size_t *);
extern int nni_copyout_bool(bool, void *, size_t *, nni_type);
extern int nni_copyout_int(int, void *, size_t *, nni_type);
extern int nni_copyout_ms(nng_duration, void *, size_t *, nni_type);
extern int nni_copyout_ptr(void *, void *, size_t *, nni_type);
extern int nni_copyout_size(size_t, void *, size_t *, nni_type);
extern int nni_copyout_sockaddr(
    const nng_sockaddr *, void *, size_t *, nni_type);
extern int nni_copyout_u64(uint64_t, void *, size_t *, nni_type);

// nni_copyout_str copies out a string.  If the type is NNI_TYPE_STRING,
// then it passes through a pointer, created by nni_strdup().
extern int nni_copyout_str(const char *, void *, size_t *, nni_type);

// nni_option is used for socket, protocol, transport, and similar options.
// Note that only for transports, the o_set member may be called with a NULL
// instance parameter, in which case the request should only validate the
// argument and do nothing further.
typedef struct nni_option_s nni_option;
struct nni_option_s {
	// o_name is the name of the option.
	const char *o_name;

	// o_get is used to retrieve the value of the option.  The
	// size supplied will limit how much data is copied.  Regardless,
	// the actual size of the object that would have been copied
	// is supplied by the function in the size.  If the object did
	// not fit, then NNG_EINVAL is returned.
	int (*o_get)(void *, void *, size_t *, nni_type);

	// o_set is used to set the value of the option.  For transport
	// endpoints only, the instance parameter (first argument) may be
	// NULL, in which case only a generic validation of the parameters
	// is performed.  (This is used when setting socket options before
	int (*o_set)(void *, const void *, size_t, nni_type);
};

typedef struct nni_chkoption_s nni_chkoption;
struct nni_chkoption_s {
	const char *o_name;
	// o_check can be NULL for read-only options
	int (*o_check)(const void *, size_t, nni_type);
};

// nni_getopt and nni_setopt are helper functions to implement options
// based on arrays of nni_option structures.
extern int nni_getopt(
    const nni_option *, const char *, void *, void *, size_t *, nni_type);
extern int nni_setopt(
    const nni_option *, const char *, void *, const void *, size_t, nni_type);
extern int nni_chkopt(
    const nni_chkoption *, const char *, const void *, size_t, nni_type);

//
// This next block sets up to define the various typed option functions.
// To make it easier to cover them all at once, we use macros.
//

#define NNI_DEFGET(base, pointer)                                        \
	int nng_##base##_get(                                                \
	    nng_##base pointer s, const char *nm, void *vp, size_t *szp)     \
	{                                                                    \
		return (nni_##base##_getx(s, nm, vp, szp, NNI_TYPE_OPAQUE)); \
	}

#define NNI_DEFTYPEDGET(base, suffix, pointer, type, nnitype)    \
	int nng_##base##_get_##suffix(                               \
	    nng_##base pointer s, const char *nm, type *vp)          \
	{                                                            \
		size_t sz = sizeof(*vp);                             \
		return (nni_##base##_getx(s, nm, vp, &sz, nnitype)); \
	}

#define NNI_DEFGETALL(base)                                      \
	NNI_DEFGET(base, )                                           \
	NNI_DEFTYPEDGET(base, int, , int, NNI_TYPE_INT32)            \
	NNI_DEFTYPEDGET(base, bool, , bool, NNI_TYPE_BOOL)           \
	NNI_DEFTYPEDGET(base, size, , size_t, NNI_TYPE_SIZE)         \
	NNI_DEFTYPEDGET(base, uint64, , uint64_t, NNI_TYPE_UINT64)   \
	NNI_DEFTYPEDGET(base, string, , char *, NNI_TYPE_STRING)     \
	NNI_DEFTYPEDGET(base, ptr, , void *, NNI_TYPE_POINTER)       \
	NNI_DEFTYPEDGET(base, ms, , nng_duration, NNI_TYPE_DURATION) \
	NNI_DEFTYPEDGET(base, addr, , nng_sockaddr, NNI_TYPE_SOCKADDR)

#define NNI_DEFGETALL_PTR(base)                                        \
	NNI_DEFGET(base, *)                                           \
	NNI_DEFTYPEDGET(base, int, *, int, NNI_TYPE_INT32)            \
	NNI_DEFTYPEDGET(base, bool, *, bool, NNI_TYPE_BOOL)           \
	NNI_DEFTYPEDGET(base, size, *, size_t, NNI_TYPE_SIZE)         \
	NNI_DEFTYPEDGET(base, uint64, *, uint64_t, NNI_TYPE_UINT64)   \
	NNI_DEFTYPEDGET(base, string, *, char *, NNI_TYPE_STRING)     \
	NNI_DEFTYPEDGET(base, ptr, *, void *, NNI_TYPE_POINTER)       \
	NNI_DEFTYPEDGET(base, ms, *, nng_duration, NNI_TYPE_DURATION) \
	NNI_DEFTYPEDGET(base, addr, *, nng_sockaddr, NNI_TYPE_SOCKADDR)

#define NNI_DEFSET(base, pointer)                                              \
	int nng_##base##_set(                                                      \
	    nng_##base pointer s, const char *nm, const void *vp, size_t sz)       \
	{                                                                   \
		return (nni_##base##_setx(s, nm, vp, sz, NNI_TYPE_OPAQUE));     \
	}

#define NNI_DEFTYPEDSETEX(base, suffix, pointer, type, len, nnitype) \
	int nng_##base##_set_##suffix(                                   \
        nng_##base pointer s, const char *nm, type v)                \
	{                                                                \
		return (nni_##base##_setx(s, nm, &v, len, nnitype));         \
	}

#define NNI_DEFTYPEDSET(base, suffix, pointer, type, nnitype)         \
	int nng_##base##_set_##suffix(                                    \
		nng_##base pointer s, const char *nm, type v)                 \
	{                                                                 \
		return (nni_##base##_setx(s, nm, &v, sizeof(v), nnitype));    \
	}

#define NNI_DEFSTRINGSET(base, pointer)                           \
	int nng_##base##_set_string(                                  \
	    nng_##base pointer s, const char *nm, const char *v)      \
	{                                                             \
		return (nni_##base##_setx(s, nm, v,                   \
		    v != NULL ? strlen(v) + 1 : 0, NNI_TYPE_STRING)); \
	}

#define NNI_DEFSOCKADDRSET(base, pointer)                            \
	int nng_##base##_set_addr(                                       \
	    nng_##base pointer s, const char *nm, const nng_sockaddr *v) \
	{                                                                \
		return (nni_##base##_setx(                        \
		    s, nm, v, sizeof(*v), NNI_TYPE_SOCKADDR));    \
	}

#define NNI_DEFSETALL(base)                                      \
	NNI_DEFSET(base, )                                           \
	NNI_DEFTYPEDSET(base, int, , int, NNI_TYPE_INT32)            \
	NNI_DEFTYPEDSET(base, bool, , bool, NNI_TYPE_BOOL)           \
	NNI_DEFTYPEDSET(base, size, , size_t, NNI_TYPE_SIZE)         \
	NNI_DEFTYPEDSET(base, uint64, , uint64_t, NNI_TYPE_UINT64)   \
	NNI_DEFTYPEDSET(base, ms, , nng_duration, NNI_TYPE_DURATION) \
	NNI_DEFTYPEDSET(base, ptr, , void *, NNI_TYPE_POINTER)       \
	NNI_DEFSTRINGSET(base, )                                     \
	NNI_DEFSOCKADDRSET(base, )

#define NNI_DEFSETALL_PTR(base)                                   \
	NNI_DEFSET(base, *)                                           \
	NNI_DEFTYPEDSET(base, int, *, int, NNI_TYPE_INT32)            \
	NNI_DEFTYPEDSET(base, bool, *, bool, NNI_TYPE_BOOL)           \
	NNI_DEFTYPEDSET(base, size, *, size_t, NNI_TYPE_SIZE)         \
	NNI_DEFTYPEDSET(base, uint64, *, uint64_t, NNI_TYPE_UINT64)   \
	NNI_DEFTYPEDSET(base, ms, *, nng_duration, NNI_TYPE_DURATION) \
	NNI_DEFTYPEDSET(base, ptr, *, void *, NNI_TYPE_POINTER)       \
	NNI_DEFSTRINGSET(base, *)                                     \
	NNI_DEFSOCKADDRSET(base, *)

#define NNI_LEGACY_DEFGET(base)                                  \
	int nng_##base##_getopt(                                     \
	    nng_##base s, const char *nm, void *vp, size_t *szp)     \
	{                                                            \
		return (nng_##base##_get(s, nm, vp, szp)); \
	}

#define NNI_LEGACY_DEFTYPEDGET(base, suffix, type)              \
	int nng_##base##_getopt_##suffix(                           \
	    nng_##base s, const char *nm, type *vp)                 \
	{                                                           \
		return (nng_##base##_get_##suffix(s, nm, vp)); \
	}

#define NNI_LEGACY_DEFSOCKADDRGET(base)                         \
	int nng_##base##_getopt_sockaddr(                           \
	    nng_##base s, const char *nm, nng_sockaddr *vp)         \
	{                                                           \
		return (nng_##base##_get_addr(s, nm, vp)); \
	}

#define NNI_LEGACY_DEFGETALL(base)                              \
	NNI_LEGACY_DEFGET(base)                                     \
	NNI_LEGACY_DEFTYPEDGET(base, int, int)                      \
	NNI_LEGACY_DEFTYPEDGET(base, bool, bool)                    \
	NNI_LEGACY_DEFTYPEDGET(base, size, size_t)                  \
	NNI_LEGACY_DEFTYPEDGET(base, uint64, uint64_t)              \
	NNI_LEGACY_DEFTYPEDGET(base, string, char *)                \
	NNI_LEGACY_DEFTYPEDGET(base, ptr, void *)                   \
	NNI_LEGACY_DEFTYPEDGET(base, ms, nng_duration)              \
	NNI_LEGACY_DEFSOCKADDRGET(base)

#define NNI_LEGACY_DEFSET(base)                                    \
	int nng_##base##_setopt(                                       \
	    nng_##base s, const char *nm, const void *vp, size_t sz)   \
	{                                                              \
		return (nng_##base##_set(s, nm, vp, sz)); \
	}

#define NNI_LEGACY_DEFTYPEDSET(base, suffix, type)                         \
	int nng_##base##_setopt_##suffix(nng_##base s, const char *nm, type v) \
	{                                                                      \
		return (nng_##base##_set_##suffix(s, nm, v));   \
	}

#define NNI_LEGACY_DEFSTRINGSET(base)                          \
	int nng_##base##_setopt_string(                            \
	    nng_##base s, const char *nm, const char *v)           \
	{                                                          \
		return (nng_##base##_set_string(s, nm, v)); \
	}

#define NNI_LEGACY_DEFSOCKADDRSET(base)                         \
	int nng_##base##_setopt_sockaddr(                           \
	    nng_##base s, const char *nm, const nng_sockaddr *v)    \
	{                                                           \
		return (nng_##base##_set_addr(s, nm, v));    \
	}

#define NNI_LEGACY_DEFSETALL(base)                    \
	NNI_LEGACY_DEFSET(base)                           \
	NNI_LEGACY_DEFTYPEDSET(base, int, int)            \
	NNI_LEGACY_DEFTYPEDSET(base, bool, bool)          \
	NNI_LEGACY_DEFTYPEDSET(base, size, size_t)        \
	NNI_LEGACY_DEFTYPEDSET(base, uint64, uint64_t)    \
	NNI_LEGACY_DEFTYPEDSET(base, ms, nng_duration)    \
	NNI_LEGACY_DEFTYPEDSET(base, ptr, void*)          \
	NNI_LEGACY_DEFSTRINGSET(base)                     \
	NNI_LEGACY_DEFSOCKADDRSET(base)

#endif // CORE_OPTIONS_H
