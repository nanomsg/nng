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

// nni_getopt and nni_setopt are helper functions to implement options
// based on arrays of nni_option structures.
extern int nni_getopt(
    const nni_option *, const char *, void *, void *, size_t *, nni_type);
extern int nni_setopt(
    const nni_option *, const char *, void *, const void *, size_t, nni_type);

#endif // CORE_OPTIONS_H
