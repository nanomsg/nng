//
// Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
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

extern int nni_copyin_ms(nni_duration *, const void *, size_t, nni_opt_type);
extern int nni_copyin_bool(bool *, const void *, size_t, nni_opt_type);
extern int nni_copyin_int(int *, const void *, size_t, int, int, nni_opt_type);
extern int nni_copyin_size(
    size_t *, const void *, size_t, size_t, size_t, nni_opt_type);
extern int nni_copyin_str(char *, const void *, size_t, size_t, nni_opt_type);
extern int nni_copyin_ptr(void **, const void *, size_t, nni_opt_type);
extern int nni_copyin_u64(uint64_t *, const void *, size_t, nni_opt_type);
extern int nni_copyin_sockaddr(
    nng_sockaddr *, const void *, size_t, nni_opt_type);

// nni_copyout_xxx copies out a type of the named value.  It assumes that
// the type is aligned and the size correct, unless NNI_TYPE_OPAQUE is passed.
extern int nni_copyout(const void *, size_t, void *, size_t *);
extern int nni_copyout_bool(bool, void *, size_t *, nni_opt_type);
extern int nni_copyout_int(int, void *, size_t *, nni_opt_type);
extern int nni_copyout_ms(nng_duration, void *, size_t *, nni_opt_type);
extern int nni_copyout_ptr(void *, void *, size_t *, nni_opt_type);
extern int nni_copyout_size(size_t, void *, size_t *, nni_opt_type);
extern int nni_copyout_sockaddr(
    const nng_sockaddr *, void *, size_t *, nni_opt_type);
extern int nni_copyout_u64(uint64_t, void *, size_t *, nni_opt_type);

// nni_copyout_str copies out a string.  If the type is NNI_TYPE_STRING,
// then it passes through a pointer, created by nni_strdup().
extern int nni_copyout_str(const char *, void *, size_t *, nni_opt_type);

#endif // CORE_OPTIONS_H
