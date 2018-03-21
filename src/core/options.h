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

// Option helpers.  These can be called from protocols or transports
// in their own option handling, centralizing the logic for dealing with
// variable sized options.

// nni_setopt_buf sets the queue size for the message queue.
extern int nni_setopt_buf(nni_msgq *, const void *, size_t);

// nni_setopt_duration sets the duration.  Durations must be legal,
// either a positive value, 0, or -1 to indicate forever.
extern int nni_setopt_ms(nni_duration *, const void *, size_t);

// nni_setopt_bool sets a bool, or _Bool
extern int nni_setopt_bool(bool *, const void *, size_t);

// nni_setopt_int sets an integer, which must be between the minimum and
// maximum values (inclusive).
extern int nni_setopt_int(int *, const void *, size_t, int, int);

#define NNI_MAXINT ((int) 2147483647)
#define NNI_MININT ((int) -2147483648)

// nni_setopt_size sets a size_t option.
extern int nni_setopt_size(size_t *, const void *, size_t, size_t, size_t);

// We limit the maximum size to 4GB.  That's intentional because some of the
// underlying protocols cannot cope with anything bigger than 32-bits.
#define NNI_MINSZ (0)
#define NNI_MAXSZ ((size_t) 0xffffffff)

extern int nni_chkopt_bool(size_t);
extern int nni_chkopt_ms(const void *, size_t);
extern int nni_chkopt_int(const void *, size_t, int, int);
extern int nni_chkopt_size(const void *, size_t, size_t, size_t);

// nni_copyout_xxx copies out a type of the named value.  It assumes that
// the type is aligned and the size correct, unless NNI_TYPE_OPAQUE is passed.
extern int nni_copyout(const void *, size_t, void *, size_t *);
extern int nni_copyout_bool(bool, void *, size_t *, int);
extern int nni_copyout_int(int, void *, size_t *, int);
extern int nni_copyout_ms(nng_duration, void *, size_t *, int);
extern int nni_copyout_ptr(void *, void *, size_t *, int);
extern int nni_copyout_size(size_t, void *, size_t *, int);
extern int nni_copyout_sockaddr(const nng_sockaddr *, void *, size_t *, int);
extern int nni_copyout_u64(uint64_t, void *, size_t *, int);

// nni_copyout_str copies out a string.  If the type is NNI_TYPE_STRING,
// then it passes through a pointer, created by nni_strdup().
extern int nni_copyout_str(const char *, void *, size_t *, int);

#endif // CORE_OPTIONS_H
