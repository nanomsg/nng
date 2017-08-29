//
// Copyright 2017 Garrett D'Amore <garrett@damore.org>
// Copyright 2017 Capitar IT Group BV <info@capitar.com>
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

// nni_getopt_buf gets the queue size for the message queue.
extern int nni_getopt_buf(nni_msgq *, void *, size_t *);

// nni_setopt_duration sets the duration.  Durations must be legal,
// either a positive value, 0, or -1 to indicate forever.
extern int nni_setopt_usec(nni_duration *, const void *, size_t);

// nni_getopt_duration gets the duration.
extern int nni_getopt_usec(nni_duration, void *, size_t *);

// nni_setopt_int sets an integer, which must be between the minimum and
// maximum values (inclusive).
extern int nni_setopt_int(int *, const void *, size_t, int, int);

#define NNI_MAXINT ((int) 2147483647)
#define NNI_MININT ((int) -2147483648)

// nni_getopt_int gets an integer.
extern int nni_getopt_int(int, void *, size_t *);

// nni_getopt_u64 gets an unsigned 64 bit number.
extern int nni_getopt_u64(uint64_t, void *, size_t *);

// nni_getopt_str gets a C style string.
extern int nni_getopt_str(const char *, void *, size_t *);

// nni_setopt_size sets a size_t option.
extern int nni_setopt_size(size_t *, const void *, size_t, size_t, size_t);

// We limit the maximum size to 4GB.  That's intentional because some of the
// underlying protocols cannot cope with anything bigger than 32-bits.
#define NNI_MINSZ (0)
#define NNI_MAXSZ ((size_t) 0xffffffff)

// nni_getopt_size obtains a size_t option.
extern int nni_getopt_size(size_t, void *, size_t *);

// nni_getopt_fd obtains a notification file descriptor.
extern int nni_getopt_fd(nni_sock *, nni_notifyfd *, int, void *, size_t *);

extern int nni_chkopt_usec(const void *, size_t);
extern int nni_chkopt_int(const void *, size_t, int, int);
extern int nni_chkopt_size(const void *, size_t, size_t, size_t);

extern int         nni_option_register(const char *, int *);
extern int         nni_option_lookup(const char *);
extern const char *nni_option_name(int);

extern int  nni_option_sys_init(void);
extern void nni_option_sys_fini(void);

#endif // CORE_OPTIONS_H
