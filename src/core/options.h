//
// Copyright 2016 Garrett D'Amore <garrett@damore.org>
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
extern int nni_setopt_buf(nni_msgqueue *, const void *, size_t);

// nni_getopt_buf gets the queue size for the message queue.
extern int nni_getopt_buf(nni_msgqueue *, void *, size_t *);

// nni_setopt_duration sets the duration.  Durations must be legal,
// either a positive value, 0, or -1 to indicate forever.
extern int nni_setopt_duration(nni_duration *, const void *, size_t);

// nni_getopt_duration gets the duration.
extern int nni_getopt_duration(nni_duration *, void *, size_t *);

// nni_setopt_int sets an integer, which must be between the minimum and
// maximum values (inclusive).
extern int nni_setopt_int(int *, const void *, size_t, int, int);

#define NNI_MAXINT	((int) 2147483647)
#define NNI_MININT	((int) -2147483648)

// nni_getopt_int gets an integer.
extern int nni_getopt_int(int *, void *, size_t *);

#endif  // CORE_OPTIONS_H
