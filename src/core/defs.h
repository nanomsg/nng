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
typedef struct nng_endpt	nni_ep;
typedef struct nng_pipe		nni_pipe;
typedef struct nng_msg		nni_msg;

// REMOVE THESE
typedef struct nng_endpt	nni_endpt;

// These are our own names.
typedef struct nni_tran		nni_tran;
typedef struct nni_tran_ep	nni_tran_ep;
typedef struct nni_tran_pipe	nni_tran_pipe;

typedef struct nni_protocol	nni_protocol;

typedef int			nni_signal;     // Turnstile/wakeup channel.
typedef uint64_t		nni_time;       // Absolute time (usec).
typedef int64_t			nni_duration;   // Relative time (usec).

// Some default timing things.
#define NNI_TIME_NEVER		((nni_time) -1)
#define NNI_TIME_ZERO		((nni_time) 0)
#define NNI_SECOND		(1000000)

// Structure allocation conveniences.
#define NNI_ALLOC_STRUCT(s)	nni_alloc(sizeof (*(s)))
#define NNI_FREE_STRUCT(s)	nni_free((s), sizeof (*(s)))

#endif  // CORE_DEFS_H
