/*
 * Copyright 2016 Garrett D'Amore <garrett@damore.org>
 *
 * This software is supplied under the terms of the MIT License, a
 * copy of which should be located in the distribution where this
 * file was obtained (LICENSE.txt).  A copy of the license may also be
 * found online at https://opensource.org/licenses/MIT.
 */

#ifndef CORE_DEFS_H
#define CORE_DEFS_H

/*
 * C compilers may get unhappy when named arguments are not used.  While
 * there are things like __attribute__((unused)) which are arguably
 * superior, support for such are not universal.
 */
#define NNI_ARG_UNUSED(x)    ((void) x);

/*
 * These types are common but have names shared with user space.
 */
typedef struct nng_socket *	nni_socket_t;
typedef struct nng_pipe *	nni_pipe_t;
typedef struct nng_msg *	nni_msg_t;
typedef struct nng_endpt *	nni_endpt_t;

#endif  /* CORE_DEFS_H */
