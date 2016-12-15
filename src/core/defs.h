/*
 * Copyright 2016 Garrett D'Amore <garrett@damore.org>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom
 * the Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#ifndef CORE_DEFS_H
#define CORE_DEFS_H

/*
 * C compilers may get unhappy when named arguments are not used.  While
 * there are things like __attribute__((unused)) which are arguably
 * superior, support for such are not universal.
 */
#define	NNI_ARG_UNUSED(x)	((void)x);

/*
 * These types are common but have names shared with user space.
 */
typedef struct nng_socket *nni_socket_t;
typedef struct nng_pipe *nni_pipe_t;
typedef struct nng_msg *nni_msg_t;
typedef struct nng_endpt *nni_endpt_t;

#endif	/* CORE_DEFS_H */
