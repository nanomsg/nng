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

#ifndef CORE_MESSAGE_H
#define CORE_MESSAGE_H

/*
 * Internally used message API.  Again, this stuff is not part of our public
 * API.
 */

extern int nni_msg_alloc(nni_msg_t *, size_t);
extern void nni_msg_free(nni_msg_t);
extern int nni_msg_realloc(nni_msg_t, size_t);
extern void *nni_msg_header(nni_msg_t, size_t *);
extern void *nni_msg_body(nni_msg_t, size_t *);
extern int nni_msg_append(nni_msg_t, const void *, size_t);
extern int nni_msg_prepend(nni_msg_t, const void *, size_t);
extern int nni_msg_append_header(nni_msg_t, const void *, size_t);
extern int nni_msg_prepend_header(nni_msg_t, const void *, size_t);
extern int nni_msg_trim(nni_msg_t, size_t);
extern int nni_msg_trunc(nni_msg_t, size_t);
extern int nni_msg_trim_header(nni_msg_t, size_t);
extern int nni_msg_trunc_header(nni_msg_t, size_t);
extern int nni_msg_pipe(nni_msg_t, nni_pipe_t *);

#endif	/* CORE_SOCKET_H */
