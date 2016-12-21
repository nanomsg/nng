/*
 * Copyright 2016 Garrett D'Amore <garrett@damore.org>
 *
 * This software is supplied under the terms of the MIT License, a
 * copy of which should be located in the distribution where this
 * file was obtained (LICENSE.txt).  A copy of the license may also be
 * found online at https://opensource.org/licenses/MIT.
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

#endif  /* CORE_SOCKET_H */
