//
// Copyright 2017 Garrett D'Amore <garrett@damore.org>
// Copyright 2017 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#ifndef CORE_MESSAGE_H
#define CORE_MESSAGE_H

// Internally used message API.  Again, this is not part of our public API.
// "trim" operations work from the front, and "chop" work from the end.

extern int      nni_msg_alloc(nni_msg **, size_t);
extern void     nni_msg_free(nni_msg *);
extern int      nni_msg_realloc(nni_msg *, size_t);
extern int      nni_msg_dup(nni_msg **, const nni_msg *);
extern void *   nni_msg_header(nni_msg *);
extern size_t   nni_msg_header_len(const nni_msg *);
extern void *   nni_msg_body(nni_msg *);
extern size_t   nni_msg_len(const nni_msg *);
extern int      nni_msg_append(nni_msg *, const void *, size_t);
extern int      nni_msg_insert(nni_msg *, const void *, size_t);
extern int      nni_msg_header_append(nni_msg *, const void *, size_t);
extern int      nni_msg_header_insert(nni_msg *, const void *, size_t);
extern int      nni_msg_trim(nni_msg *, size_t);
extern int      nni_msg_chop(nni_msg *, size_t);
extern void     nni_msg_clear(nni_msg *);
extern void     nni_msg_header_clear(nni_msg *);
extern int      nni_msg_header_trim(nni_msg *, size_t);
extern int      nni_msg_header_chop(nni_msg *, size_t);
extern int      nni_msg_setopt(nni_msg *, int, const void *, size_t);
extern int      nni_msg_getopt(nni_msg *, int, void *, size_t *);
extern void     nni_msg_dump(const char *, const nni_msg *);
extern int      nni_msg_append_u16(nni_msg *, uint16_t);
extern int      nni_msg_append_u32(nni_msg *, uint32_t);
extern int      nni_msg_append_u64(nni_msg *, uint64_t);
extern int      nni_msg_insert_u16(nni_msg *, uint16_t);
extern int      nni_msg_insert_u32(nni_msg *, uint32_t);
extern int      nni_msg_insert_u64(nni_msg *, uint64_t);
extern int      nni_msg_header_append_u16(nni_msg *, uint16_t);
extern int      nni_msg_header_append_u32(nni_msg *, uint32_t);
extern int      nni_msg_header_append_u64(nni_msg *, uint64_t);
extern int      nni_msg_header_insert_u16(nni_msg *, uint16_t);
extern int      nni_msg_header_insert_u32(nni_msg *, uint32_t);
extern int      nni_msg_header_insert_u64(nni_msg *, uint64_t);
extern uint16_t nni_msg_trim_u16(nni_msg *);
extern uint32_t nni_msg_trim_u32(nni_msg *);
extern uint64_t nni_msg_trim_u64(nni_msg *);
extern uint16_t nni_msg_chop_u16(nni_msg *);
extern uint32_t nni_msg_chop_u32(nni_msg *);
extern uint64_t nni_msg_chop_u64(nni_msg *);
extern uint16_t nni_msg_header_trim_u16(nni_msg *);
extern uint32_t nni_msg_header_trim_u32(nni_msg *);
extern uint64_t nni_msg_header_trim_u64(nni_msg *);
extern uint16_t nni_msg_header_chop_u16(nni_msg *);
extern uint32_t nni_msg_header_chop_u32(nni_msg *);
extern uint64_t nni_msg_header_chop_u64(nni_msg *);
extern void     nni_msg_set_pipe(nni_msg *, uint32_t);
extern uint32_t nni_msg_get_pipe(const nni_msg *);

#endif // CORE_SOCKET_H
