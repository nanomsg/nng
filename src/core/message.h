//
// Copyright 2021 Staysail Systems, Inc. <info@staysail.tech>
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
extern int      nni_msg_reserve(nni_msg *, size_t);
extern size_t   nni_msg_capacity(nni_msg *);
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
extern void     nni_msg_dump(const char *, const nni_msg *);
extern void     nni_msg_header_append_u32(nni_msg *, uint32_t);
extern uint32_t nni_msg_header_trim_u32(nni_msg *);
extern uint32_t nni_msg_trim_u32(nni_msg *);
// Peek and poke variants just access the first uint32 in the
// header.  This is useful when incrementing reference counts, etc.
// It's faster than trim and append, but logically equivalent.
extern uint32_t nni_msg_header_peek_u32(nni_msg *);
extern void     nni_msg_header_poke_u32(nni_msg *, uint32_t);
extern void     nni_msg_set_pipe(nni_msg *, uint32_t);
extern uint32_t nni_msg_get_pipe(const nni_msg *);

// Reference counting messages. This allows the same message to be
// cheaply reused instead of copied over and over again.  Callers of
// this functionality MUST be certain to use nni_msg_unique() before
// passing a message out of their control (e.g. to user programs.)
// Failure to do so will likely result in corruption.
extern void     nni_msg_clone(nni_msg *);
extern nni_msg *nni_msg_unique(nni_msg *);
extern bool     nni_msg_shared(nni_msg *);

// nni_msg_pull_up ensures that the message is unique, and that any
// header present is "pulled up" into the message body.  If the function
// cannot do this for any reason (out of space in the body), then NULL
// is returned.  It is the responsibility of the caller to free the
// original message in that case (same semantics as realloc).
extern nni_msg *nni_msg_pull_up(nni_msg *);

// Message option handling.  Message options are intended for protocol
// specific use.  For this reason, their API is not made public -- instead
// protocols should provide protocol specific functions for accessing them.
// Note that manipulation of message options must not be performed while the
// message is shared.  If a copy is made with nni_msg_unique(), then the
// options will be cloned appropriately.

// nni_msg_set_opt sets a given option.  This will replace another option
// on the message set using the same name.  The supplied functions are
// used when freeing the message, or when duplicating the message.
// If the value was created using nni_alloc, then nni_free and nni_mem_dup
// can be supplied.  Note that the message must not be shared when this
// is called.
//
// NB: It is possible to use a non-NULL dup function, but have a NULL
// free function.  This is appropriate if the content of the buffer is
// located in the message header, for example.
extern int nni_msg_set_opt(nng_msg *, const char *, void *, size_t,
    void (*)(void *, size_t), int (*)(void **, void *, size_t));

// nni_msg_add_opt adds a given option, regardless of whether another
// instance of the option with the same name exists. In all other respects
// it behaves like nng_msg_set_opt.
extern int nni_msg_add_opt(nng_msg *, const char *, void *, size_t,
    void (*)(void *, size_t), int (*)(void **, void *, size_t));

// nni_msg_rem_opt removes any (and all) instances of the named option
// from the message. It returns zero if any instances are removed, or
// NNG_ENOENT if no instance of the option was found on the message.
// The message must not be shared.
extern int nni_msg_rem_opt(nng_msg *, const char *);

// nni_msg_get_opt is used to get the first instance of a message option.
// If the option cannot be found, then NNG_ENOENT is returned.
extern int nni_msg_get_opt(nng_msg *, const char *, void **, size_t *);

// nni_msg_walk_opt is used to iterate over all options with a function.
// The called function should return true to keep iterating, or false
// to stop the iteration.  The argument is supplied as the first parameter
// to the function.
extern void
nni_msg_walk_opt(
    nng_msg *, void *, bool (*)(void *, const char *, void *, size_t))

#endif // CORE_SOCKET_H
