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

// Message protocol private data.  This is specific for protocol use,
// and not exposed to library users.

// nni_proto_msg_ops is used to handle the protocol private data
// associated with a message.
typedef struct nni_proto_msg_ops {
	// This is used to free protocol specific data previously
	// attached to the message, and is called when the message
	// itself is freed, or when protocol private is replaced.
	int (*msg_free)(void *);

	// Duplicate protocol private data when duplicating a message,
	// such as by nni_msg_dup() or calling nni_msg_unique() on a
	// shared message.
	int (*msg_dup)(void **, const void *);
} nni_proto_msg_ops;

// nni_msg_set_proto_data is used to set protocol private data, and
// callbacks for freeing and duplicating said data, on the message.
// If other protocol private data exists on the message, it will be freed.
// NULL can be used for the ops and the pointer to clear any previously
// set data. The message must not be shared when this is called.
extern void nni_msg_set_proto_data(nng_msg *, nni_proto_msg_ops *, void *);

// nni_msg_get_proto_data returns the data previously set on the message.
// Note that the protocol is responsible for ensuring that the data on
// the message is set by it alone.
extern void *nni_msg_get_proto_data(nng_msg *);

extern uint8_t nni_msg_get_pub_qos(nng_msg *m);

#endif // CORE_SOCKET_H
