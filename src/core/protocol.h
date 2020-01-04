//
// Copyright 2020 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#ifndef CORE_PROTOCOL_H
#define CORE_PROTOCOL_H

#include "core/options.h"

// Protocol implementation details.  Protocols must implement the
// interfaces in this file.  Note that implementing new protocols is
// not necessarily intended to be a trivial task.  The protocol developer
// must understand the nature of nng, as they are responsible for handling
// most of the logic.  The protocol generally does most of the work for
// locking, and calls into the transport's pipe functions to do actual
// work, and the pipe functions generally assume no locking is needed.
// As a consequence, most of the concurrency in nng exists in the protocol
// implementations.

// nni_proto_pipe contains protocol-specific per-pipe operations.
struct nni_proto_pipe_ops {
	// pipe_size is the size of a protocol pipe object.  The common
	// code allocates this memory for the protocol private state.
	size_t pipe_size;

	// pipe_init2 initializes the protocol-specific pipe data structure.
	// The last argument is the per-socket protocol private data.
	int (*pipe_init)(void *, nni_pipe *, void *);

	// pipe_fini releases any pipe data structures.  This is called after
	// the pipe has been removed from the protocol, and the generic
	// pipe threads have been stopped.
	void (*pipe_fini)(void *);

	// pipe_start is called to register a pipe with the protocol.  The
	// protocol can reject this, for example if another pipe is already
	// active on a 1:1 protocol.  The protocol may not block during this.
	int (*pipe_start)(void *);

	// pipe_close is an idempotent, non-blocking, operation, called
	// when the pipe is being closed.  Any operations pending on the
	// pipe should be canceled with NNG_ECLOSED.  (Best option is to
	// use nng_aio_close() on them)
	void (*pipe_close)(void *);

	// pipe_stop is called during finalization, to ensure that
	// the protocol is absolutely finished with the pipe.  It should
	// wait if necessary to ensure that the pipe is not referenced
	// anymore by the protocol.  It should not destroy resources.
	void (*pipe_stop)(void *);
};

struct nni_proto_ctx_ops {
	// ctx_size is the size of a protocol context object.  The common
	// code allocates this memory for the protocol private state.
	size_t ctx_size;

	// ctx_init initializes a new context. The second argument is the
	// protocol specific socket structure.
	int (*ctx_init)(void *, void *);

	// ctx_fini destroys a context.
	void (*ctx_fini)(void *);

	// ctx_recv is an asynchronous recv.
	void (*ctx_recv)(void *, nni_aio *);

	// ctx_send is an asynchronous send.
	void (*ctx_send)(void *, nni_aio *);

	// ctx_drain drains the context, signaling the aio when done.
	// This should prevent any further receives from completing,
	// and only sends that had already been submitted should be
	// permitted to continue.  It may be NULL for protocols where
	// draining without an ability to receive makes no sense
	// (e.g. REQ or SURVEY).
	void (*ctx_drain)(void *, nni_aio *);

	// ctx_options array.
	nni_option *ctx_options;
};

struct nni_proto_sock_ops {
	// ctx_size is the size of a protocol socket object.  The common
	// code allocates this memory for the protocol private state.
	size_t sock_size;

	// sock_init2 initializes the protocol instance, which will be stored
	// on the socket. This is run without the sock lock held.
	int (*sock_init)(void *, nni_sock *);

	// sock_fini destroys the protocol instance.  This is run without the
	// socket lock held, and is intended to release resources.  It may
	// block as needed.
	void (*sock_fini)(void *);

	// Open the protocol instance.  This is run with the lock held,
	// and intended to allow the protocol to start any asynchronous
	// processing.
	void (*sock_open)(void *);

	// Close the protocol instance.  This is run with the lock held,
	// and intended to initiate closure of the socket.  For example,
	// it can signal the socket worker threads to exit.
	void (*sock_close)(void *);

	// Send a message.
	void (*sock_send)(void *, nni_aio *);

	// Receive a message.
	void (*sock_recv)(void *, nni_aio *);

	// Options. Must not be NULL. Final entry should have NULL name.
	nni_option *sock_options;
};

typedef struct nni_proto_id {
	uint16_t    p_id;
	const char *p_name;
} nni_proto_id;

struct nni_proto {
	uint32_t                  proto_version;  // Ops vector version
	nni_proto_id              proto_self;     // Our identity
	nni_proto_id              proto_peer;     // Peer identity
	uint32_t                  proto_flags;    // Protocol flags
	const nni_proto_sock_ops *proto_sock_ops; // Per-socket opeations
	const nni_proto_pipe_ops *proto_pipe_ops; // Per-pipe operations.
	const nni_proto_ctx_ops * proto_ctx_ops;  // Context operations.

	// proto_init, if not NULL, provides a function that initializes
	// global values.  The main purpose of this may be to initialize
	// protocol option values.
	int (*proto_init)(void);

	// proto_fini, if not NULL, is called at shutdown, to release
	// any resources allocated at proto_init time.
	void (*proto_fini)(void);
};

// We quite intentionally use a signature where the upper word is nonzero,
// which ensures that if we get garbage we will reject it.  This is more
// likely to mismatch than all zero bytes would.  The actual version is
// stored in the lower word; this is not semver -- the numbers are just
// increasing - we doubt it will increase more than a handful of times
// during the life of the project.  If we add a new version, please keep
// the old version around -- it may be possible to automatically convert
// older versions in the future.
#define NNI_PROTOCOL_V0 0x50520000u // "pr\0\0"
#define NNI_PROTOCOL_V1 0x50520001u // "pr\0\0"
#define NNI_PROTOCOL_VERSION NNI_PROTOCOL_V1

// These flags determine which operations make sense.  We use them so that
// we can reject attempts to create notification fds for operations that make
// no sense.  Also, we can detect raw mode, thereby providing handling for
// that at the socket layer (NNG_PROTO_FLAG_RAW).  Finally, we provide the
// NNI_PROTO_FLAG_NOMSGQ flag for protocols that do not use the upper write
// or upper read queues.
#define NNI_PROTO_FLAG_RCV 1u    // Protocol can receive
#define NNI_PROTO_FLAG_SND 2u    // Protocol can send
#define NNI_PROTO_FLAG_SNDRCV 3u // Protocol can both send & recv
#define NNI_PROTO_FLAG_RAW 4u    // Protocol is raw
#define NNI_PROTO_FLAG_NOMSGQ 8u // Protocol bypasses the upper queues

// nni_proto_open is called by the protocol to create a socket instance
// with its ops vector.  The intent is that applications will only see
// the single protocol-specific constructure, like nng_pair_v0_open(),
// which should just be a thin wrapper around this.  If the protocol has
// not been initialized yet, this routine will do so.
extern int nni_proto_open(nng_socket *, const nni_proto *);

// Protocol numbers.  These are to be used with nng_socket_create().
// These values are used on the wire, so must not be changed.  The major
// number of the protocol is shifted left by 4 bits, and a subprotocol is
// assigned in the lower 4 bits.
//
// There are gaps in the list, which are obsolete or unsupported protocols.
// Protocol numbers are never more than 16 bits.  Also, there will never be
// a valid protocol numbered 0 (NNG_PROTO_NONE).
#define NNI_PROTO(major, minor) (((major) *16) + (minor))

// Protocol major numbers.  This is here for documentation only, and
// to serve as a "registry" for managing new protocol numbers.  Consider
// updating this table when adding new protocols.
//
// Protocol     Maj Min Name       Notes
// -------------------------------------------
// NONE          0   0             reserved
// PAIRv0        1   0  pair
// PAIRv1        1   1  pair1      nng only, experimental
// PUBv0         2   0  pub
// SUBv0         2   1  sub
// REQv0         3   0  req
// REPv0         3   1  rep
// PUSHv0        5   0  push
// PULLv0        5   1  pull
// SURVEYORv0    6   2  surveyor   minors 0 & 1 retired
// RESPONDENTv0  6   3  respondent
// BUSv0         7   0  bus
// STARv0      100   0  star       mangos only, experimental

extern int  nni_proto_sys_init(void);
extern void nni_proto_sys_fini(void);

#endif // CORE_PROTOCOL_H
