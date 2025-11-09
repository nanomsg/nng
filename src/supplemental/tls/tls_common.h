//
// Copyright 2025 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
// Copyright 2019 Devolutions <info@devolutions.net>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../core/nng_impl.h"

#include "core/lmq.h"
#include "tls_engine.h"

#ifndef NNG_TLS_TLS_COMMON_H
#define NNG_TLS_TLS_COMMON_H

// NNG_TLS_MAX_SEND_SIZE limits the amount of data we will buffer for sending,
// exerting back-pressure if this size is exceeded.  The 16K is aligned to the
// maximum TLS record size.
#ifndef NNG_TLS_MAX_SEND_SIZE
#define NNG_TLS_MAX_SEND_SIZE 16384
#endif

// NNG_TLS_MAX_RECV_SIZE limits the amount of data we will receive in a single
// operation.  As we have to buffer data, this drives the size of our
// intermediary buffer.  The 16K is aligned to the maximum TLS record size.
#ifndef NNG_TLS_MAX_RECV_SIZE
#define NNG_TLS_MAX_RECV_SIZE 16384
#endif

// NNG_TLS_MAX_SEND_MSG_QUEUE limits the number of pending messages for
// sending. This is only used for msg oriented transports like DTLS or SCTP.
#ifndef NNG_TLS_MAX_SEND_MSG_QUEUE
#define NNG_TLS_MAX_SEND_MSG_QUEUE 32
#endif

// NNG_TLS_MAX_RECV_MSG_QUEUE limits the number of pending messages for
// receiving. This is only used for msg oriented transports like DTLS or SCTP.
#ifndef NNG_TLS_MAX_RECV_MSG_QUEUE
#define NNG_TLS_MAX_RECV_MSG_QUEUE 32
#endif

// This file contains common code for TLS, and is only compiled if we
// have TLS configured in the system.  In particular, this provides the
// parts of TLS support that are invariant relative to different TLS
// libraries, such as dialer and listener support.

struct nng_tls_config {
	nni_mtx      lock;
	int          ref;
	bool         busy;
	bool         key_is_set;
	nng_tls_mode mode;
	size_t       size;

	// ... engine config data follows
};

struct nng_tls_cert_s;

typedef struct nni_tls_bio_ops_s {
	void (*bio_send)(void *, nng_aio *);
	void (*bio_recv)(void *, nng_aio *);
	void (*bio_stop)(void *);
	void (*bio_close)(void *);
	void (*bio_free)(void *);
} nni_tls_bio_ops;

typedef struct {
	nng_stream      stream;
	nng_tls_config *cfg;
	size_t          size;
	nni_mtx         lock;
	nni_atomic_flag did_close;
	bool            hs_done;
	bool            closed;
	bool            msg_oriented; // works with messages instead of streams
	nni_list        send_queue;
	nni_list        recv_queue;

	void           *bio;      // lower level transport object
	nni_tls_bio_ops bio_ops;  // lower level ops vector
	nni_aio         bio_send; // lower level send pending
	nni_aio         bio_recv; // lower level recv pending
	nni_mtx         bio_lock; // lock protecting lower layer operations
	uint8_t        *bio_send_buf;
	uint8_t        *bio_recv_buf;
	size_t          bio_recv_len;
	size_t          bio_recv_off;
	bool            bio_recv_pend;
	bool            bio_send_active;
	bool            bio_closed;
	nng_err         bio_err;
	size_t          bio_send_len;
	size_t          bio_send_head;
	size_t          bio_send_tail;
	nni_lmq         bio_send_lmq; // for msg oriented only
	nni_lmq         bio_recv_lmq; // for msg oriented only
	nni_msg        *bio_recv_msg; // for msg oriented only
	nni_reap_node   reap;

	// ... engine connection data follows
} nni_tls_conn;

extern void nni_tls_fini(nni_tls_conn *conn);
extern int  nni_tls_init(
     nni_tls_conn *conn, nng_tls_config *cfg, bool msg_oriented);
extern int  nni_tls_start(nni_tls_conn *conn, const nni_tls_bio_ops *biops,
     void *bio, const nng_sockaddr *sa);
extern void nni_tls_stop(nni_tls_conn *conn);
extern void nni_tls_close(nni_tls_conn *conn);
extern void nni_tls_recv(nni_tls_conn *conn, nni_aio *aio);
extern void nni_tls_send(nni_tls_conn *conn, nni_aio *aio);
extern bool nni_tls_verified(nni_tls_conn *conn);
extern const char *nni_tls_peer_cn(nni_tls_conn *conn);
extern nng_err     nni_tls_peer_cert(nni_tls_conn *conn, nng_tls_cert **certp);
extern nng_err     nni_tls_run(nni_tls_conn *conn);
extern size_t      nni_tls_engine_conn_size(void);

#endif // NNG_TLS_TLS_COMMON_H
