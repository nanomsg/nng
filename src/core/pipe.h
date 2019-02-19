//
// Copyright 2019 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#ifndef CORE_PIPE_H
#define CORE_PIPE_H

// NB: This structure is supplied here for use by the CORE. Use of this
// OUSIDE of the core is STRICTLY VERBOTEN.  NO DIRECT ACCESS BY PROTOCOLS OR
// TRANSPORTS.

#include "core/defs.h"
#include "core/thread.h"
#include "core/transport.h"

extern int  nni_pipe_sys_init(void);
extern void nni_pipe_sys_fini(void);

// AIO
extern void nni_pipe_recv(nni_pipe *, nni_aio *);
extern void nni_pipe_send(nni_pipe *, nni_aio *);

// Pipe operations that protocols use.
extern uint32_t nni_pipe_id(nni_pipe *);

// nni_pipe_close closes the underlying transport for the pipe.  Further
// operations against will return NNG_ECLOSED.  This is idempotent.  The
// actual pipe will be reaped asynchronously.
extern void nni_pipe_close(nni_pipe *);

extern uint16_t nni_pipe_proto(nni_pipe *);
extern uint16_t nni_pipe_peer(nni_pipe *);

// nni_pipe_getopt looks up the option.  The last argument is the type,
// which.  If the type is NNI_TYPE_OPAQUE, then no format check is performed.
extern int nni_pipe_getopt(
    nni_pipe *, const char *, void *, size_t *, nni_opt_type);

// nni_pipe_get_proto_data gets the protocol private data set with the
// nni_pipe_set_proto_data function.  No locking is performed.
extern void *nni_pipe_get_proto_data(nni_pipe *);

// nni_pipe_find finds a pipe given its ID.  It places a hold on the
// pipe, which must be released by the caller when it is done.
extern int nni_pipe_find(nni_pipe **, uint32_t);

// nni_pipe_sock_id returns the socket id for the pipe (used by public API).
extern uint32_t nni_pipe_sock_id(nni_pipe *);

// nni_pipe_listener_id returns the listener id for the pipe (or 0 if none).
extern uint32_t nni_pipe_listener_id(nni_pipe *);

// nni_pipe_dialer_id returns the dialer id for the pipe (or 0 if none).
extern uint32_t nni_pipe_dialer_id(nni_pipe *);

// nni_pipe_rele releases the hold on the pipe placed by nni_pipe_find.
extern void nni_pipe_rele(nni_pipe *);

// nni_pipe_add_stat adds a statistic to the pipe
extern void nni_pipe_add_stat(nni_pipe *, nni_stat_item *);

extern void nni_pipe_bump_rx(nni_pipe *, size_t);
extern void nni_pipe_bump_tx(nni_pipe *, size_t);
extern void nni_pipe_bump_error(nni_pipe *, int);

#endif // CORE_PIPE_H
