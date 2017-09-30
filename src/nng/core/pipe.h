//
// Copyright 2017 Garrett D'Amore <garrett@damore.org>
// Copyright 2017 Capitar IT Group BV <info@capitar.com>
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
// operations against will return NNG_ECLOSED.
extern void nni_pipe_close(nni_pipe *);

// nni_pipe_stop is called to begin the process of tearing down the socket.
// This function runs asynchronously, and takes care to ensure that no
// other consumers are referencing the pipe.  We assume that either the
// socket (protocol code) or endpoint may have references to the pipe
// when this function is called.  The pipe cleanup is asynchronous and
// make take a while depending on scheduling, etc.  The pipe lock itself
// may not be held during this, but any other locks may be.
extern void nni_pipe_stop(nni_pipe *);

// nni_pipe_create is used only by endpoints - as we don't wish to expose the
// details of the pipe structure outside of pipe.c.  This function must be
// called without any locks held, as it will call back up into the socket and
// endpoint, grabbing each of those locks.  The function takes ownership of
// the transport specific pipe (3rd argument), regardless of whether it
// succeeds or not.  The endpoint should be held when calling this.
extern int nni_pipe_create(nni_ep *, void *);

// nni_pipe_start is called by the socket to begin any startup activities
// on the pipe before making it ready for use by protocols.  For example,
// TCP and IPC initial handshaking is performed this way.
extern void nni_pipe_start(nni_pipe *);

extern uint16_t nni_pipe_proto(nni_pipe *);
extern uint16_t nni_pipe_peer(nni_pipe *);
extern int      nni_pipe_getopt(nni_pipe *, const char *, void *, size_t *);

// nni_pipe_get_proto_data gets the protocol private data set with the
// nni_pipe_set_proto_data function.  No locking is performed.
extern void *nni_pipe_get_proto_data(nni_pipe *);
extern void  nni_pipe_set_proto_data(nni_pipe *, void *);

// nni_pipe_sock_list_init initializes a list of pipes, to be used by
// a per-socket list.
extern void nni_pipe_sock_list_init(nni_list *);

// nni_pipe_ep_list_init initializes a list of pipes, to be used by
// a per-endpoint list.
extern void nni_pipe_ep_list_init(nni_list *);

// nni_pipe_find finds a pipe given its ID.  It places a hold on the
// pipe, which must be released by the caller when it is done.
extern int nni_pipe_find(nni_pipe **, uint32_t);

// nni_pipe_rele releases the hold on the pipe placed by nni_pipe_find.
extern void nni_pipe_rele(nni_pipe *);

#endif // CORE_PIPE_H
