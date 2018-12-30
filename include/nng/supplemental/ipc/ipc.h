//
// Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
// Copyright 2018 Devolutions <info@devolutions.net>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#ifndef NNG_SUPPLEMENTAL_IPC_IPC_H
#define NNG_SUPPLEMENTAL_IPC_IPC_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

#include <nng/nng.h>
#include <nng/transport/ipc/ipc.h> // For IPC option names.

// This is our "public" IPC API.  This allows applications to access
// basic IPC functions, using our AIO framework.  Most applications will
// not need this.  This supports both UNIX domain sockets (AF_LOCAL),
// and Windows Named Pipes, depending on the underlying platform.

// nng_ipc represents a single IPC connection.  This is generally
// a connected stream.
typedef struct nng_ipc_s nng_ipc;

// nng_ipc_dialer is a dialer object used to create outgoing connections.
// This is a bit different than a typical BSD socket API, but doing it
// helps keep the API orthogonal to the listener API.
typedef struct nng_ipc_dialer_s nng_ipc_dialer;

// nng_ipc_listener is a listener object.  This is used to accept incoming
// connections.
typedef struct nng_ipc_listener_s nng_ipc_listener;

// nng_ipc_close closes the connection, but does not release the
// underlying object.  Operations that may be pending on the connect,
// as well as further operations, will result in NNG_ECLOSED.
NNG_DECL void nng_ipc_close(nng_ipc *);

// nng_ipc_free frees the IPC connection, closing it if it is open.
// This is necessary to release the resources of the IPC object.
// (It is an error to refer to the IPC object after this is called.)
NNG_DECL void nng_ipc_free(nng_ipc *);

// nng_ipc_send sends the data in the aio, which should be stored in
// an iov for the message.  Note that the iov in the aio may be modified,
// so applications should not assume otherwise.
NNG_DECL void nng_ipc_send(nng_ipc *, nng_aio *);

// nng_ipc_recv receives data into the iov supplied.  It is possible for
// the callback to be executed with less data read than requested.  (This
// is actually pretty likely for bulk transfers.)  The caller should update
// the iov's and resubmit as needed.
NNG_DECL void nng_ipc_recv(nng_ipc *, nng_aio *);

// nng_ipc_getopt is used to get options.  The options available are:
//
// NNG_OPT_REMADDR         - nng_sockaddr for the connection.
// NNG_OPT_LOCADD          - nng_sockaddr for the connection.
// NNG_OPT_IPC_PEER_UID    - peer user ID (if available), uint64_t
// NNG_OPT_IPC_PEER_GID    - peer group ID (if available), uint64_t
// NNG_OPT_IPC_PEER_ZONEID - peer zone ID (illumos/Solaris only), uint64_t
NNG_DECL int nng_ipc_getopt(nng_ipc *, const char *, void *, size_t *);

// nng_ipc_setopt is used to set options.  There are presently no such
// options defined for connections.
NNG_DECL int nng_ipc_setopt(nng_ipc *, const char *, const void *, size_t);

// nng_ipc_dialer_alloc is used to allocate an IPC dialer.
NNG_DECL int nng_ipc_dialer_alloc(nng_ipc_dialer **);

// nng_ipc_dialer_close closes the dialer, aborting any pending outbound
// connection attempts (and preventing any new ones) with NNG_ECLOSED.
// This does not free the resources associated with the dialer, so the
// application should still call nng_ipc_dialer_free.  Connections already
// established by the dialer are unaffected by this call.
NNG_DECL void nng_ipc_dialer_close(nng_ipc_dialer *);

// nng_ipc_dialer_free is used to free the dialer.  This implicitly calls
// nng_ipc_dialer_close, then releases the resources associated with the
// dialer.  It is therefore an error for the application to attempt to use
// the dialer after this call.
NNG_DECL void nng_ipc_dialer_free(nng_ipc_dialer *);

// nng_ipc_dialer_dial attempts to create a new connection (nng_ipc *)
// may making an outbound connect call.  If this succeeds, the aio
// will return a suitable nng_ipc * in the first output of the aio.
// (I.e. nng_aio_get_output(aio, 0).)  The destination address to dial
// is stored in the 2nd argument.
NNG_DECL void nng_ipc_dialer_dial(
    nng_ipc_dialer *, const nng_sockaddr *, nng_aio *);

// nng_ipc_listener_alloc creates a listener.
NNG_DECL int nng_ipc_listener_alloc(nng_ipc_listener **);

// nng_ipc_listener_close closes the listener, unbinding it from
// any active path if it was previously bound with nng_ipc_listener_listen.
// This does not completely release the resources associated with the
// listener, so nng_ipc_listener_free should still be called.
// Any pending accept calls will be aborted with NNG_ECLOSED, and any
// future attempts will also result in NNG_ECLOSED.  Connections already
// established by this listener are unaffected by this call.
NNG_DECL void nng_ipc_listener_close(nng_ipc_listener *);

// nng_ipc_listener_free frees the listener.  This causes any other
// outstanding accept calls to return NNG_ECLOSED.  The listener cannot
// be used by the application after this is called.  This implictly
// includes a call to nng_ipc_listener_close().
NNG_DECL void nng_ipc_listener_free(nng_ipc_listener *);

// nng_ipc_listener_listen binds to the IPC address and arranges for
// the IPC path to be created and bound.  It does not accept any new
// incoming connections.  This operation is synchronous.
NNG_DECL int nng_ipc_listener_listen(nng_ipc_listener *, const nng_sockaddr *);

// nng_ipc_listener_accept accepts an incoming connection (creating an
// nng_ipc * object), and returns it in the nng_aio as the first output
// on success.
NNG_DECL void nng_ipc_listener_accept(nng_ipc_listener *, nng_aio *);

#ifdef __cplusplus
}
#endif

#endif // NNG_SUPPLEMENTAL_IPC_IPC_H
