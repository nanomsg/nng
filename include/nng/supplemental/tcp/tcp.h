//
// Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#ifndef NNG_SUPPLEMENTAL_TCP_TCP_H
#define NNG_SUPPLEMENTAL_TCP_TCP_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

#include <nng/nng.h>

// This is our "public" TCP API.  This allows applications to access
// basic TCP functions, using our AIO framework.  Most applications will
// not need this.

// nng_tcp represents a single TCP connection.  This is generally
// a connected stream.
typedef struct nng_tcp_s nng_tcp;

// nng_tcp_dialer is a dialer object used to create outgoing connections.
// This is a bit different than a typical BSD socket API, but doing it
// helps keep the API orthogonal to the listener API.
typedef struct nng_tcp_dialer_s nng_tcp_dialer;

// nng_tcp_listener is a listener object.  This is used to accept incoming
// connections.
typedef struct nng_tcp_listener_s nng_tcp_listener;

// nng_tcp_close closes the connection, but does not release the
// underlying object.  Operations that may be pending on the connect,
// as well as further operations, will result in NNG_ECLOSED.
NNG_DECL void nng_tcp_close(nng_tcp *);

// nng_tcp_free frees the TCP connection, closing it if it is open.
// This is necessary to release the resources of the TCP object.
// (It is an error to refer to the TCP object after this is called.)
NNG_DECL void nng_tcp_free(nng_tcp *);

// nng_tcp_send sends the data in the aio, which should be stored in
// an iov for the message.  Note that the iov in the aio may be modified,
// so applications should not assume otherwise.
NNG_DECL void nng_tcp_send(nng_tcp *, nng_aio *);

// nng_tcp_recv receives data into the iov supplied.  It is possible for
// the callback to be executed with less data read than requested.  (This
// is actually pretty likely for bulk transfers.)  The caller should update
// the iov's and resubmit as needed.
NNG_DECL void nng_tcp_recv(nng_tcp *, nng_aio *);

// nng_tcp_sockname obtains an nng_sockaddr associated with our local address.
NNG_DECL int nng_tcp_sockname(nng_tcp *, nng_sockaddr *);

// nng_tcp_peername obtains an nng_sockaddr associated with our peer.
NNG_DECL int nng_tcp_peername(nng_tcp *, nng_sockaddr *);

// nng_tcp_set_nodelay is used to disable Nagle's algorithm (true) or
// enable it.  For latency sensitive applications, disable it.  For
// throughput operations involving tiny messages, leave it enabled.  We
// usually recommend disabling it.
NNG_DECL int nng_tcp_set_nodelay(nng_tcp *, bool);

// nng_set_keepalive is used to enable the use of TCP keepalives.
// At the moment there is no further tuning, because the tunables here
// tend to be fairly platform specific.
NNG_DECL int nng_tcp_set_keepalive(nng_tcp *, bool);

// nng_tcp_dialer_alloc is used to allocate a TCP dialer.
NNG_DECL int nng_tcp_dialer_alloc(nng_tcp_dialer **);

// nng_tcp_dialer_close closes the dialer, aborting any pending outbound
// connection attempts (and preventing any new ones) with NNG_ECLOSED.
// This does not free the resources associated with the dialer, so the
// application should still call nng_tcp_dialer_free.  Connections already
// established by the dialer are unaffected by this call.
NNG_DECL void nng_tcp_dialer_close(nng_tcp_dialer *);

// nng_tcp_dialer_free is used to free the dialer.  This implicitly calls
// nng_tcp_dialer_close, then releases the resources associated with the
// dialer.  It is therefore an error for the application to attempt to use
// the dialer after this call.
NNG_DECL void nng_tcp_dialer_free(nng_tcp_dialer *);

// nng_tcp_dialer_set_source is used to set the source address that the
// dialer should dial from.  The port component of the socket address is
// ignored, as a source port is always chosen at random.  If this is not
// called, then a system specific default source address is chosen.
// (Usually the local interface IP address chosen based on the route to
// the destination.)
NNG_DECL int nng_tcp_dialer_set_source(nng_tcp_dialer *, const nng_sockaddr *);

// nng_tcp_dialer_dial attempts to create a new connection (nng_tcp *)
// may making an outbound connect call.  If this succeeds, the aio
// will return a suitable nng_tcp * in the first output of the aio.
// (I.e. nng_aio_get_output(aio, 0).)  The destination address to dial
// is stored in the 2nd argument.
NNG_DECL void nng_tcp_dialer_dial(
    nng_tcp_dialer *, const nng_sockaddr *, nng_aio *);

// nng_tcp_listener_alloc creates a listener.
NNG_DECL int nng_tcp_listener_alloc(nng_tcp_listener **);

// nng_tcp_listener_close closes the listener, unbinding it from
// any active ports if it was previously bound with nng_tcp_listener_listen.
// This does not completely release the resources associated with the
// listener, so nng_tcp_listener_free should still be called.
// Any pending accept calls will be aborted with NNG_ECLOSED, and any
// future attempts will also result in NNG_ECLOSED.  Connections already
// established by this listener are unaffected by this call.
NNG_DECL void nng_tcp_listener_close(nng_tcp_listener *);

// nng_tcp_listener_free frees the listener.  This causes any other
// outstanding accept calls to return NNG_ECLOSED.  The listener cannot
// be used by the application after this is called.  This implictly
// includes a call to nng_tcp_listener_close().
NNG_DECL void nng_tcp_listener_free(nng_tcp_listener *);

// nng_tcp_listener_listen binds to the TCP address and arranges for
// the TCP port / address to be allocated.  It does not accept any new
// incoming connections.  (The listenq depth is configured to some reasonable
// default -- typically around 128.)  This operation is synchronous.
// On success, the sockaddr will be update with the actual address bound.
// This is useful if the TCP port number 0 is specified, which permits
// the implementation to choose a free random port.  The caller can then
// inspect the sockaddr to learn the actual bound port.
NNG_DECL int nng_tcp_listener_listen(nng_tcp_listener *, nng_sockaddr *);

// nng_tcp_listener_accept accepts an incoming connection (creating an
// nng_tcp * object), and returns it in the nng_aio as the first output
// on success.
NNG_DECL void nng_tcp_listener_accept(nng_tcp_listener *, nng_aio *);

#ifdef __cplusplus
}
#endif

#endif // NNG_SUPPLEMENTAL_TCP_TCP_H
