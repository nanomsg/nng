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

#ifndef NNG_SUPPLEMENTAL_HTTP_HTTP_API_H
#define NNG_SUPPLEMENTAL_HTTP_HTTP_API_H

#include "core/nng_impl.h"
#include "nng/http.h"

#include "http_msg.h"

// This represents the "internal" HTTP API.  It should not be used
// or exposed to applications directly.

#include <stdbool.h>

typedef struct nng_http_req    nni_http_req;
typedef struct nng_http_res    nni_http_res;
typedef struct nng_http_server nni_http_server;
typedef struct nng_http_chunk  nni_http_chunk;
typedef struct nng_http_chunks nni_http_chunks;

// These functions are private to the internal framework, and really should
// not be used elsewhere.

extern void    nni_http_req_init(nni_http_req *);
extern void    nni_http_req_reset(nni_http_req *);
extern nng_err nni_http_req_parse(nng_http *, void *, size_t, size_t *);

extern void    nni_http_res_init(nni_http_res *);
extern void    nni_http_res_reset(nni_http_res *);
extern nng_err nni_http_res_parse(nng_http *, void *, size_t, size_t *);

// Chunked transfer encoding.  For the moment this is not part of our public
// API.  We can change that later.

// nni_http_chunk_list_init creates a list of chunks, which shall not exceed
// the specified overall size.  (Size 0 means no limit.)
extern nng_err nni_http_chunks_init(nni_http_chunks **, size_t);

extern void nni_http_chunks_free(nni_http_chunks *);

// nni_http_chunk_iter iterates over all chunks in the list.
// Pass NULL for the last chunk to start at the head.  Returns NULL when done.
extern nni_http_chunk *nni_http_chunks_iter(
    nni_http_chunks *, nni_http_chunk *);

// nni_http_chunk_list_size returns the combined size of all chunks in list.
extern size_t nni_http_chunks_size(nni_http_chunks *);

// nni_http_chunk_size returns the size of given chunk.
extern size_t nni_http_chunk_size(nni_http_chunk *);
// nni_http_chunk_data returns a pointer to the data.
extern void *nni_http_chunk_data(nni_http_chunk *);

extern nng_err nni_http_chunks_parse(
    nni_http_chunks *, void *, size_t, size_t *);

extern void nni_http_read_chunks(nng_http *, nni_http_chunks *, nni_aio *);

extern nni_http_req *nni_http_conn_req(nng_http *);
extern nni_http_res *nni_http_conn_res(nng_http *);

// Private to the server. (Used to support session hijacking.)
extern void  nni_http_conn_set_ctx(nng_http *, void *);
extern void *nni_http_conn_get_ctx(nng_http *);

// An HTTP connection is a connection over which messages are exchanged.
// Generally, clients send request messages, and then read responses.
// Servers, read requests, and write responses.  However, we do not
// require a 1:1 mapping between request and response here -- the application
// is responsible for dealing with that.
//
// We only support HTTP/1.1, though using the nni_http_read and
// nni_http_write low level methods, it is possible to write an upgrader
// (such as websocket!) that might support e.g. HTTP/2 or reading data that
// follows a legacy HTTP/1.0 message.
//
// Any error on the connection, including cancellation of a request, is fatal
// the connection.

// These initialization functions create stream for HTTP transactions.
// They should only be used by the server or client HTTP implementations,
// and are not for use by other code.
extern nng_err nni_http_init(nng_http **, nng_stream *, bool);

extern void nni_http_conn_close(nng_http *);
extern void nni_http_conn_fini(nng_http *);
extern int  nni_http_conn_getopt(
     nng_http *, const char *, void *, size_t *, nni_type);

// Reading messages -- the caller must supply a preinitialized (but otherwise
// idle) message.  We recommend the caller store this in the aio's user data.
// Note that the iovs of the aio's are clobbered by these methods -- callers
// must not use them for any other purpose.

extern void nni_http_write_req(nng_http *, nni_aio *);
extern void nni_http_read_res(nng_http *, nni_aio *);
extern void nni_http_read_req(nng_http *, nni_aio *);
extern void nni_http_write_res(nng_http *, nni_aio *);
extern void nni_http_read_discard(nng_http *, size_t, nni_aio *);

extern nng_err nni_http_req_alloc_data(nni_http_req *, size_t);
extern nng_err nni_http_res_alloc_data(nni_http_res *, size_t);

extern bool nni_http_is_error(nng_http *);

extern void nni_http_read(nng_http *, nni_aio *);
extern void nni_http_read_full(nng_http *, nni_aio *);
extern void nni_http_write(nng_http *, nni_aio *);
extern void nni_http_write_full(nng_http *, nni_aio *);

// prune body clears the outgoing body (0 bytes), but leaves content-length
// intact if present for the benefit of HEAD.
extern void nni_http_prune_body(nng_http *);

// nni_http_server will look for an existing server with the same
// name and port, or create one if one does not exist.  The servers
// are reference counted to permit sharing the server object across
// multiple subsystems.  The URL hostname matching is very limited,
// and the names must match *exactly* (without DNS resolution).  Unless
// a restricted binding is required, we recommend using a URL consisting
// of an empty host name, such as http://  or https://  -- this would
// convert to binding to the default port on all interfaces on the host.
extern nng_err nni_http_server_init(nni_http_server **, const nng_url *);

// nni_http_server_fini drops the reference count on the server, and
// if this was the last reference, closes down the server and frees
// all related resources.  It will not affect hijacked connections.
extern void nni_http_server_fini(nni_http_server *);

// nni_http_server_add_handler registers a handler on the server.
// This function will return NNG_EADDRINUSE if a conflicting handler
// is already registered (i.e. a handler with the same value for Host,
// Method, and URL.)
extern nng_err nni_http_server_add_handler(
    nni_http_server *, nng_http_handler *);

// nni_http_del_handler removes the given handler.  The caller is
// responsible for finalizing it afterwards.  If the handler was not found
// (not registered), NNG_ENOENT is returned.  In this case it is unsafe
// to make assumptions about the validity of the handler.
extern nng_err nni_http_server_del_handler(
    nni_http_server *, nng_http_handler *);

// nni_http_server_set_tls adds a TLS configuration to the server,
// and enables the use of it.  This returns NNG_EBUSY if the server is
// already started.   This wipes out the entire TLS configuration on the
// server client, so the caller must have configured it reasonably.
// This API is not recommended unless the caller needs complete control
// over the TLS configuration.
extern nng_err nni_http_server_set_tls(
    nni_http_server *, struct nng_tls_config *);

// nni_http_server_get_tls obtains the TLS configuration if one is present,
// or returns NNG_EINVAL.  The TLS configuration is invalidated if the
// nni_http_server_set_tls function is called, so be careful.
extern nng_err nni_http_server_get_tls(
    nni_http_server *, struct nng_tls_config **);

extern int nni_http_server_set(
    nni_http_server *, const char *, const void *, size_t, nni_type);
extern int nni_http_server_get(
    nni_http_server *, const char *, void *, size_t *, nni_type);

// nni_http_server_start starts listening on the supplied port.
extern nng_err nni_http_server_start(nni_http_server *);

// nni_http_server_stop stops the server, closing the listening socket.
// Connections that have been "upgraded" are unaffected.  Connections
// associated with a callback will complete their callback, and then close.
// Connections will be aborted but may not have terminated all the way.
extern void nni_http_server_stop(nni_http_server *);

// nni_http_server_close closes down the socket, but does not shut down
// any connections that are already open.  This is useful for example
// when shutting down an SP listener, and we don't want to break established
// sessions.
extern void nni_http_server_close(nni_http_server *);

// nni_http_server_set_error_page sets an error page for the named status.
extern nng_err nni_http_server_set_error_page(
    nni_http_server *, nng_http_status, const char *);

// nni_http_server_res_error takes replaces the body of the res with
// a custom error page previously set for the server, using the status
// of the res.  The res must have the status set first.
extern nng_err nni_http_server_error(nni_http_server *, nng_http *);

// Client stuff.

// nni_http_client_set_tls sets the TLS configuration.  This wipes out
// the entire TLS configuration on the client, so the caller must have
// configured it reasonably.  This API is not recommended unless the
// caller needs complete control over the TLS configuration.
extern nng_err nni_http_client_set_tls(
    nng_http_client *, struct nng_tls_config *);

// nni_http_client_get_tls obtains the TLS configuration if one is present,
// or returns NNG_EINVAL.  The supplied TLS configuration object may
// be invalidated by any future calls to nni_http_client_set_tls.
extern nng_err nni_http_client_get_tls(
    nng_http_client *, struct nng_tls_config **);

extern int nni_http_client_set(
    nng_http_client *, const char *, const void *buf, size_t, nni_type);
extern int nni_http_client_get(
    nng_http_client *, const char *, void *, size_t *, nni_type);

// nni_http_stream_scheme returns the underlying stream scheme for a given
// upper layer scheme.
extern const char *nni_http_stream_scheme(const char *);

// Private method used for the server.
extern bool nni_http_res_sent(nng_http *conn);

// nni_http_set_error flags an error using the built in HTML page.
// unless body is not NULL.  To pass no content, pass an empty string for body.
extern nng_err nni_http_set_error(nng_http *conn, nng_http_status status,
    const char *reason, const char *body);

// nni_http_set_redirect is used to set the redirection.
// It uses a built-in error page, with a message about the redirection, and
// sets the response Location: header accordingly.
extern nng_err nni_http_set_redirect(nng_http *conn, nng_http_status status,
    const char *reason, const char *dest);

extern void nni_http_set_host(nng_http *conn, const char *);
extern void nni_http_set_content_type(nng_http *conn, const char *);
extern void nni_http_conn_reset(nng_http *conn);

extern void nni_http_set_static_header(
    nng_http *conn, nni_http_header *header, const char *key, const char *val);

extern bool nni_http_parsed(nng_http *conn);

#endif // NNG_SUPPLEMENTAL_HTTP_HTTP_API_H
