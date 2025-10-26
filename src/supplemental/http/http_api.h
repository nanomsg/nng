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

#include "../../core/defs.h"
#include "http_msg.h"
#include "nng/http.h"

// This represents the "internal" HTTP API.  It should not be used
// or exposed to applications directly.

#include <stdbool.h>

typedef struct nng_http_req     nni_http_req;
typedef struct nng_http_res     nni_http_res;
typedef struct nng_http_conn    nni_http_conn;
typedef struct nng_http_handler nni_http_handler;
typedef struct nng_http_server  nni_http_server;
typedef struct nng_http_client  nni_http_client;
typedef struct nng_http_chunk   nni_http_chunk;
typedef struct nng_http_chunks  nni_http_chunks;

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

extern void nni_http_read_chunks(
    nni_http_conn *, nni_http_chunks *, nng_aio *);

extern nni_http_req *nni_http_conn_req(nni_http_conn *);
extern nni_http_res *nni_http_conn_res(nni_http_conn *);

extern const nng_sockaddr *nni_http_peer_addr(nni_http_conn *);
extern const nng_sockaddr *nni_http_self_addr(nni_http_conn *);

// Private to the server. (Used to support session hijacking.)
extern void  nni_http_conn_set_ctx(nni_http_conn *, void *);
extern void *nni_http_conn_get_ctx(nni_http_conn *);

// An HTTP connection is a connection over which messages are exchanged.
// Generally, clients send request messages, and then read responses.
// Servers, read requests, and write responses.  However, we do not
// require a 1:1 mapping between request and response here -- the application
// is responsible for dealing with that.
//
// We only support HTTP/1.1, though using the nni_http_conn_read and
// nni_http_conn_write low level methods, it is possible to write an upgrader
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
extern void nni_http_conn_fini(nni_http_conn *);
extern int  nni_http_conn_getopt(
     nng_http *, const char *, void *, size_t *, nni_type);
extern nng_err nni_http_conn_peer_cert(nng_http *, nng_tls_cert **);

// Reading messages -- the caller must supply a preinitialized (but otherwise
// idle) message.  We recommend the caller store this in the aio's user data.
// Note that the iovs of the aio's are clobbered by these methods -- callers
// must not use them for any other purpose.

extern void nni_http_write_req(nni_http_conn *, nng_aio *);
extern void nni_http_read_res(nni_http_conn *, nng_aio *);
extern void nni_http_read_req(nni_http_conn *, nng_aio *);
extern void nni_http_write_res(nni_http_conn *, nng_aio *);
extern void nni_http_read_discard(nni_http_conn *, size_t, nng_aio *);

extern nng_err nni_http_req_alloc_data(nni_http_req *, size_t);
extern nng_err nni_http_res_alloc_data(nni_http_res *, size_t);

extern bool nni_http_is_error(nng_http *);

extern void nni_http_read(nni_http_conn *, nng_aio *);
extern void nni_http_read_full(nni_http_conn *, nng_aio *);
extern void nni_http_write(nni_http_conn *, nng_aio *);
extern void nni_http_write_full(nni_http_conn *, nng_aio *);

extern nng_err     nni_http_add_header(nng_http *, const char *, const char *);
extern nng_err     nni_http_set_header(nng_http *, const char *, const char *);
extern void        nni_http_del_header(nng_http *, const char *);
extern const char *nni_http_get_header(nng_http *, const char *);
extern bool        nni_http_next_header(
           nng_http *, const char **, const char **, void **);

extern void    nni_http_get_body(nng_http *, void **, size_t *);
extern void    nni_http_set_body(nng_http *, void *, size_t);
extern nng_err nni_http_copy_body(nng_http *, const void *, size_t);

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
    nni_http_server *, nni_http_handler *);

// nni_http_del_handler removes the given handler.  The caller is
// responsible for finalizing it afterwards.  If the handler was not found
// (not registered), NNG_ENOENT is returned.  In this case it is unsafe
// to make assumptions about the validity of the handler.
extern nng_err nni_http_server_del_handler(
    nni_http_server *, nni_http_handler *);

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

// nni_http_hijack is intended to be called by a handler that wishes to
// take over the processing of the HTTP session -- usually to change protocols
// (such as in the case of websocket).  The caller is responsible for obtaining
// and disposal of the associated nni_http session.  Also, this completely
// disassociates the http session from the server, so the server may be
// stopped or destroyed without affecting the hijacked session.  Note also
// that the hijacker will need to issue any HTTP reply itself.  Finally,
// when a session is hijacked, the caller is also responsible for disposing
// of the request structure.  (Some hijackers may keep the request for
// further processing.)
extern nng_err nni_http_hijack(nni_http_conn *);

// nni_http_handler_init creates a server handler object, for the supplied
// URI (path only) with the callback.
//
// Note that methods which modify a handler cannot be called while the handler
// is registered with the server, and that a handler can only be registered
// once per server.
extern nng_err nni_http_handler_init(
    nni_http_handler **, const char *, nng_http_handler_func);

// nni_http_handler_init_file creates a handler with a function to serve
// up a file named in the last argument.
extern nng_err nni_http_handler_init_file(
    nni_http_handler **, const char *, const char *);

// nni_http_handler_init_file_ctype is like nni_http_handler_init_file, but
// provides for setting the Content-Type explicitly (last argument).
extern nng_err nni_http_handler_init_file_ctype(
    nni_http_handler **, const char *, const char *, const char *);

// nni_http_handler_init_directory arranges to serve up an entire
// directory tree.  The content types are determined from the built-in
// content type list.  Actual directories are required to contain a
// file called index.html or index.htm.  We do not generate directory
// listings for security reasons.
extern nng_err nni_http_handler_init_directory(
    nni_http_handler **, const char *, const char *);

// nni_http_handler_init_static creates a handler that serves up static content
// supplied, with the Content-Type supplied in the final argument.
extern nng_err nni_http_handler_init_static(
    nni_http_handler **, const char *, const void *, size_t, const char *);

// nni_http_handler_init_redirect creates a handler that redirects the request.
extern nng_err nni_http_handler_init_redirect(
    nni_http_handler **, const char *, nng_http_status, const char *);

// nni_http_handler_fini destroys a handler.  This should only be done before
// the handler is added, or after it is deleted.  The server automatically
// calls this for any handlers still registered with it if it is destroyed.
extern void nni_http_handler_fini(nni_http_handler *);

// nni_http_handler_collect_body informs the server that it should collect
// the entitty data associated with the client request, and sets the maximum
// size to accept.
extern void nni_http_handler_collect_body(nni_http_handler *, bool, size_t);

// nni_http_handler_set_tree marks the handler as servicing the entire
// tree (e.g. a directory), rather than just a leaf node.  The handler
// will probably need to inspect the URL of the request.
extern void nni_http_handler_set_tree(nni_http_handler *);

// nni_http_handler_set_host limits the handler to only being called for
// the given Host: field.  This can be used to set up multiple virtual
// hosts.  Note that host names must match exactly.  If NULL or an empty
// string is specified, then the client's Host: field is ignored.  (The
// supplied value for the Host is copied by this function.)  When supplying
// a hostname, do not include a value for the port number; we do not match
// on port number as we assume that clients MUST have gotten that part right
// as we do not support virtual hosting on multiple separate ports; the
// server only listens on a single port.
extern void nni_http_handler_set_host(nni_http_handler *, const char *);

// nni_http_handler_set_method limits the handler to only being called
// for the given HTTP method.  By default a handler is called for GET
// methods only (and HEAD, which is handled internally.)  Handlers can
// be specified for any valid HTTP method.  A handler may set the value
// NULL here, to be called for any HTTP method.  In such a case, the handler
// is obligated to inspect the method.  (Note: the passed method must be
// in upper case and should come from a statically allocated string; the
// server does not make its own copy.)
extern void nni_http_handler_set_method(nni_http_handler *, const char *);

// nni_http_handler_set_data sets an opaque data element on the handler,
// which will be available to the handler function as argument.
// The callback is an optional destructor, and will be called with the
// data as its argument, when the handler is being destroyed.
extern void nni_http_handler_set_data(nni_http_handler *, void *, nni_cb);

// nni_http_handler_get_uri returns the URI set on the handler.
extern const char *nni_http_handler_get_uri(nni_http_handler *);

// Client stuff.

extern nng_err nni_http_client_init(nni_http_client **, const nng_url *);
extern void    nni_http_client_fini(nni_http_client *);

// nni_http_client_set_tls sets the TLS configuration.  This wipes out
// the entire TLS configuration on the client, so the caller must have
// configured it reasonably.  This API is not recommended unless the
// caller needs complete control over the TLS configuration.
extern nng_err nni_http_client_set_tls(
    nni_http_client *, struct nng_tls_config *);

// nni_http_client_get_tls obtains the TLS configuration if one is present,
// or returns NNG_EINVAL.  The supplied TLS configuration object may
// be invalidated by any future calls to nni_http_client_set_tls.
extern nng_err nni_http_client_get_tls(
    nni_http_client *, struct nng_tls_config **);

extern int nni_http_client_set(
    nni_http_client *, const char *, const void *buf, size_t, nni_type);
extern int nni_http_client_get(
    nni_http_client *, const char *, void *, size_t *, nni_type);

extern void nni_http_client_connect(nni_http_client *, nng_aio *);

// nni_http_transact_conn is used to perform a round-trip exchange (i.e. a
// single HTTP transaction).  It will not automatically close the connection,
// unless some kind of significant error occurs.  The caller should dispose
// of the connection if the aio does not complete successfully.
// Note that this will fail with NNG_ENOTSUP if the server attempts to reply
// with a chunked transfer encoding.  The request and response used are the
// ones associated with the connection.
extern void nni_http_transact_conn(nni_http_conn *, nng_aio *);

// nni_http_transact is used to execute a single transaction to a server.
// The connection is opened, and will be closed when the transaction is
// complete.  Note that this will fail with NNG_ENOTSUP if the server attempts
// to reply with a chunked transfer encoding.
extern void nni_http_transact(
    nni_http_client *, nni_http_req *, nni_http_res *, nng_aio *);

// nni_http_stream_scheme returns the underlying stream scheme for a given
// upper layer scheme.
extern const char *nni_http_stream_scheme(const char *);

// Private method used for the server.
extern bool nni_http_res_sent(nni_http_conn *conn);

extern const char *nni_http_get_version(nng_http *conn);
extern int         nni_http_set_version(nng_http *conn, const char *vers);

extern void        nni_http_set_method(nng_http *conn, const char *method);
extern const char *nni_http_get_method(nng_http *conn);

extern void nni_http_set_status(
    nng_http *conn, nng_http_status status, const char *reason);

extern nng_http_status nni_http_get_status(nng_http *);
extern const char     *nni_http_get_reason(nng_http *);

// nni_http_set_error flags an error using the built in HTML page.
// unless body is not NULL.  To pass no content, pass an empty string for body.
extern nng_err nni_http_set_error(nng_http *conn, nng_http_status status,
    const char *reason, const char *body);

// nni_http_set_redirect is used to set the redirection.
// It uses a built-in error page, with a message about the redirection, and
// sets the response Location: header accordingly.
extern nng_err nni_http_set_redirect(nng_http *conn, nng_http_status status,
    const char *reason, const char *dest);

extern nng_err nni_http_set_uri(
    nng_http *conn, const char *uri, const char *query);
extern const char *nni_http_get_uri(nng_http *conn);

extern void nni_http_set_host(nng_http *conn, const char *);
extern void nni_http_set_content_type(nng_http *conn, const char *);
extern void nni_http_conn_reset(nng_http *conn);

extern void nni_http_set_static_header(
    nng_http *conn, nni_http_header *header, const char *key, const char *val);

extern bool nni_http_parsed(nng_http *conn);

#endif // NNG_SUPPLEMENTAL_HTTP_HTTP_API_H
