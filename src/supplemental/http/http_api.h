//
// Copyright 2019 Staysail Systems, Inc. <info@staysail.tech>
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
#include <nng/supplemental/http/http.h>
#include <nng/supplemental/tls/tls.h>

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

extern const char *nni_http_reason(uint16_t);

extern int   nni_http_req_init(nni_http_req **);
extern void  nni_http_req_reset(nni_http_req *);
extern int   nni_http_req_get_buf(nni_http_req *, void **, size_t *);
extern int   nni_http_req_parse(nni_http_req *, void *, size_t, size_t *);
extern char *nni_http_req_headers(nni_http_req *);
extern void  nni_http_req_get_data(nni_http_req *, void **, size_t *);

extern void  nni_http_res_reset(nni_http_res *);
extern int   nni_http_res_get_buf(nni_http_res *, void **, size_t *);
extern int   nni_http_res_parse(nni_http_res *, void *, size_t, size_t *);
extern void  nni_http_res_get_data(nni_http_res *, void **, size_t *);
extern char *nni_http_res_headers(nni_http_res *);

// Chunked transfer encoding.  For the moment this is not part of our public
// API.  We can change that later.

// nni_http_chunk_list_init creates a list of chunks, which shall not exceed
// the specified overall size.  (Size 0 means no limit.)
extern int nni_http_chunks_init(nni_http_chunks **, size_t);

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

extern int nni_http_chunks_parse(nni_http_chunks *, void *, size_t, size_t *);

extern void nni_http_read_chunks(
    nni_http_conn *, nni_http_chunks *, nni_aio *);

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
extern int nni_http_conn_init(nni_http_conn **, nng_stream *);

extern void nni_http_conn_close(nni_http_conn *);
extern void nni_http_conn_fini(nni_http_conn *);
extern int  nni_http_conn_getopt(
     nni_http_conn *, const char *, void *, size_t *, nni_type);
extern int nni_http_conn_setopt(
    nni_http_conn *, const char *, const void *, size_t, nni_type);

// Reading messages -- the caller must supply a preinitialized (but otherwise
// idle) message.  We recommend the caller store this in the aio's user data.
// Note that the iovs of the aio's are clobbered by these methods -- callers
// must not use them for any other purpose.

extern int  nni_http_req_alloc(nni_http_req **, const nni_url *);
extern int  nni_http_res_alloc(nni_http_res **);
extern int  nni_http_res_alloc_error(nni_http_res **, uint16_t);
extern void nni_http_req_free(nni_http_req *);
extern void nni_http_res_free(nni_http_res *);
extern void nni_http_write_req(nni_http_conn *, nni_http_req *, nni_aio *);
extern void nni_http_write_res(nni_http_conn *, nni_http_res *, nni_aio *);
extern void nni_http_read_req(nni_http_conn *, nni_http_req *, nni_aio *);
extern void nni_http_read_res(nni_http_conn *, nni_http_res *, nni_aio *);

extern const char *nni_http_req_get_header(nni_http_req *, const char *);
extern const char *nni_http_res_get_header(nni_http_res *, const char *);
extern int nni_http_req_add_header(nni_http_req *, const char *, const char *);
extern int nni_http_res_add_header(nni_http_res *, const char *, const char *);
extern int nni_http_req_set_header(nni_http_req *, const char *, const char *);
extern int nni_http_res_set_header(nni_http_res *, const char *, const char *);
extern int nni_http_req_del_header(nni_http_req *, const char *);
extern int nni_http_res_del_header(nni_http_res *, const char *);
extern int nni_http_req_copy_data(nni_http_req *, const void *, size_t);
extern int nni_http_res_copy_data(nni_http_res *, const void *, size_t);
extern int nni_http_req_set_data(nni_http_req *, const void *, size_t);
extern int nni_http_res_set_data(nni_http_res *, const void *, size_t);
extern int nni_http_req_alloc_data(nni_http_req *, size_t);
extern int nni_http_res_alloc_data(nni_http_res *, size_t);
extern const char *nni_http_req_get_method(nni_http_req *);
extern const char *nni_http_req_get_version(nni_http_req *);
extern const char *nni_http_req_get_uri(nni_http_req *);
extern int         nni_http_req_set_method(nni_http_req *, const char *);
extern int         nni_http_req_set_version(nni_http_req *, const char *);
extern int         nni_http_req_set_uri(nni_http_req *, const char *);
extern uint16_t    nni_http_res_get_status(nni_http_res *);
extern int         nni_http_res_set_status(nni_http_res *, uint16_t);
extern const char *nni_http_res_get_version(nni_http_res *);
extern int         nni_http_res_set_version(nni_http_res *, const char *);
extern const char *nni_http_res_get_reason(nni_http_res *);
extern int         nni_http_res_set_reason(nni_http_res *, const char *);

// nni_http_res_is_error is true if the status was allocated as part of
// nni_http_res_alloc_error().  This is a hint to the server to replace
// the HTML body with customized content if it exists.
extern bool nni_http_res_is_error(nni_http_res *);

// nni_http_alloc_html_error allocates a string corresponding to an
// HTML error.  This can be set as the body of the res.  The status
// will be looked up using HTTP status code lookups, but the details
// will be added if present as further body text.  The result can
// be freed with nni_strfree() later.
extern int nni_http_alloc_html_error(char **, uint16_t, const char *);

extern void nni_http_read(nni_http_conn *, nni_aio *);
extern void nni_http_read_full(nni_http_conn *, nni_aio *);
extern void nni_http_write(nni_http_conn *, nni_aio *);
extern void nni_http_write_full(nni_http_conn *, nni_aio *);

// nni_http_server will look for an existing server with the same
// name and port, or create one if one does not exist.  The servers
// are reference counted to permit sharing the server object across
// multiple subsystems.  The URL hostname matching is very limited,
// and the names must match *exactly* (without DNS resolution).  Unless
// a restricted binding is required, we recommend using a URL consisting
// of an empty host name, such as http://  or https://  -- this would
// convert to binding to the default port on all interfaces on the host.
extern int nni_http_server_init(nni_http_server **, const nni_url *);

// nni_http_server_fini drops the reference count on the server, and
// if this was the last reference, closes down the server and frees
// all related resources.  It will not affect hijacked connections.
extern void nni_http_server_fini(nni_http_server *);

// nni_http_server_add_handler registers a handler on the server.
// This function will return NNG_EADDRINUSE if a conflicting handler
// is already registered (i.e. a handler with the same value for Host,
// Method, and URL.)
extern int nni_http_server_add_handler(nni_http_server *, nni_http_handler *);

// nni_http_del_handler removes the given handler.  The caller is
// responsible for finalizing it afterwards.  If the handler was not found
// (not registered), NNG_ENOENT is returned.  In this case it is unsafe
// to make assumptions about the validity of the handler.
extern int nni_http_server_del_handler(nni_http_server *, nni_http_handler *);

// nni_http_server_set_tls adds a TLS configuration to the server,
// and enables the use of it.  This returns NNG_EBUSY if the server is
// already started.   This wipes out the entire TLS configuration on the
// server client, so the caller must have configured it reasonably.
// This API is not recommended unless the caller needs complete control
// over the TLS configuration.
extern int nni_http_server_set_tls(nni_http_server *, struct nng_tls_config *);

// nni_http_server_get_tls obtains the TLS configuration if one is present,
// or returns NNG_EINVAL.  The TLS configuration is invalidated if the
// nni_http_server_set_tls function is called, so be careful.
extern int nni_http_server_get_tls(
    nni_http_server *, struct nng_tls_config **);

extern int nni_http_server_setx(
    nni_http_server *, const char *, const void *, size_t, nni_type);
extern int nni_http_server_getx(
    nni_http_server *, const char *, void *, size_t *, nni_type);

// nni_http_server_start starts listening on the supplied port.
extern int nni_http_server_start(nni_http_server *);

// nni_http_server_stop stops the server, closing the listening socket.
// Connections that have been "upgraded" are unaffected.  Connections
// associated with a callback will complete their callback, and then close.
extern void nni_http_server_stop(nni_http_server *);

// nni_http_server_set_error_page sets an error page for the named status.
extern int nni_http_server_set_error_page(
    nni_http_server *, uint16_t, const char *);

// nni_http_server_set_error_page sets an error file for the named status.
extern int nni_http_server_set_error_file(
    nni_http_server *, uint16_t, const char *);

// nni_http_server_res_error takes replaces the body of the res with
// a custom error page previously set for the server, using the status
// of the res.  The res must have the status set first.
extern int nni_http_server_res_error(nni_http_server *, nni_http_res *);

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
extern int nni_http_hijack(nni_http_conn *);

// nni_http_handler_init creates a server handler object, for the supplied
// URI (path only) with the callback.
//
// Note that methods which modify a handler cannot be called while the handler
// is registered with the server, and that a handler can only be registered
// once per server.
//
// The callback function will receive the following arguments (via
// nng_aio_get_input(): nni_http_request *, nni_http_handler *, and
// nni_http_conn_t *.  The first is a request object, for convenience.
// The second is the handler, from which the callback can obtain any other
// data it has set.  The final is the http context, from which its possible
// to hijack the session.
extern int nni_http_handler_init(
    nni_http_handler **, const char *, void (*)(nni_aio *));

// nni_http_handler_init_file creates a handler with a function to serve
// up a file named in the last argument.
extern int nni_http_handler_init_file(
    nni_http_handler **, const char *, const char *);

// nni_http_handler_init_file_ctype is like nni_http_handler_init_file, but
// provides for setting the Content-Type explicitly (last argument).
extern int nni_http_handler_init_file_ctype(
    nni_http_handler **, const char *, const char *, const char *);

// nni_http_handler_init_directory arranges to serve up an entire
// directory tree.  The content types are determined from the built-in
// content type list.  Actual directories are required to contain a
// file called index.html or index.htm.  We do not generate directory
// listings for security reasons.
extern int nni_http_handler_init_directory(
    nni_http_handler **, const char *, const char *);

// nni_http_handler_init_static creates a handler that serves up static content
// supplied, with the Content-Type supplied in the final argument.
extern int nni_http_handler_init_static(
    nni_http_handler **, const char *, const void *, size_t, const char *);

// nni_http_handler_init_redirect creates a handler that redirects the request.
extern int nni_http_handler_init_redirect(
    nni_http_handler **, const char *, uint16_t, const char *);

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
extern int nni_http_handler_set_tree(nni_http_handler *);

// nni_http_handler_set_tree_exclusive marks the handler as servicing the
// entire tree (e.g. a directory) exclusively, rather than just a leaf node.
// When servicing a tree exclusively, other handlers sharing parts of the uri
// will induce an address conflict when adding them to a server. The handler
// will probably need to inspect the URL of the request.
extern int nni_http_handler_set_tree_exclusive(nni_http_handler *);

// nni_http_handler_set_host limits the handler to only being called for
// the given Host: field.  This can be used to set up multiple virtual
// hosts.  Note that host names must match exactly.  If NULL or an empty
// string is specified, then the client's Host: field is ignored.  (The
// supplied value for the Host is copied by this function.)  When supplying
// a hostname, do not include a value for the port number; we do not match
// on port number as we assume that clients MUST have gotten that part right
// as we do not support virtual hosting on multiple separate ports; the
// server only listens on a single port.
extern int nni_http_handler_set_host(nni_http_handler *, const char *);

// nni_http_handler_set_method limits the handler to only being called
// for the given HTTP method.  By default a handler is called for GET
// methods only (and HEAD, which is handled internally.)  Handlers can
// be specified for any valid HTTP method.  A handler may set the value
// NULL here, to be called for any HTTP method.  In such a case, the handler
// is obligated to inspect the method.  (Note: the passed method must be
// in upper case and should come from a statically allocated string; the
// server does not make its own copy.)
extern int nni_http_handler_set_method(nni_http_handler *, const char *);

// nni_http_handler_set_data sets an opaque data element on the handler,
// which will be available to the callback via nni_http_handler_get_data.
// The callback is an optional destructor, and will be called with the
// data as its argument, when the handler is being destroyed.
extern int nni_http_handler_set_data(nni_http_handler *, void *, nni_cb);

// nni_http_handler_get_data returns the data that was previously stored
// at that index.  It returns NULL if no data was set, or an invalid index
// is supplied.
extern void *nni_http_handler_get_data(nni_http_handler *);

// nni_http_handler_get_uri returns the URI set on the handler.
extern const char *nni_http_handler_get_uri(nni_http_handler *);

// Client stuff.

extern int  nni_http_client_init(nni_http_client **, const nni_url *);
extern void nni_http_client_fini(nni_http_client *);

// nni_http_client_set_tls sets the TLS configuration.  This wipes out
// the entire TLS configuration on the client, so the caller must have
// configured it reasonably.  This API is not recommended unless the
// caller needs complete control over the TLS configuration.
extern int nni_http_client_set_tls(nni_http_client *, struct nng_tls_config *);

// nni_http_client_get_tls obtains the TLS configuration if one is present,
// or returns NNG_EINVAL.  The supplied TLS configuration object may
// be invalidated by any future calls to nni_http_client_set_tls.
extern int nni_http_client_get_tls(
    nni_http_client *, struct nng_tls_config **);

extern int nni_http_client_setx(
    nni_http_client *, const char *, const void *, size_t, nni_type);
extern int nni_http_client_getx(
    nni_http_client *, const char *, void *, size_t *, nni_type);

extern void nni_http_client_connect(nni_http_client *, nni_aio *);

// nni_http_transact_conn is used to perform a round-trip exchange (i.e. a
// single HTTP transaction).  It will not automatically close the connection,
// unless some kind of significant error occurs.  The caller should dispose
// of the connection if the aio does not complete successfully.
// Note that this will fail with NNG_ENOTSUP if the server attempts to reply
// with a chunked transfer encoding.
extern void nni_http_transact_conn(
    nni_http_conn *, nni_http_req *, nni_http_res *, nni_aio *);

// nni_http_transact is used to execute a single transaction to a server.
// The connection is opened, and will be closed when the transaction is
// complete.  Note that this will fail with NNG_ENOTSUP if the server attempts
// to reply with a chunked transfer encoding.
extern void nni_http_transact(
    nni_http_client *, nni_http_req *, nni_http_res *, nni_aio *);

#endif // NNG_SUPPLEMENTAL_HTTP_HTTP_API_H
