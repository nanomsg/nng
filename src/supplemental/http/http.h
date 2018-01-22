//
// Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#ifndef NNG_SUPPLEMENTAL_HTTP_HTTP_H
#define NNG_SUPPLEMENTAL_HTTP_HTTP_H

#include <stdbool.h>

typedef struct nni_http_res    nni_http_res;
typedef struct nni_http_entity nni_http_entity;

typedef struct nni_http_req nni_http_req;

extern int  nni_http_req_init(nni_http_req **);
extern void nni_http_req_fini(nni_http_req *);
extern void nni_http_req_reset(nni_http_req *);
extern int nni_http_req_set_header(nni_http_req *, const char *, const char *);
extern int nni_http_req_add_header(nni_http_req *, const char *, const char *);
extern int nni_http_req_del_header(nni_http_req *, const char *);
extern int nni_http_req_get_buf(nni_http_req *, void **, size_t *);
extern int nni_http_req_set_method(nni_http_req *, const char *);
extern int nni_http_req_set_version(nni_http_req *, const char *);
extern int nni_http_req_set_uri(nni_http_req *, const char *);
extern const char *nni_http_req_get_header(nni_http_req *, const char *);
extern const char *nni_http_req_get_header(nni_http_req *, const char *);
extern const char *nni_http_req_get_version(nni_http_req *);
extern const char *nni_http_req_get_uri(nni_http_req *);
extern const char *nni_http_req_get_method(nni_http_req *);
extern int   nni_http_req_parse(nni_http_req *, void *, size_t, size_t *);
extern char *nni_http_req_headers(nni_http_req *);

extern int  nni_http_res_init(nni_http_res **);
extern void nni_http_res_fini(nni_http_res *);
extern void nni_http_res_reset(nni_http_res *);
extern int  nni_http_res_get_buf(nni_http_res *, void **, size_t *);
extern int nni_http_res_set_header(nni_http_res *, const char *, const char *);
extern int nni_http_res_add_header(nni_http_res *, const char *, const char *);
extern int nni_http_res_del_header(nni_http_res *, const char *);
extern int nni_http_res_set_version(nni_http_res *, const char *);
extern int nni_http_res_set_status(nni_http_res *, int, const char *);
extern const char *nni_http_res_get_header(nni_http_res *, const char *);
extern const char *nni_http_res_get_version(nni_http_res *);
extern const char *nni_http_res_get_reason(nni_http_res *);
extern int         nni_http_res_get_status(nni_http_res *);
extern int   nni_http_res_parse(nni_http_res *, void *, size_t, size_t *);
extern int   nni_http_res_set_data(nni_http_res *, const void *, size_t);
extern int   nni_http_res_copy_data(nni_http_res *, const void *, size_t);
extern int   nni_http_res_alloc_data(nni_http_res *, size_t);
extern void  nni_http_res_get_data(nni_http_res *, void **, size_t *);
extern int   nni_http_res_init_error(nni_http_res **, uint16_t);
extern char *nni_http_res_headers(nni_http_res *);

// HTTP status codes.  This list is not exhaustive.
enum { NNI_HTTP_STATUS_CONTINUE                  = 100,
	NNI_HTTP_STATUS_SWITCHING                = 101,
	NNI_HTTP_STATUS_PROCESSING               = 102,
	NNI_HTTP_STATUS_OK                       = 200,
	NNI_HTTP_STATUS_CREATED                  = 201,
	NNI_HTTP_STATUS_ACCEPTED                 = 202,
	NNI_HTTP_STATUS_NOT_AUTHORITATIVE        = 203,
	NNI_HTTP_STATUS_NO_CONTENT               = 204,
	NNI_HTTP_STATUS_RESET_CONTENT            = 205,
	NNI_HTTP_STATUS_PARTIAL_CONTENT          = 206,
	NNI_HTTP_STATUS_MULTI_STATUS             = 207,
	NNI_HTTP_STATUS_ALREADY_REPORTED         = 208,
	NNI_HTTP_STATUS_IM_USED                  = 226,
	NNI_HTTP_STATUS_MULTIPLE_CHOICES         = 300,
	NNI_HTTP_STATUS_STATUS_MOVED_PERMANENTLY = 301,
	NNI_HTTP_STATUS_FOUND                    = 302,
	NNI_HTTP_STATUS_SEE_OTHER                = 303,
	NNI_HTTP_STATUS_NOT_MODIFIED             = 304,
	NNI_HTTP_STATUS_USE_PROXY                = 305,
	NNI_HTTP_STATUS_TEMPORARY_REDIRECT       = 307,
	NNI_HTTP_STATUS_PERMANENT_REDIRECT       = 308,
	NNI_HTTP_STATUS_BAD_REQUEST              = 400,
	NNI_HTTP_STATUS_UNAUTHORIZED             = 401,
	NNI_HTTP_STATUS_PAYMENT_REQUIRED         = 402,
	NNI_HTTP_STATUS_FORBIDDEN                = 403,
	NNI_HTTP_STATUS_NOT_FOUND                = 404,
	NNI_HTTP_STATUS_METHOD_NOT_ALLOWED       = 405,
	NNI_HTTP_STATUS_NOT_ACCEPTABLE           = 406,
	NNI_HTTP_STATUS_PROXY_AUTH_REQUIRED      = 407,
	NNI_HTTP_STATUS_REQUEST_TIMEOUT          = 408,
	NNI_HTTP_STATUS_CONFLICT                 = 409,
	NNI_HTTP_STATUS_GONE                     = 410,
	NNI_HTTP_STATUS_LENGTH_REQUIRED          = 411,
	NNI_HTTP_STATUS_PRECONDITION_FAILED      = 412,
	NNI_HTTP_STATUS_PAYLOAD_TOO_LARGE        = 413,
	NNI_HTTP_STATUS_URI_TOO_LONG             = 414,
	NNI_HTTP_STATUS_UNSUPPORTED_MEDIA_TYPE   = 415,
	NNI_HTTP_STATUS_RANGE_NOT_SATISFIABLE    = 416,
	NNI_HTTP_STATUS_EXPECTATION_FAILED       = 417,
	NNI_HTTP_STATUS_TEAPOT                   = 418,
	NNI_HTTP_STATUS_UNPROCESSABLE_ENTITY     = 422,
	NNI_HTTP_STATUS_LOCKED                   = 423,
	NNI_HTTP_STATUS_FAILED_DEPENDENCY        = 424,
	NNI_HTTP_STATUS_UPGRADE_REQUIRED         = 426,
	NNI_HTTP_STATUS_PRECONDITION_REQUIRED    = 428,
	NNI_HTTP_STATUS_TOO_MANY_REQUESTS        = 429,
	NNI_HTTP_STATUS_HEADERS_TOO_LARGE        = 431,
	NNI_HTTP_STATUS_UNAVAIL_LEGAL_REASONS    = 451,
	NNI_HTTP_STATUS_INTERNAL_SERVER_ERROR    = 500,
	NNI_HTTP_STATUS_NOT_IMPLEMENTED          = 501,
	NNI_HTTP_STATUS_BAD_GATEWAY              = 502,
	NNI_HTTP_STATUS_SERVICE_UNAVAILABLE      = 503,
	NNI_HTTP_STATUS_GATEWAY_TIMEOUT          = 504,
	NNI_HTTP_STATUS_HTTP_VERSION_NOT_SUPP    = 505,
	NNI_HTTP_STATUS_VARIANT_ALSO_NEGOTIATES  = 506,
	NNI_HTTP_STATUS_INSUFFICIENT_STORAGE     = 507,
	NNI_HTTP_STATUS_LOOP_DETECTED            = 508,
	NNI_HTTP_STATUS_NOT_EXTENDED             = 510,
	NNI_HTTP_STATUS_NETWORK_AUTH_REQUIRED    = 511,
};

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
typedef struct nni_http nni_http;

// These initialization functions create stream for HTTP transactions.
// They should only be used by the server or client HTTP implementations,
// and are not for use by other code.
extern int nni_http_init_tcp(nni_http **, void *);
extern int nni_http_init_tls(nni_http **, nng_tls_config *, void *);

extern void nni_http_close(nni_http *);
extern void nni_http_fini(nni_http *);

// Reading messages -- the caller must supply a preinitialized (but otherwise
// idle) message.  We recommend the caller store this in the aio's user data.
// Note that the iovs of the aio's are clobbered by these methods -- callers
// must not use them for any other purpose.

extern void nni_http_write_req(nni_http *, nni_http_req *, nni_aio *);
extern void nni_http_write_res(nni_http *, nni_http_res *, nni_aio *);
extern void nni_http_read_req(nni_http *, nni_http_req *, nni_aio *);
extern void nni_http_read_res(nni_http *, nni_http_res *, nni_aio *);

extern void nni_http_read(nni_http *, nni_aio *);
extern void nni_http_read_full(nni_http *, nni_aio *);
extern void nni_http_write(nni_http *, nni_aio *);
extern void nni_http_write_full(nni_http *, nni_aio *);
extern int  nni_http_sock_addr(nni_http *, nni_sockaddr *);
extern int  nni_http_peer_addr(nni_http *, nni_sockaddr *);

// nni_tls_http_verified returns true if the peer has been verified using TLS.
extern bool nni_http_tls_verified(nni_http *);

typedef struct nni_http_server  nni_http_server;
typedef struct nni_http_handler nni_http_handler;

// nni_http_server will look for an existing server with the same
// name and port, or create one if one does not exist.  The servers
// are reference counted to permit sharing the server object across
// multiple subsystems.  The URL hostname matching is very limited,
// and the names must match *exactly* (without DNS resolution).  Unless
// a restricted binding is required, we recommend using a URL consisting
// of an empty host name, such as http://  or https://  -- this would
// convert to binding to the default port on all interfaces on the host.
extern int nni_http_server_init(nni_http_server **, nni_url *);

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
// responsible for finalizing it afterwards.
extern void nni_http_server_del_handler(nni_http_server *, nni_http_handler *);

// nni_http_server_set_tls adds a TLS configuration to the server,
// and enables the use of it.  This returns NNG_EBUSY if the server is
// already started.   This wipes out the entire TLS configuration on the
// server client, so the caller must have configured it reasonably.
// This API is not recommended unless the caller needs complete control
// over the TLS configuration.
extern int nni_http_server_set_tls(nni_http_server *, nng_tls_config *);

// nni_http_server_get_tls obtains the TLS configuration if one is present,
// or returns NNG_EINVAL.  The TLS configuration is invalidated if the
// nni_http_server_set_tls function is called, so be careful.
extern int nni_http_server_get_tls(nni_http_server *, nng_tls_config **);

// nni_http_server_start starts listening on the supplied port.
extern int nni_http_server_start(nni_http_server *);

// nni_http_server_stop stops the server, closing the listening socket.
// Connections that have been "upgraded" are unaffected.  Connections
// associated with a callback will complete their callback, and then close.
extern void nni_http_server_stop(nni_http_server *);

// nni_http_ctx is the context associated with a particular request
// arriving at the server, and is tied to an underlying nni_http channel.
typedef struct nni_http_ctx nni_http_ctx;

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
extern int nni_http_hijack(nni_http_ctx *);

// nni_http_ctx_stream obtains the underlying nni_http channel for the
// context.  This is used by hijackers, as well as anything that needs
// to handle sending its own replies on the channel.
extern int nni_http_ctx_stream(nni_http_ctx *, nni_http **);

// nni_http_handler_init creates a server handler object, for the supplied
// URI (path only) with the callback.
//
// Note that methods which modify a handler cannot be called while the handler
// is registered with the server, and that a handler can only be registered
// once per server.
//
// The callback function will receive the following arguments (via
// nni_aio_get_input(): nni_http_request *, nni_http_handler *, and
// nni_http_context_t *.  The first is a request object, for convenience.
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
// provides for settign the Content-Type explicitly (last argument).
extern int nni_http_handler_init_file_ctype(
    nni_http_handler **, const char *, const char *, const char *);

// nni_http_handler_init_directory arranges to serve up an entire
// directory tree.  The content types are determined from the builtin
// content type list.  Actual directories are required to contain a
// file called index.html or index.htm.  We do not generate directory
// listings for security reasons.
extern int nni_http_handler_init_directory(
    nni_http_handler **, const char *, const char *);

// nni_http_handler_init_static creates a handler that serves up static content
// supplied, with the Content-Type supplied in the final argument.
extern int nni_http_handler_init_static(
    nni_http_handler **, const char *, const void *, size_t, const char *);

// nni_http_handler_fini destroys a handler.  This should only be done before
// the handler is added, or after it is deleted.  The server automatically
// calls this for any handlers still registered with it if it is destroyed.
extern void nni_http_handler_fini(nni_http_handler *);

// nni_http_handler_set_dtor sets a callback that is executed when
// the handler is torn down.  The argument to the destructor is the
// handler itself.  This function is called by the nni_http_handler_fini
// function.
extern int nni_http_handler_set_dtor(
    nni_http_handler *, void (*)(nni_http_handler *));

// nni_http_handler_set_tree marks the handler as servicing the entire
// tree (e.g. a directory), rather than just a leaf node.  The handler
// will probably need to inspect the URL of the request.
extern int nni_http_handler_set_tree(nni_http_handler *, bool);

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
// Note that indices used should be small, to minimize array allocations.
// This can fail with NNG_ENOMEM if storage cannot be allocated.
extern int nni_http_handler_set_data(nni_http_handler *, void *, unsigned);

// nni_http_handler_get_data returns the data that was previously stored
// at that index.  It returns NULL if no data was set, or an invalid index
// is supplied.
extern void *nni_http_handler_get_data(nni_http_handler *, unsigned);

// Client stuff.

typedef struct nni_http_client nni_http_client;

extern int  nni_http_client_init(nni_http_client **, nni_url *);
extern void nni_http_client_fini(nni_http_client *);

// nni_http_client_set_tls sets the TLS configuration.  This wipes out
// the entire TLS configuration on the client, so the caller must have
// configured it reasonably.  This API is not recommended unless the
// caller needs complete control over the TLS configuration.
extern int nni_http_client_set_tls(nni_http_client *, nng_tls_config *);

// nni_http_client_get_tls obtains the TLS configuration if one is present,
// or returns NNG_EINVAL.  The supplied TLS configuration object may
// be invalidated by any future calls to nni_http_client_set_tls.
extern int nni_http_client_get_tls(nni_http_client *, nng_tls_config **);

extern void nni_http_client_connect(nni_http_client *, nni_aio *);

#endif // NNG_SUPPLEMENTAL_HTTP_HTTP_H
