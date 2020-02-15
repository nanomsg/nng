//
// Copyright 2020 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
// Copyright 2020 Dirac Research <robert.bielik@dirac.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#ifndef NNG_SUPPLEMENTAL_HTTP_HTTP_H
#define NNG_SUPPLEMENTAL_HTTP_HTTP_H

// HTTP API.  Only present if HTTP support compiled into the library.
// Functions will return NNG_ENOTSUP (or NULL or 0 as appropriate)
// if the library lacks support for HTTP.

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

struct nng_tls_config;

// HTTP status codes.  This list is not exhaustive.
enum nng_http_status {
	NNG_HTTP_STATUS_CONTINUE                 = 100,
	NNG_HTTP_STATUS_SWITCHING                = 101,
	NNG_HTTP_STATUS_PROCESSING               = 102,
	NNG_HTTP_STATUS_OK                       = 200,
	NNG_HTTP_STATUS_CREATED                  = 201,
	NNG_HTTP_STATUS_ACCEPTED                 = 202,
	NNG_HTTP_STATUS_NOT_AUTHORITATIVE        = 203,
	NNG_HTTP_STATUS_NO_CONTENT               = 204,
	NNG_HTTP_STATUS_RESET_CONTENT            = 205,
	NNG_HTTP_STATUS_PARTIAL_CONTENT          = 206,
	NNG_HTTP_STATUS_MULTI_STATUS             = 207,
	NNG_HTTP_STATUS_ALREADY_REPORTED         = 208,
	NNG_HTTP_STATUS_IM_USED                  = 226,
	NNG_HTTP_STATUS_MULTIPLE_CHOICES         = 300,
	NNG_HTTP_STATUS_STATUS_MOVED_PERMANENTLY = 301,
	NNG_HTTP_STATUS_FOUND                    = 302,
	NNG_HTTP_STATUS_SEE_OTHER                = 303,
	NNG_HTTP_STATUS_NOT_MODIFIED             = 304,
	NNG_HTTP_STATUS_USE_PROXY                = 305,
	NNG_HTTP_STATUS_TEMPORARY_REDIRECT       = 307,
	NNG_HTTP_STATUS_PERMANENT_REDIRECT       = 308,
	NNG_HTTP_STATUS_BAD_REQUEST              = 400,
	NNG_HTTP_STATUS_UNAUTHORIZED             = 401,
	NNG_HTTP_STATUS_PAYMENT_REQUIRED         = 402,
	NNG_HTTP_STATUS_FORBIDDEN                = 403,
	NNG_HTTP_STATUS_NOT_FOUND                = 404,
	NNG_HTTP_STATUS_METHOD_NOT_ALLOWED       = 405,
	NNG_HTTP_STATUS_NOT_ACCEPTABLE           = 406,
	NNG_HTTP_STATUS_PROXY_AUTH_REQUIRED      = 407,
	NNG_HTTP_STATUS_REQUEST_TIMEOUT          = 408,
	NNG_HTTP_STATUS_CONFLICT                 = 409,
	NNG_HTTP_STATUS_GONE                     = 410,
	NNG_HTTP_STATUS_LENGTH_REQUIRED          = 411,
	NNG_HTTP_STATUS_PRECONDITION_FAILED      = 412,
	NNG_HTTP_STATUS_PAYLOAD_TOO_LARGE        = 413,
	NNG_HTTP_STATUS_ENTITY_TOO_LONG          = 414,
	NNG_HTTP_STATUS_UNSUPPORTED_MEDIA_TYPE   = 415,
	NNG_HTTP_STATUS_RANGE_NOT_SATISFIABLE    = 416,
	NNG_HTTP_STATUS_EXPECTATION_FAILED       = 417,
	NNG_HTTP_STATUS_TEAPOT                   = 418,
	NNG_HTTP_STATUS_UNPROCESSABLE_ENTITY     = 422,
	NNG_HTTP_STATUS_LOCKED                   = 423,
	NNG_HTTP_STATUS_FAILED_DEPENDENCY        = 424,
	NNG_HTTP_STATUS_UPGRADE_REQUIRED         = 426,
	NNG_HTTP_STATUS_PRECONDITION_REQUIRED    = 428,
	NNG_HTTP_STATUS_TOO_MANY_REQUESTS        = 429,
	NNG_HTTP_STATUS_HEADERS_TOO_LARGE        = 431,
	NNG_HTTP_STATUS_UNAVAIL_LEGAL_REASONS    = 451,
	NNG_HTTP_STATUS_INTERNAL_SERVER_ERROR    = 500,
	NNG_HTTP_STATUS_NOT_IMPLEMENTED          = 501,
	NNG_HTTP_STATUS_BAD_GATEWAY              = 502,
	NNG_HTTP_STATUS_SERVICE_UNAVAILABLE      = 503,
	NNG_HTTP_STATUS_GATEWAY_TIMEOUT          = 504,
	NNG_HTTP_STATUS_HTTP_VERSION_NOT_SUPP    = 505,
	NNG_HTTP_STATUS_VARIANT_ALSO_NEGOTIATES  = 506,
	NNG_HTTP_STATUS_INSUFFICIENT_STORAGE     = 507,
	NNG_HTTP_STATUS_LOOP_DETECTED            = 508,
	NNG_HTTP_STATUS_NOT_EXTENDED             = 510,
	NNG_HTTP_STATUS_NETWORK_AUTH_REQUIRED    = 511,
};

// nng_http_req represents an HTTP request.
typedef struct nng_http_req nng_http_req;

// nng_http_req_alloc creates a vanilla HTTP request object.  The object is
// initialized with the given URL object for an HTTP/1.1 GET request by
// default. It also adds the Host: header required for HTTP/1.1.  If the
// url is NULL, then the uri and Host: header are uninitialized, and will
// need to be set explicitly.
NNG_DECL int nng_http_req_alloc(nng_http_req **, const nng_url *);

// nng_http_req_free frees an HTTP request object.
NNG_DECL void nng_http_req_free(nng_http_req *);

// nng_http_req_get_method returns the method.
NNG_DECL const char *nng_http_req_get_method(nng_http_req *);

// nng_http_req_get_version returns the version, usually HTTP/1.1.
NNG_DECL const char *nng_http_req_get_version(nng_http_req *);

// nng_http_req_get_uri returns the "abs-uri", which is URL without
// the scheme, host, or port.
NNG_DECL const char *nng_http_req_get_uri(nng_http_req *);

// nng_http_req_set_header sets an HTTP header, replacing any previous value
// that might have been present.
NNG_DECL int nng_http_req_set_header(
    nng_http_req *, const char *, const char *);

// nng_http_req_add_header adds an HTTP header, without disrupting any other
// with the same name that might have been present.
NNG_DECL int nng_http_req_add_header(
    nng_http_req *, const char *, const char *);

// nng_http_req_del_header deletes all occurrences of a named header.
NNG_DECL int nng_http_req_del_header(nng_http_req *, const char *);

// nng_http_req_get_header looks up a header with the named, returns NULL
// if not found.
NNG_DECL const char *nng_http_req_get_header(nng_http_req *, const char *);

// nng_http_req_set_method is used to change the method of a request.
// The method should be an upper case HTTP method, like POST, or DELETE.
// Null sets the default ("GET").
NNG_DECL int nng_http_req_set_method(nng_http_req *, const char *);

// nng_http_req_set_version is used to change the version of a request.
// Normally the version is "HTTP/1.1".  Note that the framework does
// not support HTTP/2 at all.  Null sets the default ("HTTP/1.1").
NNG_DECL int nng_http_req_set_version(nng_http_req *, const char *);

// nng_http_req_set_uri is used to change the URI of a request.  This
// should be an "abs-uri", that is a path, plus query and fragment if
// needed.  The scheme, host, and port don't belong here.  The URI should
// start with a leading '/' per HTTP.
NNG_DECL int nng_http_req_set_uri(nng_http_req *, const char *);

// nng_http_req_set_data adds entity data to the request.  The
// data object must persist (so only really useful for static data).
// The content-length header is updated as well, but the caller should
// probably set the content-type header.
NNG_DECL int nng_http_req_set_data(nng_http_req *, const void *, size_t);

// nng_http_req_copy_data adds entity data to the response. A private
// copy of the data is made (will be freed with the request).
// The content-length header is updated as well, but the caller should
// probably set the content-type header.
NNG_DECL int nng_http_req_copy_data(nng_http_req *, const void *, size_t);

// nng_http_req_get_data gets the data for the response.
NNG_DECL void nng_http_req_get_data(nng_http_req *, void **, size_t *);

// nng_http_res represents an HTTP response.
typedef struct nng_http_res nng_http_res;

// nng_http_res_alloc creates a vanilla HTTP response object.  The object is
// initialized for an HTTP/1.1 200 OK response by default.
NNG_DECL int nng_http_res_alloc(nng_http_res **);

// nng_http_res_alloc_error creates an error HTTP response object.  The object
// is initialized for an HTTP/1.1 response, and contains an associated
// generic HTML error page.
NNG_DECL int nng_http_res_alloc_error(nng_http_res **, uint16_t);

// nng_http_res_free frees an HTTP response object.
NNG_DECL void nng_http_res_free(nng_http_res *);

// nng_http_res_get_status returns the HTTP status code from the server.
NNG_DECL uint16_t nng_http_res_get_status(nng_http_res *);

// nng_http_res_set_status sets the HTTP status code.
NNG_DECL int nng_http_res_set_status(nng_http_res *, uint16_t);

// nng_http_res_get_reason returns the human readable status message
// that the server responds (or responded) with.
NNG_DECL const char *nng_http_res_get_reason(nng_http_res *);

// nng_http_res_set_reason sets the human readable status message.
// NULL means that a default reason is used based on the status code.
NNG_DECL int nng_http_res_set_reason(nng_http_res *, const char *);

// nng_http_res_set_header sets an HTTP header, replacing any previous value
// that might have been present.
NNG_DECL int nng_http_res_set_header(
    nng_http_res *, const char *, const char *);

// nng_http_res_add_header adds an HTTP header, without disrupting any other
// with the same name that might have been present.
NNG_DECL int nng_http_res_add_header(
    nng_http_res *, const char *, const char *);

// nng_http_res_del_header deletes all occurrences of a named header.
NNG_DECL int nng_http_res_del_header(nng_http_res *, const char *);

// nng_http_res_get_header looks up a header with the named, returns NULL
// if not found.
NNG_DECL const char *nng_http_res_get_header(nng_http_res *, const char *);

// nng_http_res_set_version is used to change the version of a response.
// Normally the version is "HTTP/1.1".  Note that the framework does
// not support HTTP/2 at all.  NULL sets the default ("HTTP/1.1").
NNG_DECL int nng_http_res_set_version(nng_http_res *, const char *);

// nng_http_res_get_version returns the version, usually HTTP/1.1.
NNG_DECL const char *nng_http_res_get_version(nng_http_res *);

// nng_http_res_get_data gets the data for the response.
NNG_DECL void nng_http_res_get_data(nng_http_res *, void **, size_t *);

// nng_http_res_set_data adds entity data to the response.  The
// data object must persist (so only really useful for static data).
// The content-length header is updated as well, but the caller should
// probably set the content-type header.
NNG_DECL int nng_http_res_set_data(nng_http_res *, const void *, size_t);

// nng_http_res_copy_data adds entity data to the response. A private
// copy of the data is made (will be freed with the request).
// The content-length header is updated as well, but the caller should
// probably set the content-type header.
NNG_DECL int nng_http_res_copy_data(nng_http_res *, const void *, size_t);

// An nng_http_conn represents an underlying "connection".  It may be
// a TCP channel, or a TLS channel, but the main thing is that this is
// normally only used for exchanging HTTP requests and responses.
typedef struct nng_http_conn nng_http_conn;

// nng_http_conn_close closes the underlying channel.  Applications should
// not use this channel after this operation is performed.
NNG_DECL void nng_http_conn_close(nng_http_conn *);

// nng_http_conn_read attempts to read data from the connection.  This
// completes as soon as at least one byte is read; it does not wait
// for the entire aio to be filled.
NNG_DECL void nng_http_conn_read(nng_http_conn *, nng_aio *);

// nng_http_conn_read_all is like nng_http_conn_read, but it does not
// finish until either all the requested data is read, or an error occurs.
NNG_DECL void nng_http_conn_read_all(nng_http_conn *, nng_aio *);

// nng_http_conn_write attempts to write data, but it can write less
// than the amount requested. (It completes as soon as at least one
// byte is written.)
NNG_DECL void nng_http_conn_write(nng_http_conn *, nng_aio *);

// nng_http_conn_write_all is like nng_http_conn_write, but it does not
// finish until either all the requested data is written, or an error occurs.
NNG_DECL void nng_http_conn_write_all(nng_http_conn *, nng_aio *);

// nng_http_conn_write_req writes the entire request.  It will also write any
// data that has been attached.
NNG_DECL void nng_http_conn_write_req(
    nng_http_conn *, nng_http_req *, nng_aio *);

// nng_http_conn_write_res writes the entire response.  It will also write any
// data that has been attached.
NNG_DECL void nng_http_conn_write_res(
    nng_http_conn *, nng_http_res *, nng_aio *);

// nng_http_conn_read_req reads an entire request, EXCEPT for any entity
// data.  The caller is responsible for processing the headers in the request
// and reading any submitted entity data itself.
NNG_DECL void nng_http_conn_read_req(
    nng_http_conn *, nng_http_req *, nng_aio *);

// nng_http_conn_read_res reads an entire response, EXCEPT for any entity
// data.  The caller is responsible for processing the headers in the response
// and reading any submitted entity data itself.
NNG_DECL void nng_http_conn_read_res(
    nng_http_conn *, nng_http_res *, nng_aio *);

// nng_http_req_reset resets the request to an initially allocated state.
NNG_DECL void nng_http_req_reset(nng_http_req *);

// nng_http_res_reset resets the response to an initially allocated state.
NNG_DECL void nng_http_res_reset(nng_http_res *);

// nng_http_handler is a handler used on the server side to handle HTTP
// requests coming into a specific URL.
typedef struct nng_http_handler nng_http_handler;

// nng_http_handler_alloc creates a server handler object, for the supplied
// absolute URI (path only) with the callback.  By default the handler
// is assumed to handle only GET requests (and implictly HEAD requests
// as well.)
//
// Note that methods which modify a handler cannot be called while the handler
// is registered with the server, and that a handler can only be registered
// once per server.
//
// The callback function will receive the following arguments (via
// nng_aio_get_input(): nng_http_request *, nng_http_handler *, and
// nng_http_conn *.  The first is a request object, for convenience.
// The second is the handler, from which the callback can obtain any other
// data it has set.  The final is the http connection, which can be used
// to hijack the session.
//
// Upon completion, the handler should store an nng_http_res * as the
// first output using nng_aio_set_output.  If it does not do so, or supplies
// NULL, then it must send a response itself.
//
// The callback should complete with a result of 0 in most circumstances.
// If it completes with an error, then the connection is terminated, after
// possibly sending a 500 error response to the client.
NNG_DECL int nng_http_handler_alloc(
    nng_http_handler **, const char *, void (*)(nng_aio *));

// nng_http_handler_free frees the handler. This actually just drops a
// reference count on the handler, as it may be in use by an existing
// server.  The server will also call this when it is destroyed.
NNG_DECL void nng_http_handler_free(nng_http_handler *);

// nng_http_handler_alloc_file creates a "file" based handler, that
// serves up static content from the given file path.  The content-type
// supplied is determined from the file name using a simple built-in map.
NNG_DECL int nng_http_handler_alloc_file(
    nng_http_handler **, const char *, const char *);

// nng_http_handler_alloc_static creates a static-content handler.
// The last argument is the content-type, which may be NULL (in which case
// "application/octet-stream" is assumed.)
NNG_DECL int nng_http_handler_alloc_static(
    nng_http_handler **, const char *, const void *, size_t, const char *);

// nng_http_handler_alloc_redirect creates an HTTP redirect handler.
// The status is given, along with the new URL.  If the status is 0,
// then 301 will be used instead.
NNG_DECL int nng_http_handler_alloc_redirect(
    nng_http_handler **, const char *, uint16_t, const char *);

// nng_http_handler_alloc_file creates a "directory" based handler, that
// serves up static content from the given directory tree.  Directories
// that contain an index.html or index.htm file use that file for the
// directory content, otherwise a suitable error page is returned (the server
// does not generate index pages automatically.)  The content-type for
// files is determined from the file name using a simple built-in map.
NNG_DECL int nng_http_handler_alloc_directory(
    nng_http_handler **, const char *, const char *);

// nng_http_handler_set_method sets the method that the handler will be
// called for.  By default this is GET.  If NULL is supplied for the
// method, then the handler is executed regardless of method, and must
// inspect the method itself.
NNG_DECL int nng_http_handler_set_method(nng_http_handler *, const char *);

// nng_http_handler_set_host sets the Host: that the handler will be
// called for (to allow for virtual hosts).  If the value is NULL (the
// default, then the Host: header is not considered when matching the
// handler.)  Note that the Host: header must match *exactly* (except
// that case is not considered.)
NNG_DECL int nng_http_handler_set_host(nng_http_handler *, const char *);

// nng_http_handler_collect_body is used to indicate the server should
// check for, and process, data sent by the client, which will be attached
// to the request.  If this is false, then the handler will need to check
// for and process any content data.  By default the server will accept
// up to 1MB.  If the client attempts to send more data than requested,
// then a 400 Bad Request will be sent back to the client.  To set an
// unlimited value, use (size_t)-1.  To preclude the client from sending
// *any* data, use 0.  (The static and file handlers use 0 by default.)
NNG_DECL int nng_http_handler_collect_body(nng_http_handler *, bool, size_t);

// nng_http_handler_set_tree indicates that the handler is being registered
// for a hierarchical tree, rather than just a single path, so it will be
// called for all child paths supplied.  By default the handler is only
// called for an exact path match.
NNG_DECL int nng_http_handler_set_tree(nng_http_handler *);

// nng_http_handler_set_tree_exclusive indicates that the handler is being
// registered for a heirarchical tree *exclusively*, rather than just a single
// path, so it will be called for all child paths supplied. By default the
// handler is only called for an exact path match. Exclusive means that any
// other handler on a conflicting path will induce an address conflict error
// when added to a server.
NNG_DECL int nng_http_handler_set_tree_exclusive(nng_http_handler *);

// nng_http_handler_set_data is used to store additional data, along with
// a possible clean up routine.  (The clean up is a custom de-allocator and
// will be called with the supplied data as an argument, when the handler
// is being de-allocated.)
NNG_DECL int nng_http_handler_set_data(
    nng_http_handler *, void *, void (*)(void *));

// nng_http_handler_get_data returns the data that was previously stored.
NNG_DECL void *nng_http_handler_get_data(nng_http_handler *);

// nng_http_server is a handle to an HTTP server instance.  Servers
// only serve a single port / address at this time.

typedef struct nng_http_server nng_http_server;

// nng_http_server_hold gets a server structure, using the address determined
// from the URL.  If a server already exists, then a hold is placed on it, and
// that instance is returned.  If no such server exists, then a new instance
// is created.
NNG_DECL int nng_http_server_hold(nng_http_server **, const nng_url *);

// nng_http_server_release releases the hold on the server.  If this is the
// last instance of the server, then it is shutdown and resources are freed.
NNG_DECL void nng_http_server_release(nng_http_server *);

// nng_http_server_start starts the server handling HTTP.  Once this is
// called, it will not be possible to change certain parameters (such as
// any TLS configuration).
NNG_DECL int nng_http_server_start(nng_http_server *);

// nng_http_server_stop stops the server.  No new client connections are
// accepted after this returns.  Once a server is stopped fully, the
// instance will no longer be returned by nng_http_server_hold, as the
// server may not be reused.
NNG_DECL void nng_http_server_stop(nng_http_server *);

// nng_http_server_add_handler registers a handler on the server.
// This function will return NNG_EADDRINUSE if a conflicting handler
// is already registered (i.e. a handler with the same value for Host,
// Method, and URL.)
NNG_DECL int nng_http_server_add_handler(
    nng_http_server *, nng_http_handler *);

// nni_http_del_handler removes the given handler.  The caller is
// responsible for finalizing it afterwards.  If the handler was not found
// (not registered), NNG_ENOENT is returned.  In this case it is unsafe
// to make assumptions about the validity of the handler.
NNG_DECL int nng_http_server_del_handler(
    nng_http_server *, nng_http_handler *);

// nng_http_server_set_tls adds a TLS configuration to the server,
// and enables the use of it.  This returns NNG_EBUSY if the server is
// already started.   This wipes out the entire TLS configuration on the
// server client, so the caller must have configured it reasonably.
// This API is not recommended unless the caller needs complete control
// over the TLS configuration.
NNG_DECL int nng_http_server_set_tls(
    nng_http_server *, struct nng_tls_config *);

// nng_http_server_get_tls obtains the TLS configuration if one is present,
// or returns NNG_EINVAL.  The TLS configuration is invalidated if the
// nng_http_server_set_tls function is called, so be careful.
NNG_DECL int nng_http_server_get_tls(
    nng_http_server *, struct nng_tls_config **);

// nng_http_server_get_addr obtains the address with which the server was
// initialized or returns NNG_EINVAL. Useful for instance when the port has
// been automatically assigned.
NNG_DECL int nng_http_server_get_addr(nng_http_server *, nng_sockaddr *);

// nng_http_server_set_error_page sets a custom error page (HTML) content
// to be sent for the given error code.  This is used when the error is
// generated internally by the framework, or when the application returns
// the response back to the server via the handler's aio, and the response
// was allocated with nng_http_res_alloc_error.  If the response was not
// allocated this way, or the application writes the response itself instead
// of letting the server do so, then this setting will be ignored.
NNG_DECL int nng_http_server_set_error_page(
    nng_http_server *, uint16_t, const char *);

// nng_http_server_set_error_file works like nng_http_server_error_page,
// except that the content is loaded from the named file path.  The contents
// are loaded at the time this function is called, so this function should be
// called anytime the contents of the named file have changed.
NNG_DECL int nng_http_server_set_error_file(
    nng_http_server *, uint16_t, const char *);

// nng_http_server_res_error takes replaces the body of the response with
// a custom error page previously set for the server, using the status
// of the response.  The response must have the status set first using
// nng_http_res_set_status or implicitly via nng_http_res_alloc_error.
NNG_DECL int nng_http_server_res_error(nng_http_server *, nng_http_res *);

// nng_http_hijack is intended to be called by a handler that wishes to
// take over the processing of the HTTP session -- usually to change protocols
// (such as in the case of websocket).  The caller is responsible for the
// final disposal of the associated nng_http_conn.  Also, this completely
// disassociates the http session from the server, so the server may be
// stopped or destroyed without affecting the hijacked session.  Note also
// that the hijacker will need to issue any HTTP reply itself.  Finally,
// when a session is hijacked, the caller is also responsible for disposing
// of the request structure.  (Some hijackers may keep the request for
// further processing.)

NNG_DECL int nng_http_hijack(nng_http_conn *);

// nng_http_client represents a "client" object.  Clients can be used
// to create HTTP connections.  At present, connections are not cached
// or reused, but that could change in the future.
typedef struct nng_http_client nng_http_client;

// nng_http_client_alloc allocates a client object, associated with
// the given URL.
NNG_DECL int nng_http_client_alloc(nng_http_client **, const nng_url *);

// nng_http_client_free frees the client.  Connections created by the
// the client are not necessarily closed.
NNG_DECL void nng_http_client_free(nng_http_client *);

// nng_http_client_set_tls sets the TLS configuration.  This wipes out
// the entire TLS configuration on the client, so the caller must have
// configured it reasonably.  This API is not recommended unless the
// caller needs complete control over the TLS configuration.
NNG_DECL int nng_http_client_set_tls(
    nng_http_client *, struct nng_tls_config *);

// nng_http_client_get_tls obtains the TLS configuration if one is present,
// or returns NNG_EINVAL.  The supplied TLS configuration object may
// be invalidated by any future calls to nni_http_client_set_tls.
NNG_DECL int nng_http_client_get_tls(
    nng_http_client *, struct nng_tls_config **);

// nng_http_client_connect establishes a new connection with the server
// named in the URL used when the client was created.  Once the connection
// is established, the associated nng_http_conn object pointer is returned
// in the first (index 0) output for the aio.
NNG_DECL void nng_http_client_connect(nng_http_client *, nng_aio *);

// nng_http_conn_transact is used to perform a round-trip exchange (i.e. a
// single HTTP transaction).  It will not automatically close the connection,
// unless some kind of significant error occurs.  The caller should close
// the connection if the aio does not complete successfully.
NNG_DECL void nng_http_conn_transact(
    nng_http_conn *, nng_http_req *, nng_http_res *, nng_aio *);

// nng_http_client_transact is used to execute a single transaction to a
// server. The connection is opened, and will be closed when the transaction is
// complete.
NNG_DECL void nng_http_client_transact(
    nng_http_client *, nng_http_req *, nng_http_res *, nng_aio *);

#ifdef __cplusplus
}
#endif

#endif // NNG_H
