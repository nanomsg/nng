//
// Copyright 2017 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2017 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#ifndef NNG_SUPPLEMENTAL_HTTP_HTTP_H
#define NNG_SUPPLEMENTAL_HTTP_HTTP_H

#include <stdbool.h>

// nni_http_msg represents an HTTP request or response message.
typedef struct nni_http_msg    nni_http_msg;
typedef struct nni_http_res    nni_http_res;
typedef struct nni_http_entity nni_http_entity;

typedef struct nni_http_tran {
	void *h_data;
	void (*h_read)(void *, nni_aio *);
	void (*h_write)(void *, nni_aio *);
	void (*h_close)(void *);
	void (*h_fini)(void *);
} nni_http_tran;

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
extern int nni_http_req_parse(nni_http_req *, void *, size_t, size_t *);

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
extern int  nni_http_res_parse(nni_http_res *, void *, size_t, size_t *);
extern int  nni_http_res_set_data(nni_http_res *, const void *, size_t);
extern int  nni_http_res_copy_data(nni_http_res *, const void *, size_t);
extern int  nni_http_res_alloc_data(nni_http_res *, size_t);
extern void nni_http_res_get_data(nni_http_res *, void **, size_t *);
extern int  nni_http_res_init_error(nni_http_res **, uint16_t);

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

extern int  nni_http_init(nni_http **, nni_http_tran *);
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

typedef struct nni_http_server nni_http_server;

typedef struct {
	// h_path is the relative URI that we are going to match against.
	// Must not be NULL.  Note that query parameters (things following
	// a "?" at the end of the path) are ignored when matching.  This
	// field may not be NULL.
	const char *h_path;

	// h_method is the HTTP method to handle such as "GET" or "POST".
	// Must not be empty or NULL.  If the incoming method is HEAD, then
	// the server will process HEAD the same as GET, but will not send
	// any response body.
	const char *h_method;

	// h_host is used to match on a specific Host: entry.  If left NULL,
	// then this handler will match regardless of the Host: value.
	const char *h_host;

	// h_is_dir indicates that the path represents a directory, and
	// any path which is a logically below it should also be matched.
	// This means that "/phone" will match for "/phone/bob" but not
	// "/phoneme/ma".  Be advised that it is not possible to register
	// a handler for a parent and a different handler for children.
	// (This restriction may be lifted in the future.)
	bool h_is_dir;

	// h_is_upgrader is used for callbacks that "upgrade" (or steal)
	// their connection. When this is true, the server framework
	// assumes that the handler takes over *all* of the details of
	// the connection.  Consequently, the connection is disassociated
	// from the framework, and no response is sent.  (Upgraders are
	// responsible for adopting the connection, including closing it
	// when they are done, and for sending any HTTP response message.
	// This is true even if an error occurs.)
	bool h_is_upgrader;

	// h_cb is a callback that handles the request.  The conventions
	// are as follows:
	//
	// inputs:
	//   0 - nni_http * for the actual underlying HTTP channel
	//   1 - nni_http_req * for the HTTP request object
	//   2 - void * for the opaque pointer supplied at registration
	//
	// outputs:
	//   0 - (optional) nni_http_res * for an HTTP response (see below)
	//
	// The callback may choose to return the a response object in output 0,
	// in which case the framework will handle sending the reply.
	// (Response entity content is also sent if the response data
	// is not NULL.)  The callback may instead do it's own replies, in
	// which case the response output should be NULL.
	//
	// Note that any request entity data is *NOT* supplied automatically
	// with the request object; the callback is expected to call the
	// nni_http_read_data method to retrieve any message data based upon
	// the presence of headers. (It may also call nni_http_read or
	// nni_http_write on the channel as it sees fit.)
	//
	// Upgraders should call the completion routine immediately,
	// once they have collected the request object and HTTP channel.
	void (*h_cb)(nni_aio *);
} nni_http_handler;

// nni_http_server will look for an existing server with the same
// socket address, or create one if one does not exist.  The servers
// are reference counted to permit sharing the server object across
// multiple subsystems.  The sockaddr matching is very limited though,
// and the addresses must match *exactly*.
extern int nni_http_server_init(nni_http_server **, nng_sockaddr *);

// nni_http_server_fini drops the reference count on the server, and
// if this was the last reference, closes down the server and frees
// all related resources.  It will not affect hijacked connections.
extern void nni_http_server_fini(nni_http_server *);

// nni_http_server_add_handler registers a new handler on the server.
// This function will return NNG_EADDRINUSE if a conflicting handler
// is already registered (i.e. a handler with the same value for Host,
// Method, and URL.)  The first parameter receives an opaque handle to
// the handler, that can be used to unregister the handler later.
extern int nni_http_server_add_handler(
    void **, nni_http_server *, nni_http_handler *, void *);

extern void nni_http_server_del_handler(nni_http_server *, void *);

// nni_http_server_start starts listening on the supplied port.
extern int nni_http_server_start(nni_http_server *);

// nni_http_server_stop stops the server, closing the listening socket.
// Connections that have been "upgraded" are unaffected.  Connections
// associated with a callback will complete their callback, and then close.
extern void nni_http_server_stop(nni_http_server *);

// nni_http_server_add_static is a short cut to add static
// content handler to the server.  The host may be NULL, and the
// ctype (aka Content-Type) may be NULL.  If the Content-Type is NULL,
// then application/octet stream will be the (probably bad) default.
// The actual data is copied, and so the caller may discard it once
// this function returns.
extern int nni_http_server_add_static(nni_http_server *, const char *host,
    const char *ctype, const char *uri, const void *, size_t);

// nni_http_server_add file is a short cut to add a file-backed static
// content handler to the server.  The host may be NULL, and the
// ctype (aka Content-Type) may be NULL.  If the Content-Type is NULL,
// then the server will try to guess it based on the filename -- but only
// a small number of file types are builtin.  URI is the absolute URI
// (sans hostname and scheme), and the path is the path on the local
// filesystem where the file can be found.
extern int nni_http_server_add_file(nni_http_server *, const char *host,
    const char *ctype, const char *uri, const char *path);

// TLS will use
// extern int nni_http_server_start_tls(nni_http_server *, nng_sockaddr *,
//     nni_tls_config *);

// Client stuff.

typedef struct nni_http_client nni_http_client;

extern int  nni_http_client_init(nni_http_client **, nng_sockaddr *);
extern void nni_http_client_fini(nni_http_client *);
extern void nni_http_client_connect(nni_http_client *, nni_aio *);

#endif // NNG_SUPPLEMENTAL_HTTP_HTTP_H
