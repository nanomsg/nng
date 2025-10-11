# HTTP Support

NNG offers support for creation of HTTP clients, and servers. NNG supports HTTP/1.1 at present, and supports
a subset of functionality, but the support should be sufficient for simple clients, REST API servers, static content servers,
and gateways between HTTP and and other protocols. It also provides support for WebSocket based connections.

HTTP follows a request/reply model, where a client issues a request, and the server is expected to reply.
Every request is answered with a single reply.

## Header File

```c
#include <nng/http.h>
```

Unlike the rest of NNG, the HTTP API in NNG requires including `nng/http.h`. It is not necessary to include
the main `nng/nng.h` header, it will be included transitively by `nng/http.h`.

## Connection Object

```c
typedef struct nng_http nng_http;
```

The {{i:`nng_http`}} object represents a single logical HTTP connection to the server.
For HTTP/1.1 and earlier, this will correspond to a single TCP connection, but the object
also contains state relating to the transaction, such as the hostname used, HTTP method used,
request headers, response status, response headers, and so forth.

An `nng_http` object can be reused, unless closed, so that additional transactions can be
performed after the first transaction is complete.

At any given point in time, an `nng_http` object can only refer to a single HTTP transaction.
In NNG, these `nng_http` objects are used in both the client and server APIs.

The `nng_http` object is created by either [`nng_http_client_connect`] or by an HTTP server
object which then passes it to an [`nng_http_handler`] callback function.

### HTTP Method

```c
void nng_http_set_method(nng_http *conn, const char *method);
const char *nng_http_get_method(nng_http *conn);
```

Each HTTP transaction has a single verb, or method, that is used. The most common methods are "GET", "HEAD", and "POST",
but a number of others are possible.

The {{i:`nng_http_set_method`}} function specifies the HTTP method to use for the transaction.
The default is "GET". HTTP methods are case sensitive, and generally upper-case, such as "GET", "POST", "HEAD",
and so forth. This function silently truncates any method to 32-characters. (There are no defined methods longer than this.)

The {{i:`nng_http_get_method`}} function is used, typically on a server, to retrieve the method the client
set when issuing the transaction.

### HTTP URI

```c
nng_err nng_http_set_uri(nng_http *conn, const char *uri, const char *query);
const char *nng_http_get_uri(nng_http *conn);
```

The {{i:`nng_http_set_uri`}} function sets the {{i:URI}}, which normally appears like a path such as "/docs/index.html",
for the next transaction on _conn_. It sets the URI to _uri_, and, if _query_ is not `NULL`, also appends the
contents of _query_, separated by either the '?' or '&' character, depending on whether _uri_ already
contains a query string. It may return [`NNG_ENOMEM`], or [`NNG_EMSGSIZE`] if the the result is too long,
or [`NNG_EINVAL`] if there is some other problem with the URI.

> [!NOTE]
> The _uri_ and _query_ must be already percent-encoded if necessary.

The {{i:`nni_http_get_uri`}} function is used to obtain the URI that was previously set by `nng_http_set_uri`.
If the URI is unset (such as for a freshly created connection), then it returns `NULL`. The returned value
will have any query concatenated, for example "/api/get_user.cgi?name=garrett".

### HTTP Version

```c
nng_err nng_http_set_version(nng_http *conn, const char *version);
const char *nng_http_get_version(nng_http *conn);
```

The {{i:`nng_http_set_version`}} function is used to select the HTTP protocol version to use for the
exchange. At present, only the values `NNG_HTTP_VERSION_1_0` and `NNG_HTTP_VERSION_1_1` (corresponding to
"HTTP/1.0" and "HTTP/1.1") are supported. NNG will default to using "HTTP/1.1" if this function is not called.
If an unsupported version is supplied, [`NNG_ENOTSUP`] will be returned, otherwise zero.

The {{i:`nng_http_get_version`}} function is used to determine the version the client selected. Normally
there is little need to use this, but there are some subtle semantic differences between HTTP/1.0 and HTTP/1.1.

> [!TIP]
> There are few, if any, remaining HTTP/1.0 implementations that are not also capable of HTTP/1.1.
> It might be easiest to just fail any request coming in that is not HTTP/1.1.

> [!NOTE]
> NNG does not support HTTP/2 or HTTP/3 at this time.

### HTTP Status

```c
typedef enum ... nng_http_status;
nng_http_status nng_http_get_status(nng_http *conn);
const char *nng_http_get_reason(nng_http_conn *conn);
void nng_http_set_status(nng_http *conn, nng_http_status status, const char *reason);
```

The {{i:`nng_http_get_status`}} function obtains the numeric code (typipcally numbered from 100 through 599) returned
by the server in the last exchange on _conn_. (If no exchange has been performed yet, the result is undefined.)
The value is returned as an {{i:`nng_http_status`}}.

A descriptive message matching the status code is returned by {{i:`nng_http_get_reason`}}.

The {{i:`nng_http_set_status`}} function is used on a server in a handler callback to set the status code that will be
reported to the client to _status_, and the associated text (reason) to _reason_. If _reason_ is `NULL`,
then a built in reason based on the _status_ will be used instead.

> [!TIP]
> Callbacks used on the server may wish to use [`nng_http_server_set_error`] or [`nng_http_server_set_redirect`] instead of
> `nng_http_set_status`, because those functions will also set the response body to a suitable HTML document
> for display to users.

Status codes are defined by the IETF. Here are definitions that NNG provides for convenience:

| Name                                                                                            | Code | Reason Text                     | Notes                                                 |
| ----------------------------------------------------------------------------------------------- | ---- | ------------------------------- | ----------------------------------------------------- |
| `NNG_HTTP_STATUS_CONTINUE`<a name="NNG_HTTP_STATUS_CONTINUE"></a>                               | 100  | Continue                        | Partial transfer, client may send body.               |
| `NNG_HTTP_STATUS_SWITCHING`<a name="NNG_HTTP_STATUS_SWITCHING"></a>                             | 101  | Switching Protocols             | Used when upgrading or hijacking a connection.        |
| `NNG_HTTP_STATUS_PROCESSING`<a name="NNG_HTTP_STATUS_PROCESSING"></a>                           | 102  | Processing                      |
| `NNG_HTTP_STATUS_OK`<a name="NNG_HTTP_STATUS_OK"></a>                                           | 200  | OK                              | Successful result.                                    |
| `NNG_HTTP_STATUS_CREATED`<a name="NNG_HTTP_STATUS_CREATED"></a>                                 | 201  | Created                         | Resource created successfully.                        |
| `NNG_HTTP_STATUS_ACCEPTED`<a name="NNG_HTTP_STATUS_ACCEPTED"></a>                               | 202  | Created                         | Request accepted for future processing.               |
| `NNG_HTTP_STATUS_NOT_AUTHORITATIVE`<a name="NNG_HTTP_STATUS_NOT_AUTHORITATIVE"></a>             | 203  | Not Authoritative               | Request successful, but modified by proxy.            |
| `NNG_HTTP_STATUS_NO_CONTENT`<a name="NNG_HTTP_STATUS_NO_CONTENT"></a>                           | 204  | No Content                      | Request successful, no content returned.              |
| `NNG_HTTP_STATUS_RESET_CONTENT`<a name="NNG_HTTP_STATUS_NO_CONTENT"></a>                        | 205  | Reset Content                   | Request successful, client should reload content.     |
| `NNG_HTTP_STATUS_PARTIAL_CONTENT`<a name="NNG_HTTP_STATUS_NO_CONTENT"></a>                      | 206  | Partial Content                 | Response to a range request.                          |
| `NNG_HTTP_STATUS_MULTI_STATUS`<a name="NNG_HTTP_STATUS_MULTI_STATUS"></a>                       | 207  | Multi-Status                    | Used with WebDAV.                                     |
| `NNG_HTTP_STATUS_ALREADY_REPORTED`<a name="NNG_HTTP_STATUS_ALREADY_REPORTED"></a>               | 208  | Already Reported                | Used with WebDAV.                                     |
| `NNG_HTTP_STATUS_IM_USED`<a name="NNG_HTTP_STATUS_IM_USED"></a>                                 | 226  | IM Used                         | Used with delta encodings, rarely supported.          |
| `NNG_HTTP_STATUS_MULTIPLE_CHOICES`<a name="NNG_HTTP_STATUS_MULTIPLE_CHOICES"></a>               | 300  | Multiple Choices                | Multiple responses possible, client should choose.    |
| `NNG_HTTP_STATUS_MOVED_PERMANENTLY`<a name="NNG_HTTP_STATUS_MOVED_PERMANENTLY"></a>             | 301  | Moved Permanently               | Permanent redirection, may be saved by client.        |
| `NNG_HTTP_STATUS_FOUND`<a name="NNG_HTTP_STATUS_FOUND"></a>                                     | 302  | Found                           | Temporary redirection, client may switch to GET.      |
| `NNG_HTTP_STATUS_SEE_OTHER`<a name="NNG_HTTP_STATUS_SEE_OTHER"></a>                             | 303  | See Other                       | Redirect, perhaps after a success POST or PUT.        |
| `NNG_HTTP_STATUS_NOT_MODIFIED`<a name="NNG_HTTP_STATUS_NOT_MODIFIED"></a>                       | 304  | Not Modified                    | Resource not modified, client may use cached version. |
| `NNG_HTTP_STATUS_USE_PROXY`<a name="NNG_HTTP_STATUS_USE_PROXY"></a>                             | 305  | Use Proxy                       |
| `NNG_HTTP_STATUS_TEMPORARY_REDIRECT`<a name="NNG_HTTP_STATUS_TEMPORARY_REDIRECT"></a>           | 307  | Temporary Redirect              | Temporary redirect, preserves method.                 |
| `NNG_HTTP_STATUS_PERMANENT_REDIRECT`<a name="NNG_HTTP_STATUS_PERMANENT_REDIRECT"></a>           | 308  | Permanent Redirect              | Permanent redirect.                                   |
| `NNG_HTTP_STATUS_BAD_REQUEST`<a name="NNG_HTTP_STATUS_BAD_REQUEST"></a>                         | 400  | Bad Request                     | Generic problem with the request.                     |
| `NNG_HTTP_STATUS_UNAUTHORIZED`<a name="NNG_HTTP_STATUS_UNAUTHORIZED"></a>                       | 401  | Unauthorized                    | Indicates a problem with authentication.              |
| `NNG_HTTP_STATUS_PAYMENT_REQUIRED`<a name="NNG_HTTP_STATUS_PAYMENT_REQUIRED"></a>               | 402  | Payment Required                |
| `NNG_HTTP_STATUS_FORBIDDEN`<a name="NNG_HTTP_STATUS_FORBIDDEN"></a>                             | 403  | Forbidden                       | No permission to access resource.                     |
| `NNG_HTTP_STATUS_NOT_FOUND`<a name="NNG_HTTP_STATUS_NOT_FOUND"></a>                             | 404  | Not Found                       | Resource does not exist.                              |
| `NNG_HTTP_STATUS_METHOD_NOT_ALLOWED`<a name="NNG_HTTP_STATUS_METHOD_NOT_ALLOWED"></a>           | 405  | Method Not Allowed              | Resource does not support the method.                 |
| `NNG_HTTP_STATUS_METHOD_NOT_ACCEPTABLE`<a name="NNG_HTTP_STATUS_METHOD_NOT_ACCEPTABLE"></a>     | 406  | Not Acceptable                  | Could not satisfy accept requirements.                |
| `NNG_HTTP_STATUS_PROXY_AUTH_REQUIRED`<a name="NNG_HTTP_STATUS_PROXY_AUTH_REQUIRED"></a>         | 407  | Proxy Authentication Required   | Proxy requires authentication.                        |
| `NNG_HTTP_STATUS_REQUEST_TIMEOUT`<a name="NNG_HTTP_STATUS_REQUEST_TIMEOUT"></a>                 | 408  | Request Timeout                 | Timed out waiting for request.                        |
| `NNG_HTTP_STATUS_CONFLICT`<a name="NNG_HTTP_STATUS_CONFLICT"></a>                               | 409  | Conflict                        | Conflicting request.                                  |
| `NNG_HTTP_STATUS_GONE`<a name="NNG_HTTP_STATUS_GONE"></a>                                       | 410  | Gone                            | Resource no longer exists.                            |
| `NNG_HTTP_STATUS_LENGTH_REQUIRED`<a name="NNG_HTTP_STATUS_LENGTH_REQUIRED"></a>                 | 411  | Length Required                 | Missing Content-Length.                               |
| `NNG_HTTP_STATUS_PRECONDITION_FAILED`<a name="NNG_HTTP_STATUS_PRECONDITION_FAILED"></a>         | 412  | Precondition Failed             |                                                       |
| `NNG_HTTP_STATUS_CONTENT_TOO_LARGE`<a name="NNG_HTTP_STATUS_PAYLOAD_TOO_LARGE"></a>             | 413  | Content Too Large               |                                                       |
| `NNG_HTTP_STATUS_URI_TOO_LONG`<a name="NNG_HTTP_STATUS_URI_TOO_LONG"></a>                       | 414  | URI Too Long                    |                                                       |
| `NNG_HTTP_STATUS_UNSUPPORTED_MEDIA_TYPE`<a name="NNG_HTTP_STATUS_UNSUPPORTED_MEDIA_TYPE"></a>   | 415  | Unsupported Media Type          |
| `NNG_HTTP_STATUS_RANGE_NOT_SATISFIABLE`<a name="NNG_HTTP_STATUS_RANGE_NOT_SATISFIABLE"></a>     | 416  | Range Not Satisfiable           |
| `NNG_HTTP_STATUS_EXPECTATION_FAILED`<a name="NNG_HTTP_STATUS_EXPECTATION_FAILED"></a>           | 417  | Expectation Failed              |
| `NNG_HTTP_STATUS_TEAPOT`<a name="NNG_HTTP_STATUS_TEAPOT"></a>                                   | 418  | I Am A Teapot                   | RFC 2324.                                             |
| `NNG_HTTP_STATUS_UNPROCESSABLE_ENTITY`<a name="NNG_HTTP_STATUS_UNPROCESSABLE_ENTITY"></a>       | 422  | Unprocessable Entity            |
| `NNG_HTTP_STATUS_LOCKED`<a name="NNG_HTTP_STATUS_LOCKED"></a>                                   | 423  | Locked                          |
| `NNG_HTTP_STATUS_FAILED_DEPENDENCY`<a name="NNG_HTTP_STATUS_FAILED_DEPENDENCY"></a>             | 424  | Failed Dependency               |
| `NNG_HTTP_STATUS_TOO_EARLY`<a name="NNG_HTTP_STATUS_TOO_EARLY"></a>                             | 425  | Too Early                       |
| `NNG_HTTP_STATUS_UPGRADE_REQUIRED`<a name="NNG_HTTP_STATUS_UPGRADE_REQUIRED"></a>               | 426  | Upgrade Required                |
| `NNG_HTTP_STATUS_PRECONDITION_REQUIRED`<a name="NNG_HTTP_STATUS_PRECONDITION_REQUIRED"></a>     | 428  | Precondition Required           |                                                       |
| `NNG_HTTP_STATUS_TOO_MANY_REQUESTS`<a name="NNG_HTTP_STATUS_TOO_MANY_REQUESTS"></a>             | 429  | Too Many Requests               |                                                       |
| `NNG_HTTP_STATUS_HEADERS_TOO_LARGE`<a name="NNG_HTTP_STATUS_HEADERS_TOO_LARGE"></a>             | 431  | Headers Too Large               |                                                       |
| `NNG_HTTP_STATUS_UNAVAIL_LEGAL_REASONS`<a name="NNG_HTTP_STATUS_UNAVAIL_LEGAL_REASONS"></a>     | 451  | Unavailable For Legal Reasons   |                                                       |
| `NNG_HTTP_STATUS_INTERNAL_SERVER_ERROR`<a name="NNG_HTTP_STATUS_INTERNAL_SERVER_ERROR"></a>     | 500  | Internal Server Error           |
| `NNG_HTTP_STATUS_NOT_IMPLEMENTED`<a name="NNG_HTTP_STATUS_NOT_IMPLEMENTED"></a>                 | 501  | Not Implemented                 | Server does not implement method.                     |
| `NNG_HTTP_STATUS_BAD_GATEWAY`<a name="NNG_HTTP_STATUS_BAD_GATEWAY"></a>                         | 502  | Bad Gateway                     |
| `NNG_HTTP_STATUS_SERVICE_UNAVAILALE`<a name="NNG_HTTP_STATUS_SERVICE_UNAVAILABLE"></a>          | 503  | Service Unavailable             |
| `NNG_HTTP_STATUS_GATEWAY_TIMEOUT`<a name="NNG_HTTP_STATUS_GATEWAY_TIMEOUT"></a>                 | 504  | Gateway TImeout                 |
| `NNG_HTTP_STATUS_HTTP_VERSION_NOT_SUPP`<a name="NNG_HTTP_STATUS_HTTP_VERSION_NOT_SUPP"></a>     | 505  | HTTP Version Not Supported      |
| `NNG_HTTP_STATUS_VARIANT_ALSO_NEGOTIATES`<a name="NNG_HTTP_STATUS_VARIANT_ALSO_NEGOTIATES"></a> | 506  | Variant Also Negotiates         |
| `NNG_HTTP_STATUS_INSUFFICIENT_STORAGE`<a name="NNG_HTTP_STATUS_INSUFFICIENT_STORAGE"></a>       | 507  | Variant Also Negotiates         |
| `NNG_HTTP_STATUS_LOOP_DETECTED`<a name="NNG_HTTP_STATUS_LOOP_DETECTED"></a>                     | 508  | Loop Detected                   |
| `NNG_HTTP_STATUS_NOT_EXTENDED`<a name="NNG_HTTP_STATUS_NOT_EXTENDED"></a>                       | 510  | Not Extended                    |
| `NNG_HTTP_STATUS_NETWORK_AUTH_REQUIRED`<a name="NNG_HTTP_STATUS_NETWORK_AUTH_REQUIRED"></a>     | 511  | Network Authentication Required |

### Retrieving Headers

```c
const char *nng_http_get_header(nng_http *conn, const char *key);
bool nng_http_next_header(nng_http *conn, const char **keyp, const char **valuep, void **next);
```

The {{i:`nng_http_get_header`}} returns the header value matching _key_ that was received over _conn_,
or `NULL` if no such header exists.

Thus, if _conn_ is a client connection, then this function returns the the header value
sent by the server as part of a response, whereas if it is a server connection, it returns
the header value sent by the client as part of the request.

If multiple headers are present with the same key, they may be returned as a combined value,
with individual values separated by commas, but this behavior is not guaranteed.

The {{i:`nng_http_next_header`}} function iterates over all the headers, using the same list
that `nng_http_get_header` uses. To start, it is called with _next_ initialized to `NULL`.
If a header was found, then it returns `true`, and sets _keyp_ and _valuep_ to values containing
the header name and value. It also updates _next_, which should be used for the next iteration.

Once `nng_http_next_header` returns `false`, further calls with the same parameters will continue to do so.
The scan can be rest by setting _next_ to `NULL`.

### Modifying Headers

```c
nng_err nng_http_add_header(nng_http *conn, const char *key, const char *val);
nng_err nng_http_set_header(nng_http *conn, const char *key, const char *val);
void nng_http_del_header(nng_http *conn, const char *key);
```

The {{i:`nng_http_add_header`}}, {{i:`nng_http_set_header`}}, and {{i:`nng_http_del_header`}} functions are
used to add a modify either the request or response headers for _conn_ prior to sending to the connected peer on _conn_.

Thus, if the _conn_ is a client connection created by [`nng_http_client_connect`], then the request headers are modified.
Conversely, if it is a connection created by an HTTP server and used in a callback function, then the response headers are modified.

The `nng_http_add_header` function adds a header with the name _key_, and the value _val_, to the list of headers.
In so doing, it may bring collapse multiple headers with the same name into a comma separated list, following
the syntax specified in RFC 9110. The function may return [`NNG_ENOMEM`], [`NNG_EMSGSIZE`], or [`NNG_EINVAL`].

The `nng_http_set_header` function adds the header if it does not already exist, but replaces any and all previously existing
headers with the same name _key_, if they exist. In all other respects it behaves similarly to `nng_http_add_header`.

The `nng_http_del_header` removes all headers with name _key_.

> [!NOTE]
> Some HTTP headers have special semantics, such as the "Host", "Content-Length", and "Content-Type" headers.
> This implementation may apply those semantics, in order to conform to the specifications for HTTP, such
> as by guaranting that only a single instance of one of these headers is present.

### Retrieving Body Content

```c
void nng_http_get_body(nng_http_conn *conn, void **datap, size_t *sizep);
```

The {{i:`nng_http_get_data`}} obtains the most recently received request or
response body. This will be `NULL` if the content has not been retrieved
properly yet, or if the peer did not any content. (Some requests are defined
to never have body content, such as "HEAD".)

### Storing Body Content

```c
void nng_http_set_body(nng_http_conn *conn, void *data, size_t size);
void nng_http_copy_body(nng_http_conn *conn, const void *data, size_t size);
```

The {{i:`nng_http_set_body`}} function sets the outgoing body content to _data_,
which must be _size_ bytes long. The caller must ensure that _data_ remains
valid for the duration of the transaction.

The {{i:`nng_http_copy_body`}} function makes a copy of _data_, which
will be freed automatically when the transaction is finished, but otherwise
behaves like `nng_http_set_body`.

On client _conn_ objects, these functions update the request object, but on server
_conn_ objects, they update the response object.

These functions also update the relevant "Content-Length" header.

> [!NOTE]
> The current framework does not support sending data via chunked
> transfer-encoding.

> [!TIP]
> It is a good idea to also set the `Content-Type` header.

### Closing the Connection

```c
void nng_http_close(nng_http *conn);
```

The {{i:`nng_http_close`}} function closes the supplied HTTP connection _conn_,
including any disposing of any underlying file descriptors or related resources.

Once this function, no further access to the _conn_ structure may be made.

### Reset Connection State

```c
void nng_http_reset(nng_http *conn);
```

The {{i:`nng_http_reset`}} function resets the request and response state of the
the connection _conn_, so that it is just as if it had been freshly created with
[`nng_http_client_connect`] or passed into a handler function for a server callback.

The intended purpose of this function is to clear the object state before reusing the _conn_ for
subsequent transactions.

### Direct Read and Write

```c
void nng_http_read(nng_http *conn, nng_aio *aio);
void nng_http_write(nng_http *conn, nng_aio *aio);
void nng_http_read_all(nng_http *conn, nng_aio *aio);
void nng_http_write_all(nng_http *conn, nng_aio *aio);
```

The {{i:`nng_http_read`}} and {{i:`nng_http_write`}} functions read or write data asynchronously from or to the
connection _conn_, using the [`nng_iov`] that is set in _aio_ with [`nng_aio_set_iov`].
These functions will complete as soon as any data is transferred.
Use [`nng_aio_count`] to determine how much data was actually transferred.

The {{i:`nng_http_read_all`}} and {{i:`nng_http_write_all`}} functions perform the same task, but will keep resubmitting
operations until the the entire amount of data requested by the [`nng_iov`] is transferred.

> [!NOTE]
> These functions perform no special handling for chunked transfers.

These functions are most likely to be useful after hijacking the connection with [`nng_http_hijack`].
They can be used to transfer request or response body data as well.

### Hijacking Connections

```c
nng_err nng_http_hijack(nng_http *conn);
```

TODO: This API will change to convert the conn into a stream object.

The {{i:`nng_http_hijack`}} function hijacks the connection _conn_, causing it
to be disassociated from the HTTP server where it was created.

The purpose of this function is the creation of HTTP upgraders (such as
WebSocket), where the underlying HTTP connection will be taken over for
some other purpose, and should not be used any further by the server.

This function is most useful when called from a handler function.
(See [`nng_http_handler_alloc`].)

> [!NOTE]
> It is the responsibility of the caller to dispose of the underlying connection when it is no longer needed.
> Furthermore, the HTTP server will no longer send any responses to the hijacked connection, so the caller should do that as well if appropriate.
> (See [`nng_http_write_response`].)

> [!TIP]
> This function is intended to facilitate uses cases that involve changing the protocol from HTTP, such as WebSocket.
> Most applications will never need to use this function.

### Obtaining TLS Connection Details

```c
nng_err nng_http_peer_cert(nng_http_conn *conn, nng_tls_cert **certp);
```

TODO: We need to document the cert API.

The {{i:`nng_http_peer_cert`}} function will obtain the TLS certificate object for the peer, if one is available.
This can then be used for additional authentication or identity specific logic.

The certificate must be released with [`nng_tls_cert_free`] when no longer in use.
See [`nng_tls_cert`] for more information about working with TLS certificates.

> [!NOTE]
> While it should be obvious that this function is only available when using HTTPS,
> it also requires that peer authentication is in use, and may require that the underlying
> TLS engine support peer certificate colleciton. (Some minimal configurations elide this
> to save space in embedded environments.)

## Client API

The NNG client API consists of an API for creating connections, and an API for performing
transactions on those connections.

### Client Object

```c
typedef struct nng_http_client nng_http_client;
```

The {{i:`nng_http_client`}} object is the client side creator for [`nng_http`] objects.
It is analogous to a [dialer] object used elsewhere in NNG, but it specifically is only for HTTP.

### Create a Client

```c
void nng_http_client_alloc(nng_http_client *clientp, const nng_url *url);
```

The {{i:`nng_http_client_alloc`}} allocates an HTTP client suitable for
connecting to the server identified by _url_ and stores a pointer to
it in the location referenced by _clientp_.

### Destroy a Client

```c
void nng_http_client_free(nng_http_client *client);
```

The {{i:`nng_http_client_free`}} connection destroys the client object and any
of its resources.

> [!NOTE]
> Any connections created by [`nng_http_client_connect`] are not affected by this function,
> and must be closed explicitly as needed.

### Client TLS

```c
nng_err nng_http_client_get_tls(nng_http_client *client, nng_tls_config **tlsp);
nng_err nng_http_client_set_tls(nng_http_client *client, nng_tls_config *tls);
```

The {{i:`nng_http_client_get_tls`}} and {{i:`nng_http_client_set_tls`}} functions are used to
retrieve or change the [TLS configuration][`nng_tls_config`] used when making outbound connections, enabling
{{i:TLS}} as a result.

If TLS has not been previously configured on _client_, then `nng_http_client_get_tls` will return [`NNG_EINVAL`].
Both functions will return [`NNG_ENOTSUP`] if either HTTP or TLS is not supported.

Calling `nng_http_client_set_tls` invalidates any client previously obtained with
`nng_http_client_get_tls`, unless a separate hold on the object was obtained.

Once TLS is enabled for an `nng_http_client`, it is not possible to disable TLS.

> [!NOTE]
> The TLS configuration itself cannot be changed once it has been used to create a connection,
> such as by calling [`nng_http_client_connect`], but a new one can be installed in the client.
> Existing connections will use the TLS configuration that there were created with.

### Creating Connections

```c
#include <nng/http.h>

void nng_http_client_connect(nng_http_client *client, nng_aio *aio);
```

The {{i:`nng_http_client_connect`}} function makes an outgoing connection to the
server configured for _client_, and creates an [`nng_http`] object for the connection.

This is done asynchronously, and when the operation succeseds the connection may be
retried from the _aio_ using [`nng_aio_get_output`] with index 0.

#### Example 1: Connecting to Google

```c
nng_aio *aio;
nng_url *url;
nng_http_client *client;
nng_http *conn;
nng_err rv;

// Error checks elided for clarity.
nng_url_parse(&url, "http://www.google.com");
nng_aio_alloc(&aio, NULL, NULL);
nng_http_client_alloc(&client, url);

nng_http_client_connect(client, aio);

// Wait for connection to establish (or attempt to fail).
nng_aio_wait(aio);

if ((rv = nng_aio_result(aio)) != 0) {
    printf("Connection failed: %s\n", nng_strerror(rv));
} else {
    // Connection established, get it.
    conn = nng_aio_get_output(aio, 0);

    // ... do something with it here

    // Close the connection when done to avoid leaking it.
    nng_http_close(conn);
}
```

### Preparing a Transaction

### Sending the Request

```c
void nng_http_write_request(nng_http *conn, nng_aio *aio);
```

The {{i:`nng_http_write_request`}} function starts an asynchronous write of
the HTTP request associated with _conn_.
The entire request is sent,
including headers, and if present, the request body data.
(The request body can be set with
[`nng_http_set_body`] or [`nng_http_copy_body`].)

This function returns immediately, with no return value.
Completion of the operation is signaled via the _aio_, and the final result
may be obtained via [`nng_aio_result`].

> [!TIP]
> Consider using the [`nng_http_transact`] function,
> which provides a simpler interface for performing a complete HTTP client transaction.

### Obtaining the Response

```c
void nng_http_read_response(nng_http *conn, nng_aio *aio);
```

The {{i:`nng_http_read_response`}} function starts an asynchronous read from the
HTTP connection _conn_, reading an HTTP response into the response associated with _conn_, including all
of the related headers.

It does _not_ transfer any response body. To do that, use [`nng_http_read_all`] or [`nng_http_read`].

> [!NOTE]
> At this time we have no API support for reading chunked transfers directly. Applications that
> need to do so may use the direct read functions.

> [!TIP]
> An easier one-shot method for many use cases might be [`nng_http_transact`].

### Submitting the Transaction

```c
void nng_http_transact(nng_http *conn, nng_aio *aio);
```

The HTTP request is issued, and the response processed, asynchronously by the {{i:`nng_http_transact`}} function.
When the function is complete, the _aio_ will be notified.

The {{i:`nng_http_transact`}} function is used to perform a complete
HTTP exchange over the connection _conn_, sending the request
and attached body data to the remote server, and reading the response.

The entire response is read, including any associated body, which can
subsequently be obtained using [`nng_http_get_body`].

This function is intended to make creation of client applications easier,
by performing multiple asynchronous operations required to complete an
entire HTTP transaction.

If an error occurs, the caller should close _conn_ with [`nng_http_close`], as it may not
necessarily be usable with other transactions.

> [!WARNING]
> If the remote server tries to send an extremely large buffer,
> then a corresponding allocation will be made, which can lead to denial
> of service attacks.
> Client applications should take care to use this only with reasonably
> trust-worthy servers.

> [!NOTE]
> A given connection _conn_ should be used with only one
> operation or transaction at a time as HTTP/1.1 has no support for
> request interleaving.

This function returns immediately, with no return value.
Completion of the operation is signaled via the _aio_, and the final result
may be obtained via [`nng_aio_result`].

### Socket Addresses

```c
nng_err nng_http_local_address(nng_http *conn, nng_sockaddr *addr);
nng_err nng_http_remote_address(nng_http *conn, nng_sockaddr *addr);
```

The {{i:`nng_http_local_address`}} and {{i:`nng_http_remote_address`}} functions
can be used to determine the local and remote addresses for an HTTP connection.
This can only be done while the connection is alive.

### Response Body

## Server API

### Handlers

```c
typedef struct nng_http_handler nng_http_handler;
```

An {{i:`nng_http_handler`}} encapsulates a function used used to handle
incoming requests on an HTTP server, routed based on method and URI,
and the parameters used with that function.

Every handler has a Request-URI to which it refers, which is determined by the _path_ argument.
Only the path component of the Request URI is considered when determining whether the handler should be called.

This implementation limits the _path_ length to 1024 bytes, including the
zero termination byte. This does not prevent requests with much longer
URIs from being supported, but doing so will require setting the handler to match a parent path in the tree using
[`nng_http_handler_set_tree`].

> [!TIP]
> The NNG HTTP framework is optimized for URLs shorter than 200 characters.

Additionally each handler has a method it is registered to handle
(the default is "GET" andc can be changed with [`nng_http_handler_set_method`]), and
optionally a "Host" header it can be matched against (see [`nng_http_handler_set_host`]).

In some cases, a handler may reference a logical tree rather (directory)
rather than just a single element.
(See [`nng_http_handler_set_tree`]).

### Implementing a Handler

```c
typedef void (*nng_http_handler_func)(nng_http_conn *conn, void *arg, nng_aio *aio);

nng_err nng_http_handler_alloc(nng_http_handler **hp, const char *path, nng_http_handler_func cb);
```

The {{i:`nng_http_handler_alloc`}} function allocates a generic handler
which will be used to process requests coming into an HTTP server.
On success, a pointer to the handler is stored at the located pointed to by _hp_.

The handler function is specified by _cb_.
This function uses the asynchronous I/O framework.

The function receives the connection on _conn_, and an optional data pointer that was set
previously with [`nng_http_handler_set_data`] as the second argument. The
final argument is the [`nng_aio`] _aio_, which must be "finished" to complete the operation.

The handler may call [`nng_http_write_response`] to send the response, or
it may simply let the framework do so on its behalf. The server will perform
this step if the callback has not already done so.

Response headers may be set using [`nng_http_set_header`], and request headers
may be accessed by using [`nng_http_get_header`]. They can also be iterated
over using [`nng_http_next_header`]

Likewise the request body may be accessed, using [`nng_http_get_body`], and
the response body may be set using either [`nng_http_set_body`] or [`nng_http_copy_body`].

> [!NOTE]
> The request body is only collected for the handler if the
> [`nng_http_handler_collect_body`] function has been called for the handler.

The HTTP status should be set for the transaction using [`nng_http_set_status`].

Finally, the handler should finish the operation by calling the [`nng_aio_finish`] function
after having set the status to [`NNG_OK`].
If any other status is set on the _aio_, then a generic 500 response will be created and
sent, if possible, and the connection will be closed.

The _aio_ may be scheduled for deferred completion using the [`nng_aio_start`].

### Freeing Handler

```c
void nng_http_handler_free(nng_http_handler *h);
```

The {{i:`nng_http_handler_free`}} function frees an allocated HTTP server handler.
Normally there is no reason to call this function, because the handler is freed with
the server it was registered with.

> [!IMPORTANT]
> It is an error to free a handler that is registered with a server.
> Any handlers that are registered with servers are automatically freed
> when the server itself is deallocated.

### Serving Directories and Files

```c
nng_err nng_http_handler_alloc_directory(nng_http_handler **hp, const char *path, const char *dirname);
nng_err nng_http_handler_alloc_file(nng_http_handler **hp, const char *path, const char *filename);
```

The {{i:`nng_http_handler_alloc_directory`}} and {{i:`nng_http_handler_alloc_file`}}
create handlers pre-configured to act as static content servers for either a full
directory at _dirname_, or the single file at _filename_. These support the "GET" and "HEAD"
methods, and the directory variant will dynamically generate `index.html` content based on
the directory contents. These will also set the "Content-Type" if the file extension
matches one of the built-in values already known. If the no suitable MIME type can be
determined, the content type is set to "application/octet-stream".

### Static Handler

```c
nng_err nng_http_handler_alloc_static(nng_http_handler **hp, const char *path,
        const void *data, size_t size, const char *content_type);
```

The {{i:`nng_http_handler_alloc_static`}} function creates a handler that
serves the content located in _data_ (consisting of _size_ bytes) at the URI _path_.
The _content_type_ determines the "Content-Type" header. If `NULL` is specified
then a value of `application/octet-stream` is assumed.

### Redirect Handler

```c
nng_err nng_http_handler_alloc_redirect(nng_http_handler **hp, const char *path,
        nng_http_status status, const char *location);
```

The {{i:`nng_http_handler_alloc_redirect`}} function creates a handler with
a function that simply directions from the URI at _path_ to the given _location_.

The HTTP reply it creates will be with [status code][`nng_http_status`] _status_,
which should be a 3XX code such as 301, and a `Location:` header will contain the URL
referenced by _location_, with any residual suffix from the request
URI appended.

> [!TIP]
> Use [`nng_http_handler_set_tree`] to redirect an entire tree.
> For example, it is possible to redirect an entire HTTP site to another
> HTTPS site by specifying `/` as the path and then using the base
> of the new site, such as `https://newsite.example.com` as the new location.

> [!TIP]
> Be sure to use the appropriate value for _status_.
> Permanent redirection should use [`NNG_HTTP_STATUS_MOVED_PERMANENTLY`] (301)
> and temporary redirections should use [`NNG_HTTP_STATUS_TEMPORARY_REDIRECT`] (307).
> In REST APIs, using a redirection to supply the new location of an object
> created with `POST` should use [`NNG_HTTP_STATUS_SEE_OTHER`] (303).

### Collecting Request Body

```c
void nng_http_handler_collect_body(nng_http_handler *handler, bool want, size_t maxsz);
```

The {{i:`nng_http_handler_collect_body`}} function requests that HTTP server
framework collect any request body for the request and attach it to the
connection before calling the callback for the _handler_.

Subsequently the data can be retrieved by the handler from the request with the
[`nng_http_get_body`] function.

The collection is enabled if _want_ is true.
Furthermore, the data that the client may sent is limited by the
value of _maxsz_.
If the client attempts to send more data than _maxsz_, then the
request will be terminated with [`NNG_HTTP_STATUS_CONTENT_TOO_LARGE`] (413).

> [!TIP]
> Limiting the size of incoming request data can provide protection
> against denial of service attacks, as a buffer of the client-supplied
> size must be allocated to receive the data.

> In order to provide an unlimited size, use `(size_t)-1` for _maxsz_.
> The value `0` for _maxsz_ can be used to prevent any data from being passed
> by the client.

> The built-in handlers for files, directories, and static data limit the
> _maxsz_ to zero by default.
> Otherwise the default setting is to enable this capability with a default
> value of _maxsz_ of 1 megabyte.

> [!NOTE]
> NNG specifically does not support the `Chunked` transfer-encoding.
> This is considered a bug, and is a deficiency for full HTTP/1.1 compliance.
> However, few clients send data in this format, so in practice this should
> create few limitations.

### Setting Callback Argument

```c
void nng_http_handler_set_data(nng_http_handler *handler, void *data,
    void (*dtor)(void *));
```

The {{i:`nng_http_handler_set_data`}} function is used to set the
_data_ argument that will be passed to the callback.

Additionally, when the handler is deallocated, if _dtor_ is not `NULL`,
then it will be called with _data_ as its argument.
The intended use of this function is deallocate any resources associated with _data_.

### Setting the Method

```c
void nng_http_handler_set_method(nng_http_handler *handler, const char *method);
```

The {{i:`nng_http_handler_set_method`}} function sets the _method_ that the
_handler_ will be called for, such as "GET" or "POST".
(By default the "GET" method is handled.)

If _method_ is `NULL` the handler will be executed for all methods.
The handler may determine the actual method used with the [`nng_http_get_method`] function.

The server will automatically call "GET" handlers if the client
sends a "HEAD" request, and will suppress HTTP body data in the responses
sent for such requests.

> [!NOTE]
> If _method_ is longer than 32-bytes, it may be truncated silently.

### Filtering by Host

```c
void nng_http_handler_set_host(nng_http_handler *handler, const char *host);
```

The {{i:`nng_http_handler_set_host`}} function is used to limit the scope of the
_handler_ so that it will only be called when the specified _host_ matches
the value of the `Host:` HTTP header.

This can be used to create servers with different content for different virtual hosts.

The value of the _host_ can include a colon and port, and should match
exactly the value of the `Host` header sent by the client.
(Canonicalization of the host name is performed.)

> [!NOTE]
> The port number may be ignored; at present the HTTP server framework
> does not support a single server listening on different ports concurrently.

### Detecting Addresses

The [`nng_http_local_address`] and [`nng_http_remote_address`] functions
can be used to determine the local and remote addresses for an HTTP connection
on the server side (in a handler) just like the can be for HTTP clients
This can be useful to provide different handling behaviors based on network identity.

### Handling an Entire Tree

```c
void nng_http_handler_set_tree(nng_http_handler *handler);
```

The {{i:`nng_http_handler_set_tree`}} function causes the _handler_ to be matched if the request URI sent
by the client is a logical child of the path for _handler_, and no more specific
_handler_ has been registered.

This is useful in cases when the handler would like to examine the entire path
and possibly behave differently; for example a REST API that uses the rest of
the path to pass additional parameters.

> [!TIP]
> This function is useful when constructing API handlers where a single
> service address (path) supports dynamically generated children.
> It can also provide a logical fallback instead of relying on a 404 error code.

### Sending the Response Explicitly

```c
void nng_http_write_response(nng_http *conn, nng_aio *aio);
```

Normally the server will send any attached response, but there are circumstances where
a response must be sent manually, such as when [hijacking][`nng_http_hijack`] a connection.

In such a case, {{i:`nng_http_write_response`}} can be called, which will send the response and any attached data, asynchronously
using the [`nng_aio`] _aio_.

By default, for `HTTP/1.1` connections, the connection is kept open, and
will be reused to receive new requests. For `HTTP/1.0`, or if the client has requested
explicitly by setting the "Connection: close" header, the connection will be closed after the
response is fully sent.

{{#include ../xref.md}}
