//
// Copyright 2025 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
// Copyright 2018 QXSoftware <lh563566994@126.com>
// Copyright 2019 Devolutions <info@devolutions.net>
// Copyright 2020 Dirac Research <robert.bielik@dirac.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <ctype.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../core/nng_impl.h"

#include "http_api.h"
#include "http_msg.h"
#include "nng/http.h"
#include "nng/nng.h"

#ifndef NNG_HTTP_MAX_URI
#define NNG_HTTP_MAX_URI 1024
#endif

struct nng_http_handler {
	nni_list_node         node;
	char                  uri[NNG_HTTP_MAX_URI];
	char                  method[32];
	char                  host[256]; // RFC 1035
	nng_sockaddr          host_addr;
	bool                  host_ip;
	bool                  tree;
	nni_atomic_int        ref;
	nni_atomic_bool       busy;
	size_t                maxbody;
	bool                  getbody;
	void                 *data;
	nni_cb                dtor;
	nng_http_handler_func cb;
	void                 *arg;
};

typedef struct http_sconn {
	nni_list_node     node;
	nni_http_conn    *conn;
	nni_http_server  *server;
	nni_http_handler *handler; // set if we deferred to read body
	nni_http_handler *release; // set if we dispatched handler
	bool              close;
	bool              finished;
	size_t            unconsumed_body;
	size_t            unconsumed_request;
	nni_aio           cbaio;
	nni_aio           rxaio;
	nni_aio           txaio;
	nni_aio           txdataio;
	nni_reap_node     reap;
	nni_atomic_flag   closed;
	nni_http_header   close_header;
} http_sconn;

typedef struct http_error {
	nni_list_node   node;
	nng_http_status code;
	char           *body;
} http_error;

struct nng_http_server {
	nng_sockaddr         addr;
	nni_list_node        node;
	int                  refcnt;
	int                  starts;
	nni_list             handlers;
	nni_list             conns;
	nni_mtx              mtx;
	bool                 closed;
	bool                 fini; // if nni_http_server_fini was called
	nni_aio              accaio;
	nng_stream_listener *listener;
	uint32_t             port; // native order
	char                *hostname;
	nni_list             errors;
	nni_mtx              errors_mtx;
	nni_reap_node        reap;
};

static void http_sc_reap(void *);

static nni_reap_list http_sc_reap_list = {
	.rl_offset = offsetof(http_sconn, reap),
	.rl_func   = http_sc_reap,
};

static void http_server_fini(nni_http_server *);

static void
http_server_fini_cb(void *arg)
{
	http_server_fini((nni_http_server *) arg);
}

static nni_reap_list http_server_reap_list = {
	.rl_offset = offsetof(nni_http_server, reap),
	.rl_func   = http_server_fini_cb,
};

nng_err
nni_http_handler_init(
    nni_http_handler **hp, const char *uri, nng_http_handler_func cb)
{
	nni_http_handler *h;

	if ((h = NNI_ALLOC_STRUCT(h)) == NULL) {
		return (NNG_ENOMEM);
	}
	nni_atomic_init(&h->ref);
	nni_atomic_inc(&h->ref);

	// Default for HTTP is /.  But remap it to "" for ease of matching.
	if ((uri == NULL) || (strlen(uri) == 0) || (strcmp(uri, "/") == 0)) {
		uri = "";
	}
	(void) snprintf(h->uri, sizeof(h->uri), "%s", uri);
	NNI_LIST_NODE_INIT(&h->node);
	h->cb      = cb;
	h->data    = NULL;
	h->dtor    = NULL;
	h->tree    = false;
	h->maxbody = 1024 * 1024; // Up to 1MB of body
	h->getbody = true;
	(void) strcpy(h->method, "GET");
	(void) strcpy(h->host, "");
	*hp = h;
	return (NNG_OK);
}

// nni_http_handler_fini just drops the reference count, only destroying
// the handler if the reference drops to zero.
void
nni_http_handler_fini(nni_http_handler *h)
{
	if (nni_atomic_dec_nv(&h->ref) != 0) {
		return;
	}
	if (h->dtor != NULL) {
		h->dtor(h->data);
	}
	NNI_FREE_STRUCT(h);
}

void
nni_http_handler_collect_body(nni_http_handler *h, bool want, size_t maxbody)
{
	h->getbody = want;
	h->maxbody = maxbody;
}

void
nni_http_handler_set_data(nni_http_handler *h, void *data, nni_cb dtor)
{
	NNI_ASSERT(!nni_atomic_get_bool(&h->busy));
	h->data = data;
	h->dtor = dtor;
}

const char *
nni_http_handler_get_uri(nni_http_handler *h)
{
	if (strlen(h->uri) == 0) {
		return ("/");
	}
	return (h->uri);
}

void
nni_http_handler_set_tree(nni_http_handler *h)
{
	NNI_ASSERT(!nni_atomic_get_bool(&h->busy));
	h->tree = true;
}

void
nni_http_handler_set_host(nni_http_handler *h, const char *host)
{
	NNI_ASSERT(!nni_atomic_get_bool(&h->busy));

	if ((host == NULL) || (strcmp(host, "*") == 0) ||
	    strcmp(host, "") == 0) {
		(void) strcpy(h->host, "");
		return;
	}
	if (nni_parse_ip(host, &h->host_addr) == 0) {
		uint8_t wild[16] = { 0 };

		// Check for wild card addresses.
		switch (h->host_addr.s_family) {
		case NNG_AF_INET:
			if (h->host_addr.s_in.sa_addr == 0) {
				(void) strcpy(h->host, "");
				return;
			}
			break;
		case NNG_AF_INET6:
			if (memcmp(h->host_addr.s_in6.sa_addr, wild, 16) ==
			    0) {
				(void) strcpy(h->host, "");
				return;
			}
			break;
		}
		h->host_ip = true;
	}
	(void) snprintf(h->host, sizeof(h->host), "%s", host);
}

void
nni_http_handler_set_method(nni_http_handler *h, const char *method)
{
	NNI_ASSERT(!nni_atomic_get_bool(&h->busy));
	if (method == NULL) {
		method = "";
	}
	(void) snprintf(h->method, sizeof(h->method), "%s", method);
}

static nni_list http_servers =
    NNI_LIST_INITIALIZER(http_servers, nni_http_server, node);
static nni_mtx http_servers_lk = NNI_MTX_INITIALIZER;

static void
http_sc_reap(void *arg)
{
	http_sconn      *sc = arg;
	nni_http_server *s  = sc->server;
	NNI_ASSERT(!sc->finished);
	sc->finished = true;
	nni_aio_stop(&sc->rxaio);
	nni_aio_stop(&sc->txaio);
	nni_aio_stop(&sc->txdataio);
	nni_aio_stop(&sc->cbaio);

	if (sc->conn != NULL) {
		nni_http_conn_fini(sc->conn);
	}
	nni_aio_fini(&sc->rxaio);
	nni_aio_fini(&sc->txaio);
	nni_aio_fini(&sc->txdataio);
	nni_aio_fini(&sc->cbaio);

	// Now it is safe to release our reference on the server.
	nni_mtx_lock(&s->mtx);
	if (nni_list_node_active(&sc->node)) {
		nni_list_remove(&s->conns, sc);
	}
	if (nni_list_empty(&s->conns) && (s->fini)) {
		nni_reap(&http_server_reap_list, s);
	}
	nni_mtx_unlock(&s->mtx);

	NNI_FREE_STRUCT(sc);
}

static void
http_sconn_close(http_sconn *sc)
{
	nni_http_conn *conn;

	if (nni_atomic_flag_test_and_set(&sc->closed)) {
		return;
	}
	NNI_ASSERT(!sc->finished);

	nni_aio_close(&sc->rxaio);
	nni_aio_close(&sc->txaio);
	nni_aio_close(&sc->txdataio);
	nni_aio_close(&sc->cbaio);

	if ((conn = sc->conn) != NULL) {
		nni_http_conn_close(conn);
	}
	nni_reap(&http_sc_reap_list, sc);
}

static void
http_sconn_txdatdone(void *arg)
{
	http_sconn *sc  = arg;
	nni_aio    *aio = &sc->txdataio;

	if (nni_aio_result(aio) != NNG_OK) {
		http_sconn_close(sc);
		return;
	}

	if (sc->close) {
		http_sconn_close(sc);
		return;
	}

	sc->handler = NULL;
	nni_http_read_req(sc->conn, &sc->rxaio);
}

static void
http_sconn_txdone(void *arg)
{
	http_sconn *sc  = arg;
	nni_aio    *aio = &sc->txaio;

	if (nni_aio_result(aio) != NNG_OK) {
		http_sconn_close(sc);
		return;
	}

	if (sc->close) {
		http_sconn_close(sc);
		return;
	}

	sc->handler = NULL;
	if (sc->unconsumed_body) {
		nni_http_read_discard(
		    sc->conn, sc->unconsumed_body, &sc->rxaio);
	} else {
		nni_http_read_req(sc->conn, &sc->rxaio);
	}
}

static void
http_sconn_error(http_sconn *sc, nng_http_status err)
{
	nng_http_set_status(sc->conn, err, NULL);
	if (nni_http_server_error(sc->server, sc->conn) != 0) {
		http_sconn_close(sc);
		return;
	}

	if (sc->close) {
		nni_http_set_static_header(
		    sc->conn, &sc->close_header, "Connection", "close");
	}
	nni_http_write_res(sc->conn, &sc->txaio);
}

nng_err
nni_http_hijack(nni_http_conn *conn)
{
	http_sconn *sc;

	sc = nni_http_conn_get_ctx(conn);
	if (sc != NULL) {
		nni_http_server *s = sc->server;
		nni_http_conn_set_ctx(conn, NULL);

		nni_mtx_lock(&s->mtx);
		sc->conn = NULL;
		nni_mtx_unlock(&s->mtx);
	}
	return (NNG_OK);
}

static bool
http_handler_host_match(nni_http_handler *h, const char *host)
{
	nng_sockaddr sa;
	size_t       len;

	if ((len = strlen(h->host)) == '\0') {
		return (true);
	}
	if (host == NULL) {
		// Virtual hosts not possible under HTTP/1.0
		return (false);
	}
	if (h->host_ip) {
		if (nni_parse_ip_port(host, &sa) != 0) {
			return (false);
		}
		switch (h->host_addr.s_family) {
		case NNG_AF_INET:
			if ((sa.s_in.sa_family != NNG_AF_INET) ||
			    (sa.s_in.sa_addr != h->host_addr.s_in.sa_addr)) {
				return (false);
			}
			return (true);
		case NNG_AF_INET6:
			if (sa.s_in6.sa_family != NNG_AF_INET6) {
				return (false);
			}
			if (memcmp(sa.s_in6.sa_addr,
			        h->host_addr.s_in6.sa_addr, 16) != 0) {
				return (false);
			}
			return (true);
		}
	}

	if ((nni_strncasecmp(host, h->host, len) != 0)) {
		return (false);
	}

	// At least the first part matches.  If the ending
	// part is a lone "." (legal in DNS), or a port
	// number, we match it.  (We do not validate the
	// port number.)  Note that there may be false matches
	// with IPv6 addresses, but addresses shouldn't be
	// used with virtual hosts anyway.  With both addresses
	// and ports, a false match would be unlikely since
	// they'd still have to *connect* using that info.
	if ((host[len] != '\0') && (host[len] != ':') &&
	    ((host[len] != '.') || (host[len + 1] != '\0'))) {
		return (false);
	}

	return (true);
}

static void
http_sconn_rxdone(void *arg)
{
	http_sconn       *sc  = arg;
	nni_http_server  *s   = sc->server;
	nni_aio          *aio = &sc->rxaio;
	int               rv;
	nni_http_handler *h    = NULL;
	nni_http_handler *head = NULL;
	const char       *val;
	nni_http_req     *req = nni_http_conn_req(sc->conn);
	const char       *uri;
	bool              badmeth  = false;
	bool              needhost = false;
	const char       *host;
	const char       *cls;

	if ((rv = nni_aio_result(aio)) != NNG_OK) {
		http_sconn_close(sc);
		return;
	}

	// read the body, keep going
	if (sc->unconsumed_body) {
		sc->unconsumed_body = 0;
		nni_http_read_req(sc->conn, aio);
		return;
	}

	if ((h = sc->handler) != NULL) {
		nni_mtx_lock(&s->mtx);
		goto finish;
	}

	// Validate the request -- it has to at least look like HTTP
	// 1.x.  We flatly refuse to deal with HTTP 0.9, and we can't
	// cope with HTTP/2.
	if (nng_http_get_status(sc->conn) >= NNG_HTTP_STATUS_BAD_REQUEST) {
		http_sconn_error(sc, nng_http_get_status(sc->conn));
		return;
	}
	if ((val = nng_http_get_version(sc->conn)) == NULL) {
		sc->close = true;
		http_sconn_error(sc, NNG_HTTP_STATUS_BAD_REQUEST);
		return;
	}
	if (strncmp(val, "HTTP/1.", 7) != 0) {
		sc->close = true;
		http_sconn_error(sc, NNG_HTTP_STATUS_HTTP_VERSION_NOT_SUPP);
		return;
	}
	if (strcmp(val, "HTTP/1.1") != 0) {
		// We treat HTTP/1.0 connections as non-persistent.
		// No effort is made for non-standard "persistent" HTTP/1.0.
		sc->close = true;
	} else {
		needhost = true;
	}

	// NB: The URI will already have been canonified by the REQ parser
	uri = nng_http_get_uri(sc->conn);
	if (uri[0] != '/') {
		// We do not support authority form or asterisk form at present
		sc->close = true;
		http_sconn_error(sc, NNG_HTTP_STATUS_BAD_REQUEST);
		return;
	}

	// If the connection was 1.0, or a connection: close was
	// requested, then mark this close on our end.
	if ((val = nni_http_get_header(sc->conn, "Connection")) != NULL) {
		// HTTP 1.1 says these have to be case insensitive
		if (nni_strcasestr(val, "close") != NULL) {
			// In theory this could falsely match some other weird
			// connection header with the substring close.  No such
			// values are defined, so anyone who does that gets
			// what they deserve. (Harmless actually, since it only
			// prevents persistent connections.)
			sc->close = true;
		}
	}

	sc->unconsumed_body = 0;
	if ((cls = nni_http_get_header(sc->conn, "Content-Length")) != NULL) {
		char *end;
		sc->unconsumed_body = strtoull(cls, &end, 10);
		if ((end == NULL) && (*end != '\0')) {
			sc->unconsumed_body = 0;
			http_sconn_error(sc, NNG_HTTP_STATUS_BAD_REQUEST);
			return;
		}
	}

	host = nni_http_get_header(sc->conn, "Host");
	if ((host == NULL) && (needhost)) {
		// Per RFC 2616 14.23 we have to send 400 status here.
		http_sconn_error(sc, NNG_HTTP_STATUS_BAD_REQUEST);
		return;
	}

	nni_mtx_lock(&s->mtx);
	NNI_LIST_FOREACH (&s->handlers, h) {
		size_t len;

		if (!http_handler_host_match(h, host)) {
			continue;
		}

		len = strlen(h->uri);
		if (strncmp(uri, h->uri, len) != 0) {
			continue;
		}
		switch (uri[len]) {
		case '\0':
			break;
		case '/':
			if ((uri[len + 1] != '\0') && (!h->tree)) {
				// Trailing component and not a directory.
				continue;
			}
			break;
		default:
			continue; // Some other substring, not matched.
		}

		if (h->method[0] == '\0') {
			// Handler wants to process *all* methods.
			break;
		}
		// So, what about the method?
		val = nni_http_get_method(sc->conn);
		if (strcmp(val, h->method) == 0) {
			break;
		}
		// HEAD is remapped to GET, but only if no HEAD specific
		// handler registered.
		if ((strcmp(val, "HEAD") == 0) &&
		    (strcmp(h->method, "GET") == 0)) {
			head = h;
			continue;
		}
		badmeth = 1;
	}

	if ((h == NULL) && (head != NULL)) {
		h = head;
	}
	if (h == NULL) {
		nni_mtx_unlock(&s->mtx);
		if (badmeth) {
			http_sconn_error(
			    sc, NNG_HTTP_STATUS_METHOD_NOT_ALLOWED);
		} else {
			http_sconn_error(sc, NNG_HTTP_STATUS_NOT_FOUND);
		}
		return;
	}

	if ((h->getbody) && (sc->unconsumed_body > 0)) {

		if (sc->unconsumed_body > h->maxbody) {
			nni_mtx_unlock(&s->mtx);
			http_sconn_error(
			    sc, NNG_HTTP_STATUS_CONTENT_TOO_LARGE);
			return;
		}
		nng_iov iov;
		if ((nni_http_req_alloc_data(req, sc->unconsumed_body)) != 0) {
			nni_mtx_unlock(&s->mtx);
			http_sconn_error(
			    sc, NNG_HTTP_STATUS_INTERNAL_SERVER_ERROR);
			return;
		}
		iov.iov_buf         = req->data.data;
		iov.iov_len         = req->data.size;
		sc->unconsumed_body = 0;
		sc->handler         = h;
		nni_mtx_unlock(&s->mtx);
		nni_aio_set_iov(&sc->rxaio, 1, &iov);
		nni_http_read_full(sc->conn, aio);
		return;
	}

finish:
	sc->release = h;
	sc->handler = NULL;

	// Set a reference -- this because the callback may be running
	// asynchronously even after it gets removed from the server.
	nni_atomic_inc(&h->ref);

	nni_aio_reset(&sc->cbaio);

	nni_mtx_unlock(&s->mtx);

	// make sure the response is freshly initialized
	nni_http_res_reset(nni_http_conn_res(sc->conn));
	nni_http_set_version(sc->conn, NNG_HTTP_VERSION_1_1);
	nni_http_set_status(sc->conn, 0, NULL);

	h->cb(sc->conn, h->data, &sc->cbaio);
}

static void
http_sconn_cbdone(void *arg)
{
	http_sconn       *sc  = arg;
	nni_aio          *aio = &sc->cbaio;
	nni_http_handler *h;
	nni_http_server  *s = sc->server;

	// Get the handler.  It may be set regardless of success or
	// failure.  Clear it, and drop our reference, since we're
	// done with the handler for now.
	if ((h = sc->release) != NULL) {
		sc->release = NULL;
		nni_http_handler_fini(h);
	}

	if (nni_aio_result(aio) != 0) {
		// Hard close, no further feedback.
		http_sconn_close(sc);
		return;
	}

	// If it's an upgrader, and they didn't give us back a response,
	// it means that they took over, and we should just discard
	// this session, without closing the underlying channel.
	if (sc->conn == NULL) {
		// If this happens, then the session was hijacked.
		// We close the context, but the http channel stays up.
		http_sconn_close(sc);
		return;
	}
	if (!nni_http_res_sent(sc->conn)) {
		const char     *val;
		const char     *method;
		nng_http_status status;
		val    = nni_http_get_header(sc->conn, "Connection");
		status = nni_http_get_status(sc->conn);
		method = nni_http_get_method(sc->conn);
		if ((val != NULL) && (strstr(val, "close") != NULL)) {
			sc->close = true;
		}
		if (sc->close) {
			nni_http_set_header(sc->conn, "Connection", "close");
		}
		if ((strcmp(method, "HEAD") == 0) && status >= 200 &&
		    status <= 299) {
			// prune off data, preserving content-length header.
			nni_http_prune_body(sc->conn);
		} else if (nni_http_is_error(sc->conn)) {
			(void) nni_http_server_error(s, sc->conn);
		}
		nni_http_write_res(sc->conn, &sc->txaio);
	} else if (sc->close) {
		http_sconn_close(sc);
	} else {
		// Presumably client already sent a response.
		// Wait for another request.
		sc->handler = NULL;
		nni_http_read_req(sc->conn, &sc->rxaio);
	}
}

static nng_err
http_sconn_init(http_sconn **scp, nng_stream *stream)
{
	http_sconn *sc;
	nng_err     rv;

	if ((sc = NNI_ALLOC_STRUCT(sc)) == NULL) {
		nng_stream_free(stream);
		return (NNG_ENOMEM);
	}

	nni_aio_init(&sc->rxaio, http_sconn_rxdone, sc);
	nni_aio_init(&sc->txaio, http_sconn_txdone, sc);
	nni_aio_init(&sc->txdataio, http_sconn_txdatdone, sc);
	nni_aio_init(&sc->cbaio, http_sconn_cbdone, sc);

	if ((rv = nni_http_init(&sc->conn, stream, false)) != 0) {
		// Can't even accept the incoming request.  Hard close.
		http_sconn_close(sc);
		return (rv);
	}

	nni_http_conn_set_ctx(sc->conn, sc);
	*scp = sc;
	return (NNG_OK);
}

static void
http_server_acccb(void *arg)
{
	nni_http_server *s   = arg;
	nni_aio         *aio = &s->accaio;
	nng_stream      *stream;
	http_sconn      *sc;
	int              rv;

	nni_mtx_lock(&s->mtx);
	if ((rv = nni_aio_result(aio)) != 0) {
		if (!s->closed) {
			// try again?
			nng_stream_listener_accept(s->listener, aio);
		}
		nni_mtx_unlock(&s->mtx);
		return;
	}
	stream = nni_aio_get_output(aio, 0);
	if (s->closed) {
		// If we're closing, then reject this one.
		nng_stream_free(stream);
		nni_mtx_unlock(&s->mtx);
		return;
	}
	if (http_sconn_init(&sc, stream) != 0) {
		// The stream structure is already cleaned up.
		// Start another accept attempt.
		nng_stream_listener_accept(s->listener, aio);
		nni_mtx_unlock(&s->mtx);
		return;
	}
	sc->server = s;
	nni_list_append(&s->conns, sc);

	sc->handler = NULL;
	nni_http_read_req(sc->conn, &sc->rxaio);
	nng_stream_listener_accept(s->listener, aio);
	nni_mtx_unlock(&s->mtx);
}

static void
http_server_fini(nni_http_server *s)
{
	nni_http_handler *h;
	http_error       *epage;

	nni_aio_stop(&s->accaio);
	nng_stream_listener_stop(s->listener);

	nni_mtx_lock(&s->mtx);
	NNI_ASSERT(nni_list_empty(&s->conns));
	nng_stream_listener_free(s->listener);
	while ((h = nni_list_first(&s->handlers)) != NULL) {
		nni_list_remove(&s->handlers, h);
		nni_http_handler_fini(h);
	}
	nni_mtx_unlock(&s->mtx);
	nni_mtx_lock(&s->errors_mtx);
	while ((epage = nni_list_first(&s->errors)) != NULL) {
		nni_list_remove(&s->errors, epage);
		nni_strfree(epage->body);
		NNI_FREE_STRUCT(epage);
	}
	nni_mtx_unlock(&s->errors_mtx);
	nni_mtx_fini(&s->errors_mtx);

	nni_aio_fini(&s->accaio);
	nni_mtx_fini(&s->mtx);
	nni_strfree(s->hostname);
	NNI_FREE_STRUCT(s);
}

static nng_err
http_server_init(nni_http_server **serverp, const nng_url *url)
{
	nni_http_server *s;
	nng_err          rv;
	nng_url          my_url;
	const char      *scheme;

	if ((scheme = nni_http_stream_scheme(url->u_scheme)) == NULL) {
		return (NNG_EADDRINVAL);
	}
	// Rewrite URLs to either TLS or TCP.
	memcpy(&my_url, url, sizeof(my_url));
	my_url.u_scheme = (char *) scheme;

	if ((s = NNI_ALLOC_STRUCT(s)) == NULL) {
		return (NNG_ENOMEM);
	}
	nni_mtx_init(&s->mtx);
	nni_mtx_init(&s->errors_mtx);
	NNI_LIST_INIT(&s->handlers, nni_http_handler, node);
	NNI_LIST_INIT(&s->conns, http_sconn, node);

	nni_mtx_init(&s->errors_mtx);
	NNI_LIST_INIT(&s->errors, http_error, node);

	nni_aio_init(&s->accaio, http_server_acccb, s);

	s->port = url->u_port;

	if ((s->hostname = nni_strdup(url->u_hostname)) == NULL) {
		http_server_fini(s);
		return (NNG_ENOMEM);
	}

	if ((rv = nng_stream_listener_alloc_url(&s->listener, &my_url)) != 0) {
		http_server_fini(s);
		return (rv);
	}

	s->refcnt = 1;
	*serverp  = s;
	return (NNG_OK);
}

nng_err
nni_http_server_init(nni_http_server **serverp, const nng_url *url)
{
	nng_err          rv;
	nni_http_server *s;

	nni_mtx_lock(&http_servers_lk);
	NNI_LIST_FOREACH (&http_servers, s) {
		nni_mtx_lock(&s->mtx);
		if ((!s->closed) && (url->u_port == s->port) &&
		    (strcmp(url->u_hostname, s->hostname) == 0)) {
			*serverp = s;
			s->refcnt++;
			nni_mtx_unlock(&s->mtx);
			nni_mtx_unlock(&http_servers_lk);
			return (NNG_OK);
		}
		nni_mtx_unlock(&s->mtx);
	}

	// We didn't find a server, try to make a new one.
	if ((rv = http_server_init(&s, url)) == 0) {
		nni_list_append(&http_servers, s);
		*serverp = s;
	}

	nni_mtx_unlock(&http_servers_lk);
	return (rv);
}

static nng_err
http_server_start(nni_http_server *s)
{
	nng_err rv;
	if ((rv = nng_stream_listener_listen(s->listener)) != 0) {
		return (rv);
	}
	if (s->port == 0) {
		int port;
		nng_stream_listener_get_int(
		    s->listener, NNG_OPT_BOUND_PORT, &port);
		s->port = (uint32_t) port;
	}
	nng_stream_listener_accept(s->listener, &s->accaio);
	return (NNG_OK);
}

nng_err
nni_http_server_start(nni_http_server *s)
{
	int rv = NNG_OK;

	nni_mtx_lock(&s->mtx);
	if (s->starts == 0) {
		rv = http_server_start(s);
	}
	if (rv == NNG_OK) {
		s->starts++;
	}
	nni_mtx_unlock(&s->mtx);
	return (rv);
}

static void
http_server_close(nni_http_server *s)
{
	if (s->closed) {
		return;
	}
	s->closed = true;

	nni_aio_close(&s->accaio);

	// Close the TCP endpoint that is listening.
	if (s->listener) {
		nng_stream_listener_close(s->listener);
	}
}

static void
http_server_stop(nni_http_server *s)
{
	http_sconn *sc;

	http_server_close(s);

	// Stopping the server is a hard stop -- it aborts any work
	// being done by clients.  (No graceful shutdown).
	NNI_LIST_FOREACH (&s->conns, sc) {
		http_sconn_close(sc);
	}
}

void
nni_http_server_stop(nni_http_server *s)
{
	nni_mtx_lock(&s->mtx);
	if (s->starts != 0) {
		s->starts--;
	}
	if (s->starts == 0) {
		http_server_stop(s);
	}
	nni_mtx_unlock(&s->mtx);
	nni_aio_stop(&s->accaio);
	nng_stream_listener_stop(s->listener);
}

void
nni_http_server_close(nni_http_server *s)
{
	nni_mtx_lock(&s->mtx);
	if (s->starts != 0) {
		s->starts--;
	}
	if (s->starts == 0) {
		http_server_close(s);
	}
	nni_mtx_unlock(&s->mtx);
}

static nng_err
http_server_set_err(nni_http_server *s, nng_http_status code, char *body)
{
	http_error *epage;

	nni_mtx_lock(&s->errors_mtx);
	NNI_LIST_FOREACH (&s->errors, epage) {
		if (epage->code == code) {
			break;
		}
	}
	if (epage == NULL) {
		if ((epage = NNI_ALLOC_STRUCT(epage)) == NULL) {
			nni_mtx_unlock(&s->mtx);
			return (NNG_ENOMEM);
		}
		epage->code = code;
		nni_list_append(&s->errors, epage);
	}
	nni_strfree(epage->body);
	epage->body = body;
	nni_mtx_unlock(&s->errors_mtx);
	return (NNG_OK);
}

nng_err
nni_http_server_set_error_page(
    nni_http_server *s, nng_http_status code, const char *html)
{
	char   *body;
	nng_err rv;

	// We copy the content, without the trailing NUL.
	if ((body = nni_strdup(html)) == NULL) {
		return (NNG_ENOMEM);
	}
	if ((rv = http_server_set_err(s, code, body)) != 0) {
		nni_strfree(body);
	}
	return (rv);
}

nng_err
nni_http_server_error(nni_http_server *s, nng_http *conn)
{
	http_error     *epage;
	char           *body = NULL;
	nng_http_status code = nni_http_get_status(conn);
	nng_err         rv;

	nni_mtx_lock(&s->errors_mtx);
	NNI_LIST_FOREACH (&s->errors, epage) {
		if (epage->code == code) {
			body = epage->body;
			break;
		}
	}
	rv = nni_http_set_error(conn, code, NULL, body);
	nni_mtx_unlock(&s->errors_mtx);
	return (rv);
}

nng_err
nni_http_server_add_handler(nni_http_server *s, nni_http_handler *h)
{
	nni_http_handler *h2;

	// Must have a legal method (and not one that is HEAD), path,
	// and handler.  (The reason HEAD is verboten is that we supply
	// it automatically as part of GET support.)
	if (((h->uri[0] != 0) && (h->uri[0] != '/')) || (h->cb == NULL)) {
		return (NNG_EINVAL);
	}

	nni_mtx_lock(&s->mtx);
	// General rule for finding a conflict is that if either uri
	// string is an exact duplicate of the other, then we have a
	// collision.  (But only if the methods match, and the host
	// matches.)  Note that a wild card host matches both.
	NNI_LIST_FOREACH (&s->handlers, h2) {

		if (nni_strcasecmp(h2->host, h->host) != 0) {
			// Hosts don't match, so we are safe.
			continue;
		}
		if (strcmp(h2->method, h->method) != 0) {
			// Different methods, so again we are fine.
			continue;
		}

		if (strcmp(h->uri, h2->uri) != 0) {
			continue; // not a duplicate
		}

		nni_mtx_unlock(&s->mtx);
		return (NNG_EADDRINUSE);
	}

	// Maintain list of handlers in longest uri first order
	NNI_LIST_FOREACH (&s->handlers, h2) {
		if (strcmp(h->uri, h2->uri) > 0) {
			nni_list_insert_before(&s->handlers, h, h2);
			break;
		}
	}
	if (h2 == NULL) {
		nni_list_append(&s->handlers, h);
	}

	// Note that we have borrowed the reference count on the handler.
	// Thus we own it, and if the server is destroyed while we have it,
	// then we must finalize it it too.  We do mark it busy so
	// that other settings cannot change.
	nni_atomic_set_bool(&h->busy, true);

	nni_mtx_unlock(&s->mtx);
	return (NNG_OK);
}

nng_err
nni_http_server_del_handler(nni_http_server *s, nni_http_handler *h)
{
	nng_err           rv = NNG_ENOENT;
	nni_http_handler *srch;
	nni_mtx_lock(&s->mtx);
	NNI_LIST_FOREACH (&s->handlers, srch) {
		if (srch == h) {
			// NB: We are giving the caller our reference
			// on the handler.
			nni_list_remove(&s->handlers, h);
			rv = NNG_OK;
			break;
		}
	}
	nni_mtx_unlock(&s->mtx);

	return (rv);
}

// Very limited MIME type map.  Used only if the handler does not
// supply it's own.
static struct content_map {
	const char *ext;
	const char *typ;
} content_map[] = {
	// clang-format off
	{ ".ai", "application/postscript" },
	{ ".aif", "audio/aiff" },
	{ ".aiff", "audio/aiff" },
	{ ".avi", "video/avi" },
	{ ".au", "audio/basic" },
	{ ".bin", "application/octet-stream" },
	{ ".bmp", "image/bmp" },
	{ ".css", "text/css" },
	{ ".eps", "application/postscript" },
	{ ".gif", "image/gif" },
	{ ".htm", "text/html" },
	{ ".html", "text/html" },
	{ ".ico", "image/x-icon" },
	{ ".jpeg", "image/jpeg" },
	{ ".jpg", "image/jpeg" },
	{ ".js", "application/javascript" },
	{ ".md", "text/markdown" },
	{ ".mp2", "video/mpeg" },
	{ ".mp3", "audio/mpeg3" },
	{ ".mpeg", "video/mpeg" },
	{ ".mpg", "video/mpeg" },
	{ ".pdf", "application/pdf" },
	{ ".png", "image/png" },
	{ ".ps", "application/postscript" },
	{ ".rtf", "text/rtf" },
	{ ".text", "text/plain" },
	{ ".tif", "image/tiff" },
	{ ".tiff", "image/tiff" },
	{ ".txt", "text/plain" },
	{ ".wav", "audio/wav"},
	{ "README", "text/plain" },
	{ NULL, NULL },
	// clang-format on
};

const char *
http_lookup_type(const char *path)
{
	size_t l1 = strlen(path);
	for (int i = 0; content_map[i].ext != NULL; i++) {
		size_t l2 = strlen(content_map[i].ext);
		if (l2 > l1) {
			continue;
		}
		if (nni_strcasecmp(&path[l1 - l2], content_map[i].ext) == 0) {
			return (content_map[i].typ);
		}
	}
	return (NULL);
}

typedef struct http_file {
	char *base;
	char *path;
	char *ctype;
} http_file;

static void
http_handle_file(nng_http *conn, void *arg, nni_aio *aio)
{
	void       *data;
	size_t      size;
	int         rv;
	http_file  *hf = arg;
	const char *ctype;

	if ((ctype = hf->ctype) == NULL) {
		ctype = "application/octet-stream";
	}

	// This is a very simplistic file server, suitable only for small
	// files.  In the future we can use an AIO based file read, where
	// we read files a bit at a time, or even mmap them, and serve
	// them up chunkwise.  Applications could even come up with their own
	// caching version of the http handler.
	if ((rv = nni_file_get(hf->path, &data, &size)) != 0) {
		nng_http_status status;
		switch (rv) {
		case NNG_ENOMEM:
			status = NNG_HTTP_STATUS_INTERNAL_SERVER_ERROR;
			break;
		case NNG_ENOENT:
			status = NNG_HTTP_STATUS_NOT_FOUND;
			break;
		case NNG_EPERM:
			status = NNG_HTTP_STATUS_FORBIDDEN;
			break;
		default:
			status = NNG_HTTP_STATUS_INTERNAL_SERVER_ERROR;
			break;
		}
		if ((rv = nni_http_set_error(conn, status, NULL, NULL)) != 0) {
			nni_aio_finish_error(aio, rv);
			return;
		}
		nni_aio_finish(aio, NNG_OK, 0);
		return;
	}
	if (((rv = nni_http_set_header(conn, "Content-Type", ctype)) != 0) ||
	    ((rv = nni_http_copy_body(conn, data, size)) != 0)) {
		nni_free(data, size);
		nni_aio_finish_error(aio, rv);
		return;
	}

	nng_http_set_status(conn, NNG_HTTP_STATUS_OK, NULL);

	nni_free(data, size);
	nni_aio_finish(aio, NNG_OK, 0);
}

static void
http_file_free(void *arg)
{
	http_file *hf;
	if ((hf = arg) != NULL) {
		nni_strfree(hf->path);
		nni_strfree(hf->ctype);
		nni_strfree(hf->base);
		NNI_FREE_STRUCT(hf);
	}
}

nng_err
nni_http_handler_init_file_ctype(nni_http_handler **hpp, const char *uri,
    const char *path, const char *ctype)
{
	nni_http_handler *h;
	http_file        *hf;
	nng_err           rv;

	if ((hf = NNI_ALLOC_STRUCT(hf)) == NULL) {
		return (NNG_ENOMEM);
	}

	// Later we might want to do this in the server side, if we support
	// custom media type lists on a per-server basis.  For now doing this
	// here ensures that we don't have to lookup the type every time.
	if (ctype == NULL) {
		if ((ctype = http_lookup_type(path)) == NULL) {
			ctype = "application/octet-stream";
		}
	}
	if (((hf->path = nni_strdup(path)) == NULL) ||
	    ((hf->ctype = nni_strdup(ctype)) == NULL)) {
		http_file_free(hf);
		return (NNG_ENOMEM);
	}

	if ((rv = nni_http_handler_init(&h, uri, http_handle_file)) != 0) {
		http_file_free(hf);
		return (rv);
	}

	nni_http_handler_set_data(h, hf, http_file_free);

	// We don't permit a body for getting a file.
	nni_http_handler_collect_body(h, true, 0);

	*hpp = h;
	return (NNG_OK);
}

nng_err
nni_http_handler_init_file(
    nni_http_handler **hpp, const char *uri, const char *path)
{
	return (nni_http_handler_init_file_ctype(hpp, uri, path, NULL));
}

static void
http_handle_dir(nng_http *conn, void *arg, nng_aio *aio)
{
	void       *data;
	size_t      size;
	nng_err     rv;
	http_file  *hf   = arg;
	const char *path = hf->path;
	const char *base = hf->base;
	const char *uri  = nni_http_get_uri(conn);
	const char *ctype;
	char       *dst;
	size_t      len;
	size_t      pnsz;
	char       *pn;

	len = strlen(base);
	if (base[1] != '\0' && // Allows "/" as base
	    ((strncmp(uri, base, len) != 0) ||
	        ((uri[len] != 0) && (uri[len] != '/')))) {
		// This should never happen!
		nni_aio_finish_error(aio, NNG_EINVAL);
		return;
	}

	// simple worst case is every character in path is a separator
	// It's never actually that bad, because we we have /<something>/.
	pnsz = (strlen(path) + strlen(uri) + 2) * strlen(NNG_PLATFORM_DIR_SEP);
	pnsz += strlen("index.html") + 1; // +1 for term nul

	if ((pn = nni_alloc(pnsz)) == NULL) {
		nni_aio_finish_error(aio, NNG_ENOMEM);
		return;
	}

	// make sure we have a "/" present.
	strcpy(pn, path);
	dst = pn + strlen(pn);

	if ((dst == pn) || (dst[-1] != '/')) {
		*dst++ = '/';
	}

	for (uri = uri + len; *uri != '\0'; uri++) {
		if (*uri == '?') {
			// Skip URI parameters
			break;
		} else if (*uri == '/') {
			strcpy(dst, NNG_PLATFORM_DIR_SEP);
			dst += sizeof(NNG_PLATFORM_DIR_SEP) - 1;
		} else {
			*dst++ = *uri;
		}
	}

	*dst = '\0';

	// This is a very simplistic file server, suitable only for small
	// files.  In the future we can use an AIO based file read, where
	// we read files a bit at a time, or even mmap them, and serve
	// them up chunkwise.  Applications could even come up with their
	// own caching version of the http handler.

	rv = 0;
	if (nni_file_is_dir(pn)) {
		snprintf(dst, pnsz - strlen(pn), "%s%s", NNG_PLATFORM_DIR_SEP,
		    "index.html");
		if (!nni_file_is_file(pn)) {
			pn[strlen(pn) - 1] = '\0'; // index.html -> index.htm
			if (!nni_file_is_file(pn)) {
				rv = NNG_ENOENT;
			}
		}
	}

	if (rv == NNG_OK) {
		rv = nni_file_get(pn, &data, &size);
	} else {
		data = NULL;
		size = 0;
	}
	ctype = http_lookup_type(pn);
	if (ctype == NULL) {
		ctype = "application/octet-stream";
	}

	nni_free(pn, pnsz);
	if (rv != NNG_OK) {
		nng_http_status status;

		switch (rv) {
		case NNG_ENOMEM:
			status = NNG_HTTP_STATUS_INTERNAL_SERVER_ERROR;
			break;
		case NNG_ENOENT:
			status = NNG_HTTP_STATUS_NOT_FOUND;
			break;
		case NNG_EPERM:
			status = NNG_HTTP_STATUS_FORBIDDEN;
			break;
		default:
			status = NNG_HTTP_STATUS_INTERNAL_SERVER_ERROR;
			break;
		}
		if ((rv = nni_http_set_error(conn, status, NULL, NULL)) != 0) {
			nni_aio_finish_error(aio, rv);
			return;
		}
		nni_aio_finish(aio, 0, 0);
		return;
	}

	if (((rv = nng_http_set_header(conn, "Content-Type", ctype)) != 0) ||
	    ((rv = nng_http_copy_body(conn, data, size)) != 0)) {
		nni_free(data, size);
		nni_aio_finish_error(aio, rv);
		return;
	}

	nng_http_set_status(conn, NNG_HTTP_STATUS_OK, NULL);

	nni_free(data, size);
	nni_aio_finish(aio, NNG_OK, 0);
}

nng_err
nni_http_handler_init_directory(
    nni_http_handler **hpp, const char *uri, const char *path)
{
	http_file        *hf;
	nni_http_handler *h;
	nng_err           rv;

	if ((hf = NNI_ALLOC_STRUCT(hf)) == NULL) {
		return (NNG_ENOMEM);
	}
	if (((hf->path = nng_strdup(path)) == NULL) ||
	    ((hf->base = nng_strdup(uri)) == NULL)) {
		http_file_free(hf);
		return (NNG_ENOMEM);
	}

	if ((rv = nni_http_handler_init(&h, uri, http_handle_dir)) != 0) {
		http_file_free(hf);
		return (rv);
	}
	// We don't permit a body for getting a file.
	nng_http_handler_set_tree(h);
	nng_http_handler_collect_body(h, true, 0);
	nng_http_handler_set_data(h, hf, http_file_free);

	*hpp = h;
	return (NNG_OK);
}

typedef struct http_redirect {
	nng_http_status code;
	char           *where;
	char           *from;
} http_redirect;

static void
http_handle_redirect(nng_http *conn, void *data, nng_aio *aio)
{
	char          *loc = NULL;
	http_redirect *hr  = data;
	int            rv;
	const char    *base;
	const char    *uri;

	base = hr->from; // base uri
	uri  = nni_http_get_uri(conn);

	// If we are doing a full tree, then include the entire suffix.
	if (strncmp(uri, base, strlen(base)) == 0) {
		rv = nni_asprintf(&loc, "%s%s", hr->where, uri + strlen(base));
		if (rv != NNG_OK) {
			nni_aio_finish_error(aio, rv);
			return;
		}
	} else {
		loc = hr->where;
	}

	// Build a response.  We always close the connection for redirects,
	// because it is probably going to another server.  This also
	// keeps us from having to consume the entity body, we can just
	// discard it.
	if (((rv = nni_http_set_redirect(conn, hr->code, NULL, loc)) != 0) ||
	    ((rv = nni_http_set_header(conn, "Connection", "close")) != 0)) {
		if (loc != hr->where) {
			nni_strfree(loc);
		}
		nni_aio_finish_error(aio, rv);
		return;
	}

	nng_http_set_status(conn, hr->code, NULL);

	if (loc != hr->where) {
		nni_strfree(loc);
	}
	nni_aio_finish(aio, NNG_OK, 0);
}

static void
http_redirect_free(void *arg)
{
	http_redirect *hr;

	if ((hr = arg) != NULL) {
		nni_strfree(hr->where);
		nni_strfree(hr->from);
		NNI_FREE_STRUCT(hr);
	}
}

nng_err
nni_http_handler_init_redirect(nni_http_handler **hpp, const char *uri,
    nng_http_status status, const char *where)
{
	nni_http_handler *h;
	nng_err           rv;
	http_redirect    *hr;

	if ((hr = NNI_ALLOC_STRUCT(hr)) == NULL) {
		return (NNG_ENOMEM);
	}
	if (((hr->where = nni_strdup(where)) == NULL) ||
	    ((hr->from = nni_strdup(uri)) == NULL)) {
		http_redirect_free(hr);
		return (NNG_ENOMEM);
	}
	if (status == 0) {
		status = NNG_HTTP_STATUS_STATUS_MOVED_PERMANENTLY;
	}
	hr->code = status;

	if ((rv = nni_http_handler_init(&h, uri, http_handle_redirect)) != 0) {
		http_redirect_free(hr);
		return (rv);
	}

	nni_http_handler_set_method(h, NULL);

	nni_http_handler_set_data(h, hr, http_redirect_free);

	// We don't need to collect the body at all, because the handler
	// just discards the content and closes the connection.
	nni_http_handler_collect_body(h, false, 0);

	*hpp = h;
	return (NNG_OK);
}

typedef struct http_static {
	void  *data;
	size_t size;
	char  *ctype;
} http_static;

static void
http_handle_static(nng_http *conn, void *data, nni_aio *aio)
{
	http_static *hs = data;
	const char  *ctype;

	if ((ctype = hs->ctype) == NULL) {
		ctype = "application/octet-stream";
	}

	// this cannot fail (no dynamic allocation)
	(void) nni_http_set_header(conn, "Content-Type", ctype);
	nni_http_set_body(conn, hs->data, hs->size);

	nng_http_set_status(conn, NNG_HTTP_STATUS_OK, NULL);

	nni_aio_finish(aio, 0, 0);
}

static void
http_static_free(void *arg)
{
	http_static *hs;

	if ((hs = arg) != NULL) {
		nni_free(hs->data, hs->size);
		nni_strfree(hs->ctype);
		NNI_FREE_STRUCT(hs);
	}
}

nng_err
nni_http_handler_init_static(nni_http_handler **hpp, const char *uri,
    const void *data, size_t size, const char *ctype)
{
	nni_http_handler *h;
	nng_err           rv;
	http_static      *hs;

	if ((hs = NNI_ALLOC_STRUCT(hs)) == NULL) {
		return (NNG_ENOMEM);
	}
	if (ctype == NULL) {
		ctype = "application/octet-stream";
	}
	if (((hs->ctype = nni_strdup(ctype)) == NULL) ||
	    ((size > 0) && ((hs->data = nni_alloc(size)) == NULL))) {
		http_static_free(hs);
		return (NNG_ENOMEM);
	}
	hs->size = size;
	memcpy(hs->data, data, size);

	if ((rv = nni_http_handler_init(&h, uri, http_handle_static)) != 0) {
		http_static_free(hs);
		return (rv);
	}

	nni_http_handler_set_data(h, hs, http_static_free);

	// We don't permit a body for getting static data.
	nni_http_handler_collect_body(h, true, 0);

	*hpp = h;
	return (NNG_OK);
}

nng_err
nni_http_server_set_tls(nni_http_server *s, nng_tls_config *tls)
{
	return (nng_stream_listener_set_tls(s->listener, tls));
}

nng_err
nni_http_server_get_tls(nni_http_server *s, nng_tls_config **tlsp)
{
	return (nng_stream_listener_get_tls(s->listener, tlsp));
}

int
nni_http_server_set(nni_http_server *s, const char *name, const void *buf,
    size_t sz, nni_type t)
{
	// We have no local options, but we just pass them straight through.
	return (nni_stream_listener_set(s->listener, name, buf, sz, t));
}

int
nni_http_server_get(
    nni_http_server *s, const char *name, void *buf, size_t *szp, nni_type t)
{
	return (nni_stream_listener_get(s->listener, name, buf, szp, t));
}

void
nni_http_server_fini(nni_http_server *s)
{
	nni_mtx_lock(&http_servers_lk);
	s->refcnt--;
	if (s->refcnt != 0) {
		nni_mtx_unlock(&http_servers_lk);
		return;
	}
	nni_list_remove(&http_servers, s);
	nni_mtx_unlock(&http_servers_lk);

	nni_mtx_lock(&s->mtx);
	http_server_stop(s);
	s->fini = true;
	if (nni_list_empty(&s->conns)) {
		nni_reap(&http_server_reap_list, s);
	}
	nni_mtx_unlock(&s->mtx);
}
