//
// Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <ctype.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "core/nng_impl.h"
#include "supplemental/tls/tls.h"
#include "supplemental/tls/tls_api.h"

#include "http_api.h"

static int  http_server_sys_init(void);
static void http_server_sys_fini(void);

static nni_initializer http_server_initializer = {
	.i_init = http_server_sys_init,
	.i_fini = http_server_sys_fini,
	.i_once = 0,
};

struct nng_http_handler {
	nni_list_node node;
	char *        uri;
	char *        method;
	char *        host;
	bool          tree;
	int           refcnt;
	void *        data;
	nni_cb        dtor;
	void (*cb)(nni_aio *);
};

typedef struct http_sconn {
	nni_list_node    node;
	nni_http_conn *  conn;
	nni_http_server *server;
	nni_http_req *   req;
	nni_http_res *   res;
	bool             close;
	bool             closed;
	bool             finished;
	nni_aio *        cbaio;
	nni_aio *        rxaio;
	nni_aio *        txaio;
	nni_aio *        txdataio;
	nni_reap_item    reap;
} http_sconn;

typedef struct http_error {
	nni_list_node node;
	uint16_t      code;
	void *        body;
	size_t        len;
} http_error;

struct nng_http_server {
	nng_sockaddr      addr;
	nni_list_node     node;
	int               refcnt;
	int               starts;
	nni_list          handlers;
	nni_list          conns;
	nni_mtx           mtx;
	nni_cv            cv;
	bool              closed;
	nng_tls_config *  tls;
	nni_aio *         accaio;
	nni_tcp_listener *listener;
	char *            port;
	char *            hostname;
	nni_list          errors;
	nni_mtx           errors_mtx;
};

int
nni_http_handler_init(
    nni_http_handler **hp, const char *uri, void (*cb)(nni_aio *))
{
	nni_http_handler *h;

	if ((h = NNI_ALLOC_STRUCT(h)) == NULL) {
		return (NNG_ENOMEM);
	}
	// Default for HTTP is /.
	if ((uri == NULL) || (strlen(uri) == 0)) {
		uri = "/";
	}
	if (((h->uri = nni_strdup(uri)) == NULL) ||
	    ((h->method = nni_strdup("GET")) == NULL)) {
		nni_http_handler_fini(h);
		return (NNG_ENOMEM);
	}
	NNI_LIST_NODE_INIT(&h->node);
	h->cb     = cb;
	h->data   = NULL;
	h->dtor   = NULL;
	h->host   = NULL;
	h->tree   = false;
	h->refcnt = 0;
	*hp       = h;
	return (0);
}

void
nni_http_handler_fini(nni_http_handler *h)
{
	if (h->refcnt != 0) {
		return;
	}
	if (h->dtor != NULL) {
		h->dtor(h->data);
	}
	nni_strfree(h->host);
	nni_strfree(h->uri);
	nni_strfree(h->method);
	NNI_FREE_STRUCT(h);
}

int
nni_http_handler_set_data(nni_http_handler *h, void *data, nni_cb dtor)
{
	if (h->refcnt != 0) {
		return (NNG_EBUSY);
	}
	h->data = data;
	h->dtor = dtor;
	return (0);
}

void *
nni_http_handler_get_data(nni_http_handler *h)
{
	return (h->data);
}

const char *
nni_http_handler_get_uri(nni_http_handler *h)
{
	return (h->uri);
}

int
nni_http_handler_set_tree(nni_http_handler *h)
{
	if (h->refcnt != 0) {
		return (NNG_EBUSY);
	}
	h->tree = true;
	return (0);
}

int
nni_http_handler_set_host(nni_http_handler *h, const char *host)
{
	char *duphost;
	if (h->refcnt != 0) {
		return (NNG_EBUSY);
	}
	if (host == NULL) {
		nni_strfree(h->host);
		h->host = NULL;
		return (0);
	}
	if ((duphost = nni_strdup(host)) == NULL) {
		return (NNG_ENOMEM);
	}
	nni_strfree(h->host);
	h->host = duphost;
	return (0);
}

int
nni_http_handler_set_method(nni_http_handler *h, const char *method)
{
	char *dupmeth;
	if (h->refcnt != 0) {
		return (NNG_EBUSY);
	}
	if (method == NULL) {
		nni_strfree(h->method);
		h->method = NULL;
		return (0);
	}
	if ((dupmeth = nni_strdup(method)) == NULL) {
		return (NNG_ENOMEM);
	}
	nni_strfree(h->method);
	h->method = dupmeth;
	return (0);
}

static nni_list http_servers;
static nni_mtx  http_servers_lk;

static void
http_sconn_reap(void *arg)
{
	http_sconn *     sc = arg;
	nni_http_server *s  = sc->server;
	NNI_ASSERT(!sc->finished);
	sc->finished = true;
	nni_aio_stop(sc->rxaio);
	nni_aio_stop(sc->txaio);
	nni_aio_stop(sc->txdataio);
	nni_aio_stop(sc->cbaio);

	if (sc->conn != NULL) {
		nni_http_conn_fini(sc->conn);
	}
	if (sc->req != NULL) {
		nni_http_req_free(sc->req);
	}
	if (sc->res != NULL) {
		nni_http_res_free(sc->res);
	}
	nni_aio_fini(sc->rxaio);
	nni_aio_fini(sc->txaio);
	nni_aio_fini(sc->txdataio);
	nni_aio_fini(sc->cbaio);

	// Now it is safe to release our reference on the server.
	nni_mtx_lock(&s->mtx);
	if (nni_list_node_active(&sc->node)) {
		nni_list_remove(&s->conns, sc);
		if (nni_list_empty(&s->conns)) {
			nni_cv_wake(&s->cv);
		}
	}
	nni_mtx_unlock(&s->mtx);

	NNI_FREE_STRUCT(sc);
}

static void
http_sconn_close_locked(http_sconn *sc)
{
	nni_http_conn *conn;

	if (sc->closed) {
		return;
	}
	NNI_ASSERT(!sc->finished);

	sc->closed = true;
	nni_aio_close(sc->rxaio);
	nni_aio_close(sc->txaio);
	nni_aio_close(sc->txdataio);
	nni_aio_close(sc->cbaio);

	if ((conn = sc->conn) != NULL) {
		nni_http_conn_close(conn);
	}
	nni_reap(&sc->reap, http_sconn_reap, sc);
}

static void
http_sconn_close(http_sconn *sc)
{
	nni_http_server *s;
	s = sc->server;

	nni_mtx_lock(&s->mtx);
	http_sconn_close_locked(sc);
	nni_mtx_unlock(&s->mtx);
}

static void
http_sconn_txdatdone(void *arg)
{
	http_sconn *sc  = arg;
	nni_aio *   aio = sc->txdataio;

	if (nni_aio_result(aio) != 0) {
		http_sconn_close(sc);
		return;
	}

	if (sc->res != NULL) {
		nni_http_res_free(sc->res);
		sc->res = NULL;
	}

	if (sc->close) {
		http_sconn_close(sc);
		return;
	}

	nni_http_req_reset(sc->req);
	nni_http_read_req(sc->conn, sc->req, sc->rxaio);
}

static void
http_sconn_txdone(void *arg)
{
	http_sconn *sc  = arg;
	nni_aio *   aio = sc->txaio;

	if (nni_aio_result(aio) != 0) {
		http_sconn_close(sc);
		return;
	}

	if (sc->close) {
		http_sconn_close(sc);
		return;
	}

	if (sc->res != NULL) {
		nni_http_res_free(sc->res);
		sc->res = NULL;
	}
	nni_http_req_reset(sc->req);
	nni_http_read_req(sc->conn, sc->req, sc->rxaio);
}

static char
http_hexval(char c)
{
	if ((c >= '0') && (c <= '9')) {
		return (c - '0');
	}
	if ((c >= 'a') && (c <= 'f')) {
		return ((c - 'a') + 10);
	}
	if ((c >= 'A') && (c <= 'F')) {
		return ((c - 'A') + 10);
	}
	return (0);
}

// XXX: REPLACE THIS WITH CODE USING THE URL FRAMEWORK.
static char *
http_uri_canonify(char *path)
{
	char *tmp;
	char *dst;

	// Chomp off query string.
	if ((tmp = strchr(path, '?')) != NULL) {
		*tmp = '\0';
	}
	// If the URI was absolute, make it relative.
	if ((nni_strncasecmp(path, "http://", strlen("http://")) == 0) ||
	    (nni_strncasecmp(path, "https://", strlen("https://")) == 0)) {
		// Skip past the ://
		path = strchr(path, ':');
		path += 3;

		// scan for the end of the host, distinguished by a /
		// path delimiter.  There might not be one, in which
		// case the whole thing is the host and we assume the
		// path is just /.
		if ((path = strchr(path, '/')) == NULL) {
			return ("/");
		}
	}

	// Now we have to unescape things.  Unescaping is a shrinking
	// operation (strictly), so this is safe.  This is just URL
	// decode. Note that paths with an embedded NUL are going to be
	// treated as though truncated.  Don't be that guy that sends
	// %00 in a URL.
	//
	// XXX: Normalizer needs to leave % encoded stuff in there if
	// the characters to which they refer are reserved.  See RFC 3986
	// section 6.2.2.
	tmp = path;
	dst = path;
	while (*tmp != '\0') {
		char c;
		if ((c = *tmp) != '%') {
			*dst++ = c;
			tmp++;
			continue;
		}
		if (isxdigit(tmp[1]) && isxdigit(tmp[2])) {
			c = http_hexval(tmp[1]);
			c *= 16;
			c += http_hexval(tmp[2]);
			*dst++ = c;
			tmp += 3;
		}
		// garbage in, garbage out
		*dst++ = c;
		tmp++;
	}
	*dst = '\0';

	return ((strlen(path) != 0) ? path : "/");
}

static void
http_sconn_error(http_sconn *sc, uint16_t err)
{
	nni_http_res *res;

	if (nni_http_res_alloc(&res) != 0) {
		http_sconn_close(sc);
		return;
	}
	nni_http_res_set_status(res, err);
	if (nni_http_server_res_error(sc->server, res) != 0) {
		nni_http_res_free(res);
		http_sconn_close(sc);
		return;
	}

	if (sc->close) {
		if (nni_http_res_set_header(res, "Connection", "close") != 0) {
			nni_http_res_free(res);
			http_sconn_close(sc);
		}
	}
	sc->res = res;
	nni_http_write_res(sc->conn, res, sc->txaio);
}

int
nni_http_hijack(nni_http_conn *conn)
{
	http_sconn *sc;

	sc = nni_http_conn_get_ctx(conn);
	if (sc != NULL) {
		nni_http_server *s = sc->server;
		nni_http_conn_set_ctx(conn, NULL);

		nni_mtx_lock(&s->mtx);
		sc->conn = NULL;
		sc->req  = NULL;
		nni_mtx_unlock(&s->mtx);
	}
	return (0);
}

static void
http_sconn_rxdone(void *arg)
{
	http_sconn *      sc  = arg;
	nni_http_server * s   = sc->server;
	nni_aio *         aio = sc->rxaio;
	int               rv;
	nni_http_handler *h    = NULL;
	nni_http_handler *head = NULL;
	const char *      val;
	nni_http_req *    req = sc->req;
	char *            uri;
	size_t            urisz;
	char *            path;
	bool              badmeth  = false;
	bool              needhost = false;
	const char *      host;

	if ((rv = nni_aio_result(aio)) != 0) {
		http_sconn_close(sc);
		return;
	}

	// Validate the request -- it has to at least look like HTTP
	// 1.x.  We flatly refuse to deal with HTTP 0.9, and we can't
	// cope with HTTP/2.
	if ((val = nni_http_req_get_version(req)) == NULL) {
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

	// If the connection was 1.0, or a connection: close was
	// requested, then mark this close on our end.
	if ((val = nni_http_req_get_header(req, "Connection")) != NULL) {
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

	val   = nni_http_req_get_uri(req);
	urisz = strlen(val) + 1;
	if ((uri = nni_alloc(urisz)) == NULL) {
		http_sconn_close(sc); // out of memory
		return;
	}
	strncpy(uri, val, urisz);
	path = http_uri_canonify(uri);

	host = nni_http_req_get_header(req, "Host");
	if ((host == NULL) && (needhost)) {
		// Per RFC 2616 14.23 we have to send 400 status here.
		http_sconn_error(sc, NNG_HTTP_STATUS_BAD_REQUEST);
		nni_free(uri, urisz);
		return;
	}

	nni_mtx_lock(&s->mtx);
	NNI_LIST_FOREACH (&s->handlers, h) {
		size_t len;
		if (h->host != NULL) {
			if (host == NULL) {
				// HTTP/1.0 cannot access virtual hosts.
				continue;
			}

			len = strlen(h->host);
			if ((nni_strncasecmp(host, h->host, len) != 0)) {
				continue;
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
				continue;
			}
		}

		len = strlen(h->uri);
		if (strncmp(path, h->uri, len) != 0) {
			continue;
		}
		switch (path[len]) {
		case '\0':
			break;
		case '/':
			if ((path[len + 1] != '\0') && (!h->tree)) {
				// Trailing component and not a directory.
				continue;
			}
			break;
		default:
			continue; // Some other substring, not matched.
		}

		if ((h->method == NULL) || (h->method[0] == '\0')) {
			// Handler wants to process *all* methods.
			break;
		}
		// So, what about the method?
		val = nni_http_req_get_method(req);
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
	nni_free(uri, urisz);
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

	nni_aio_set_input(sc->cbaio, 0, sc->req);
	nni_aio_set_input(sc->cbaio, 1, h);
	nni_aio_set_input(sc->cbaio, 2, sc->conn);

	// Technically, probably callback should initialize this with
	// start, but we do it instead.
	// This operation cannot at present canceled or timed out.
	if (nni_aio_begin(sc->cbaio) != 0) {
		nni_mtx_unlock(&s->mtx);
		return;
	}
	nni_aio_set_data(sc->cbaio, 1, h);
	h->refcnt++;
	nni_mtx_unlock(&s->mtx);
	h->cb(sc->cbaio);
}

static void
http_sconn_cbdone(void *arg)
{
	http_sconn *      sc  = arg;
	nni_aio *         aio = sc->cbaio;
	nni_http_res *    res;
	nni_http_handler *h;
	nni_http_server * s = sc->server;

	if (nni_aio_result(aio) != 0) {
		// Hard close, no further feedback.
		http_sconn_close(sc);
		return;
	}

	h   = nni_aio_get_data(aio, 1);
	res = nni_aio_get_output(aio, 0);

	nni_mtx_lock(&s->mtx);
	h->refcnt--;
	if (h->refcnt == 0) {
		nni_http_handler_fini(h);
	}
	nni_mtx_unlock(&s->mtx);

	// If its an upgrader, and they didn't give us back a response,
	// it means that they took over, and we should just discard
	// this session, without closing the underlying channel.
	if (sc->conn == NULL) {
		// If this happens, then the session was hijacked.
		// We close the context, but the http channel stays up.
		http_sconn_close(sc);
		return;
	}
	if (res != NULL) {
		const char *val;
		val = nni_http_res_get_header(res, "Connection");
		if ((val != NULL) && (strstr(val, "close") != NULL)) {
			sc->close = true;
		}
		if (sc->close) {
			nni_http_res_set_header(res, "Connection", "close");
		}
		sc->res = res;
		if (strcmp(nni_http_req_get_method(sc->req), "HEAD") == 0) {
			void * data;
			size_t size;
			// prune off the data, but preserve the content-length
			// header.  By passing NULL here, we leave off the old
			// data, but the non-zero size means we don't clobber
			// the HTTP header.
			nni_http_res_get_data(res, &data, &size);
			nni_http_res_set_data(res, NULL, size);
		} else if (nni_http_res_is_error(res)) {
			(void) nni_http_server_res_error(s, res);
		}
		nni_http_write_res(sc->conn, res, sc->txaio);
	} else if (sc->close) {
		http_sconn_close(sc);
	} else {
		// Presumably client already sent a response.
		// Wait for another request.
		nni_http_req_reset(sc->req);
		nni_http_read_req(sc->conn, sc->req, sc->rxaio);
	}
}

static int
http_sconn_init(http_sconn **scp, nni_http_server *s, nni_tcp_conn *tcp)
{
	http_sconn *sc;
	int         rv;

	if ((sc = NNI_ALLOC_STRUCT(sc)) == NULL) {
		nni_tcp_conn_fini(tcp);
		return (NNG_ENOMEM);
	}

	if (((rv = nni_http_req_alloc(&sc->req, NULL)) != 0) ||
	    ((rv = nni_aio_init(&sc->rxaio, http_sconn_rxdone, sc)) != 0) ||
	    ((rv = nni_aio_init(&sc->txaio, http_sconn_txdone, sc)) != 0) ||
	    ((rv = nni_aio_init(&sc->txdataio, http_sconn_txdatdone, sc)) !=
	        0) ||
	    ((rv = nni_aio_init(&sc->cbaio, http_sconn_cbdone, sc)) != 0)) {
		// Can't even accept the incoming request.  Hard close.
		http_sconn_close(sc);
		return (rv);
	}

	if (s->tls != NULL) {
		rv = nni_http_conn_init_tls(&sc->conn, s->tls, tcp);
	} else {
		rv = nni_http_conn_init_tcp(&sc->conn, tcp);
	}
	if (rv != 0) {
		http_sconn_close(sc);
		return (rv);
	}
	nni_http_conn_set_ctx(sc->conn, sc);
	*scp = sc;
	return (0);
}

static void
http_server_acccb(void *arg)
{
	nni_http_server *s   = arg;
	nni_aio *        aio = s->accaio;
	nni_tcp_conn *   tcp;
	http_sconn *     sc;
	int              rv;

	nni_mtx_lock(&s->mtx);
	if ((rv = nni_aio_result(aio)) != 0) {
		if (!s->closed) {
			// try again?
			nni_tcp_listener_accept(s->listener, s->accaio);
		}
		nni_mtx_unlock(&s->mtx);
		return;
	}
	tcp = nni_aio_get_output(aio, 0);
	if (s->closed) {
		// If we're closing, then reject this one.
		nni_tcp_conn_fini(tcp);
		nni_mtx_unlock(&s->mtx);
		return;
	}
	if (http_sconn_init(&sc, s, tcp) != 0) {
		// The TCP structure is already cleaned up.
		// Start another accept attempt.
		nni_tcp_listener_accept(s->listener, s->accaio);
		nni_mtx_unlock(&s->mtx);
		return;
	}
	sc->server = s;
	nni_list_append(&s->conns, sc);

	nni_http_read_req(sc->conn, sc->req, sc->rxaio);
	nni_tcp_listener_accept(s->listener, s->accaio);
	nni_mtx_unlock(&s->mtx);
}

static void
http_server_fini(nni_http_server *s)
{
	nni_http_handler *h;
	http_error *      epage;

	nni_aio_stop(s->accaio);

	nni_mtx_lock(&s->mtx);
	while (!nni_list_empty(&s->conns)) {
		nni_cv_wait(&s->cv);
	}
	if (s->listener != NULL) {
		nni_tcp_listener_fini(s->listener);
	}
	while ((h = nni_list_first(&s->handlers)) != NULL) {
		nni_list_remove(&s->handlers, h);
		h->refcnt--;
		nni_http_handler_fini(h);
	}
	nni_mtx_unlock(&s->mtx);
#ifdef NNG_SUPP_TLS
	if (s->tls != NULL) {
		nni_tls_config_fini(s->tls);
	}
#endif
	nni_mtx_lock(&s->errors_mtx);
	while ((epage = nni_list_first(&s->errors)) != NULL) {
		nni_list_remove(&s->errors, epage);
		nni_free(epage->body, epage->len);
		NNI_FREE_STRUCT(epage);
	}
	nni_mtx_unlock(&s->errors_mtx);
	nni_mtx_fini(&s->errors_mtx);

	nni_aio_fini(s->accaio);
	nni_cv_fini(&s->cv);
	nni_mtx_fini(&s->mtx);
	nni_strfree(s->hostname);
	nni_strfree(s->port);
	NNI_FREE_STRUCT(s);
}

void
nni_http_server_fini(nni_http_server *s)
{
	nni_mtx_lock(&http_servers_lk);
	s->refcnt--;
	if (s->refcnt == 0) {
		nni_list_remove(&http_servers, s);
		http_server_fini(s);
	}
	nni_mtx_unlock(&http_servers_lk);
}

static int
http_server_init(nni_http_server **serverp, const nni_url *url)
{
	nni_http_server *s;
	int              rv;
	nni_aio *        aio;

	if ((strcmp(url->u_scheme, "http") != 0) &&
#ifdef NNG_SUPP_TLS
	    (strcmp(url->u_scheme, "https") != 0) &&
	    (strcmp(url->u_scheme, "wss") != 0) &&
#endif
	    (strcmp(url->u_scheme, "ws") != 0)) {
		return (NNG_EADDRINVAL);
	}
	if ((s = NNI_ALLOC_STRUCT(s)) == NULL) {
		return (NNG_ENOMEM);
	}
	nni_mtx_init(&s->mtx);
	nni_cv_init(&s->cv, &s->mtx);
	nni_mtx_init(&s->errors_mtx);
	NNI_LIST_INIT(&s->handlers, nni_http_handler, node);
	NNI_LIST_INIT(&s->conns, http_sconn, node);

	nni_mtx_init(&s->errors_mtx);
	NNI_LIST_INIT(&s->errors, http_error, node);

	if ((rv = nni_aio_init(&s->accaio, http_server_acccb, s)) != 0) {
		http_server_fini(s);
		return (rv);
	}

	if ((strlen(url->u_port)) &&
	    ((s->port = nni_strdup(url->u_port)) == NULL)) {
		http_server_fini(s);
		return (NNG_ENOMEM);
	}
	if ((strlen(url->u_hostname)) &&
	    ((s->hostname = nni_strdup(url->u_hostname)) == NULL)) {
		http_server_fini(s);
		return (NNG_ENOMEM);
	}

#ifdef NNG_SUPP_TLS
	if ((strcmp(url->u_scheme, "https") == 0) ||
	    (strcmp(url->u_scheme, "wss") == 0)) {
		rv = nni_tls_config_init(&s->tls, NNG_TLS_MODE_SERVER);
		if (rv != 0) {
			http_server_fini(s);
			return (rv);
		}
	}
#endif

	// Do the DNS lookup *now*.  This means that this is
	// synchronous, but it should be fast, since it should either
	// resolve as a number, or resolve locally, without having to
	// hit up DNS.
	if ((rv = nni_aio_init(&aio, NULL, NULL)) != 0) {
		http_server_fini(s);
		return (rv);
	}
	nni_aio_set_input(aio, 0, &s->addr);
	nni_tcp_resolv(s->hostname, s->port, NNG_AF_UNSPEC, true, aio);
	nni_aio_wait(aio);
	rv = nni_aio_result(aio);
	nni_aio_fini(aio);
	if (rv != 0) {
		http_server_fini(s);
		return (rv);
	}
	s->refcnt = 1;
	*serverp  = s;
	return (0);
}

int
nni_http_server_init(nni_http_server **serverp, const nni_url *url)
{
	int              rv;
	nni_http_server *s;

	nni_initialize(&http_server_initializer);

	nni_mtx_lock(&http_servers_lk);
	NNI_LIST_FOREACH (&http_servers, s) {
		if ((strcmp(url->u_port, s->port) == 0) &&
		    (strcmp(url->u_hostname, s->hostname) == 0)) {
			*serverp = s;
			s->refcnt++;
			nni_mtx_unlock(&http_servers_lk);
			return (0);
		}
	}

	// We didn't find a server, try to make a new one.
	if ((rv = http_server_init(&s, url)) == 0) {
		nni_list_append(&http_servers, s);
		*serverp = s;
	}

	nni_mtx_unlock(&http_servers_lk);
	return (rv);
}

static int
http_server_start(nni_http_server *s)
{
	int rv;
	if ((rv = nni_tcp_listener_init(&s->listener)) != 0) {
		return (rv);
	}
	if ((rv = nni_tcp_listener_listen(s->listener, &s->addr)) != 0) {
		nni_tcp_listener_fini(s->listener);
		s->listener = NULL;
		return (rv);
	}
	nni_tcp_listener_accept(s->listener, s->accaio);
	return (0);
}

int
nni_http_server_start(nni_http_server *s)
{
	int rv = 0;

	nni_mtx_lock(&s->mtx);
	if (s->starts == 0) {
		rv = http_server_start(s);
	}
	if (rv == 0) {
		s->starts++;
	}
	nni_mtx_unlock(&s->mtx);
	return (rv);
}

static void
http_server_stop(nni_http_server *s)
{
	http_sconn *sc;

	if (s->closed) {
		return;
	}

	s->closed = true;
	// Close the TCP endpoint that is listening.
	if (s->listener) {
		nni_tcp_listener_close(s->listener);
	}

	// Stopping the server is a hard stop -- it aborts any work
	// being done by clients.  (No graceful shutdown).
	NNI_LIST_FOREACH (&s->conns, sc) {
		http_sconn_close_locked(sc);
	}
	nni_cv_wake(&s->cv);
}

void
nni_http_server_stop(nni_http_server *s)
{
	nni_mtx_lock(&s->mtx);
	s->starts--;
	if (s->starts == 0) {
		http_server_stop(s);
	}
	nni_mtx_unlock(&s->mtx);
}

static int
http_server_set_err(nni_http_server *s, uint16_t code, void *body, size_t len)
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
	if (epage->len != 0) {
		nni_free(epage->body, epage->len);
	}
	epage->body = body;
	epage->len  = len;
	nni_mtx_unlock(&s->errors_mtx);
	return (0);
}

int
nni_http_server_set_error_page(
    nni_http_server *s, uint16_t code, const char *html)
{
	char * body;
	int    rv;
	size_t len;

	// We copy the content, without the trailing NUL.
	len = strlen(html);
	if ((body = nni_alloc(len)) == NULL) {
		return (NNG_ENOMEM);
	}
	memcpy(body, html, len);
	if ((rv = http_server_set_err(s, code, body, len)) != 0) {
		nni_free(body, len);
	}
	return (rv);
}

int
nni_http_server_set_error_file(
    nni_http_server *s, uint16_t code, const char *path)
{
	void * body;
	size_t len;
	int    rv;
	if ((rv = nni_file_get(path, &body, &len)) != 0) {
		return (rv);
	}
	if ((rv = http_server_set_err(s, code, body, len)) != 0) {
		nni_free(body, len);
	}
	return (rv);
}

int
nni_http_server_res_error(nni_http_server *s, nni_http_res *res)
{
	http_error *epage;
	char *      body = NULL;
	size_t      len;
	uint16_t    code = nni_http_res_get_status(res);
	int         rv;
	char        html[512];

	nni_mtx_lock(&s->errors_mtx);
	NNI_LIST_FOREACH (&s->errors, epage) {
		if (epage->code == code) {
			body = epage->body;
			len  = epage->len;
			break;
		}
	}
	if (body == NULL) {
		const char *reason = nni_http_reason(code);
		// very simple builtin error page
		(void) snprintf(html, sizeof(html),
		    "<head><title>%d %s</title></head>"
		    "<body><p/><h1 align=\"center\">"
		    "<span style=\"font-size: 36px; border-radius: 5px; "
		    "background-color: black; color: white; padding: 7px; "
		    "font-family: Arial, sans serif;\">%d</span></h1>"
		    "<p align=\"center\">"
		    "<span style=\"font-size: 24px; font-family: Arial, sans "
		    "serif;\">"
		    "%s</span></p></body>",
		    code, reason, code, reason);
		body = html;
		len  = strlen(body);
	}
	// NB: The server lock has to be held here to guard against the
	// error page being tossed or changed.
	if (((rv = nni_http_res_copy_data(res, body, len)) == 0) &&
	    ((rv = nni_http_res_set_header(
	          res, "Content-Type", "text/html; charset=UTF-8")) == 0)) {
		nni_http_res_set_status(res, code);
	}

	nni_mtx_unlock(&s->errors_mtx);
	return (rv);
}

int
nni_http_server_add_handler(nni_http_server *s, nni_http_handler *h)
{
	nni_http_handler *h2;
	size_t            len;

	// Must have a legal method (and not one that is HEAD), path,
	// and handler.  (The reason HEAD is verboten is that we supply
	// it automatically as part of GET support.)
	if (((len = strlen(h->uri)) == 0) || (h->uri[0] != '/') ||
	    (h->cb == NULL)) {
		return (NNG_EINVAL);
	}
	while ((len > 0) && (h->uri[len - 1] == '/')) {
		len--; // ignore trailing '/' (this collapses them)
	}

	nni_mtx_lock(&s->mtx);
	// General rule for finding a conflict is that if either string
	// is a strict substring of the other, then we have a
	// collision.  (But only if the methods match, and the host
	// matches.)  Note that a wild card host matches both.
	NNI_LIST_FOREACH (&s->handlers, h2) {
		size_t len2;

		if ((h2->host != NULL) && (h->host != NULL) &&
		    (nni_strcasecmp(h2->host, h->host) != 0)) {
			// Hosts don't match, so we are safe.
			continue;
		}
		if (((h2->host == NULL) && (h->host != NULL)) ||
		    ((h->host == NULL) && (h2->host != NULL))) {
			continue; // Host specified for just one.
		}
		if (((h->method == NULL) && (h2->method != NULL)) ||
		    ((h2->method == NULL) && (h->method != NULL))) {
			continue; // Method specified for just one.
		}
		if ((h->method != NULL) &&
		    (strcmp(h2->method, h->method) != 0)) {
			// Different methods, so again we are fine.
			continue;
		}

		len2 = strlen(h2->uri);

		while ((len2 > 0) && (h2->uri[len2 - 1] == '/')) {
			len2--; // ignore trailing '/'
		}
		if (strncmp(h->uri, h2->uri, len > len2 ? len2 : len) != 0) {
			continue; // prefixes don't match.
		}

		if (len2 > len) {
			if ((h2->uri[len] == '/') && (h->tree)) {
				nni_mtx_unlock(&s->mtx);
				return (NNG_EADDRINUSE);
			}
		} else if (len > len2) {
			if ((h->uri[len2] == '/') && (h2->tree)) {
				nni_mtx_unlock(&s->mtx);
				return (NNG_EADDRINUSE);
			}
		} else {
			nni_mtx_unlock(&s->mtx);
			return (NNG_EADDRINUSE);
		}
	}
	h->refcnt = 1;
	nni_list_append(&s->handlers, h);
	nni_mtx_unlock(&s->mtx);
	return (0);
}

int
nni_http_server_del_handler(nni_http_server *s, nni_http_handler *h)
{
	int               rv = NNG_ENOENT;
	nni_http_handler *srch;
	nni_mtx_lock(&s->mtx);
	NNI_LIST_FOREACH (&s->handlers, srch) {
		if (srch == h) {
			nni_list_remove(&s->handlers, h);
			h->refcnt--;
			rv = 0;
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
	char *path;
	char *ctype;
} http_file;

static void
http_handle_file(nni_aio *aio)
{
	nni_http_handler *h   = nni_aio_get_input(aio, 1);
	nni_http_res *    res = NULL;
	void *            data;
	size_t            size;
	int               rv;
	http_file *       hf = nni_http_handler_get_data(h);
	const char *      ctype;

	if ((ctype = hf->ctype) == NULL) {
		ctype = "application/octet-stream";
	}

	// This is a very simplistic file server, suitable only for small
	// files.  In the future we can use an AIO based file read, where
	// we read files a bit at a time, or even mmap them, and serve
	// them up chunkwise.  Applications could even come up with their own
	// caching version of the http handler.
	if ((rv = nni_file_get(hf->path, &data, &size)) != 0) {
		uint16_t status;
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
		if ((rv = nni_http_res_alloc_error(&res, status)) != 0) {
			nni_aio_finish_error(aio, rv);
			return;
		}
		nni_aio_set_output(aio, 0, res);
		nni_aio_finish(aio, 0, 0);
		return;
	}
	if (((rv = nni_http_res_alloc(&res)) != 0) ||
	    ((rv = nni_http_res_set_status(res, NNG_HTTP_STATUS_OK)) != 0) ||
	    ((rv = nni_http_res_set_header(res, "Content-Type", ctype)) !=
	        0) ||
	    ((rv = nni_http_res_copy_data(res, data, size)) != 0)) {
		if (res != NULL) {
			nni_http_res_free(res);
		}
		nni_free(data, size);
		nni_aio_finish_error(aio, rv);
		return;
	}

	nni_free(data, size);
	nni_aio_set_output(aio, 0, res);
	nni_aio_finish(aio, 0, 0);
}

static void
http_file_free(void *arg)
{
	http_file *hf;
	if ((hf = arg) != NULL) {
		nni_strfree(hf->path);
		nni_strfree(hf->ctype);
		NNI_FREE_STRUCT(hf);
	}
}

int
nni_http_handler_init_file_ctype(nni_http_handler **hpp, const char *uri,
    const char *path, const char *ctype)
{
	nni_http_handler *h;
	http_file *       hf;
	int               rv;

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

	if ((rv = nni_http_handler_set_data(h, hf, http_file_free)) != 0) {
		http_file_free(hf);
		nni_http_handler_fini(h);
		return (rv);
	}

	*hpp = h;
	return (0);
}

int
nni_http_handler_init_file(
    nni_http_handler **hpp, const char *uri, const char *path)
{
	return (nni_http_handler_init_file_ctype(hpp, uri, path, NULL));
}

static void
http_handle_dir(nni_aio *aio)
{
	nni_http_req *    req = nni_aio_get_input(aio, 0);
	nni_http_handler *h   = nni_aio_get_input(aio, 1);
	nni_http_res *    res = NULL;
	void *            data;
	size_t            size;
	int               rv;
	http_file *       hf   = nni_http_handler_get_data(h);
	const char *      path = hf->path;
	const char *      base = nni_http_handler_get_uri(h); // base uri
	const char *      uri  = nni_http_req_get_uri(req);
	const char *      ctype;
	char *            dst;
	size_t            len;
	size_t            pnsz;
	char *            pn;

	len = strlen(base);
	if ((strncmp(uri, base, len) != 0) ||
	    ((uri[len] != 0) && (uri[len] != '/'))) {
		// This should never happen!
		nni_aio_finish_error(aio, NNG_EINVAL);
		return;
	}

	// simple worst case is every character in path is a seperator
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
		if (*uri == '/') {
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
		sprintf(dst, "%s%s", NNG_PLATFORM_DIR_SEP, "index.html");
		if (!nni_file_is_file(pn)) {
			pn[strlen(pn) - 1] = '\0'; // index.html -> index.htm
		}
		if (!nni_file_is_file(pn)) {
			rv = NNG_ENOENT;
		}
	}

	if (rv == 0) {
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
	if (rv != 0) {
		uint16_t status;

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
		if ((rv = nni_http_res_alloc_error(&res, status)) != 0) {
			nni_aio_finish_error(aio, rv);
			return;
		}
		nni_aio_set_output(aio, 0, res);
		nni_aio_finish(aio, 0, 0);
		return;
	}

	if (((rv = nni_http_res_alloc(&res)) != 0) ||
	    ((rv = nni_http_res_set_status(res, NNG_HTTP_STATUS_OK)) != 0) ||
	    ((rv = nni_http_res_set_header(res, "Content-Type", ctype)) !=
	        0) ||
	    ((rv = nni_http_res_copy_data(res, data, size)) != 0)) {
		if (res != NULL) {
			nni_http_res_free(res);
		}
		nni_free(data, size);
		nni_aio_finish_error(aio, rv);
		return;
	}

	nni_free(data, size);
	nni_aio_set_output(aio, 0, res);
	nni_aio_finish(aio, 0, 0);
}

int
nni_http_handler_init_directory(
    nni_http_handler **hpp, const char *uri, const char *path)
{
	http_file *       hf;
	nni_http_handler *h;
	int               rv;

	if ((hf = NNI_ALLOC_STRUCT(hf)) == NULL) {
		return (NNG_ENOMEM);
	}
	if ((hf->path = nni_strdup(path)) == NULL) {
		NNI_FREE_STRUCT(hf);
		return (NNG_ENOMEM);
	}

	if ((rv = nni_http_handler_init(&h, uri, http_handle_dir)) != 0) {
		http_file_free(hf);
		return (rv);
	}

	if (((rv = nni_http_handler_set_tree(h)) != 0) ||
	    ((rv = nni_http_handler_set_data(h, hf, http_file_free)) != 0)) {
		http_file_free(hf);
		nni_http_handler_fini(h);
		return (rv);
	}

	*hpp = h;
	return (0);
}

typedef struct http_static {
	void * data;
	size_t size;
	char * ctype;
} http_static;

static void
http_handle_static(nni_aio *aio)
{
	http_static *     hs;
	const char *      ctype;
	nni_http_handler *h;
	nni_http_res *    r = NULL;
	int               rv;

	h  = nni_aio_get_input(aio, 1);
	hs = nni_http_handler_get_data(h);

	if ((ctype = hs->ctype) == NULL) {
		ctype = "application/octet-stream";
	}

	if (((rv = nni_http_res_alloc(&r)) != 0) ||
	    ((rv = nni_http_res_set_header(r, "Content-Type", ctype)) != 0) ||
	    ((rv = nni_http_res_set_status(r, NNG_HTTP_STATUS_OK)) != 0) ||
	    ((rv = nni_http_res_set_data(r, hs->data, hs->size)) != 0)) {
		if (r != NULL) {
			nni_http_res_free(r);
		}
		nni_aio_finish_error(aio, rv);
		return;
	}

	nni_aio_set_output(aio, 0, r);
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

int
nni_http_handler_init_static(nni_http_handler **hpp, const char *uri,
    const void *data, size_t size, const char *ctype)
{
	nni_http_handler *h;
	int               rv;
	http_static *     hs;

	if ((hs = NNI_ALLOC_STRUCT(hs)) == NULL) {
		return (NNG_ENOMEM);
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

	if ((rv = nni_http_handler_set_data(h, hs, http_static_free)) != 0) {
		http_static_free(hs);
		nni_http_handler_fini(h);
		return (rv);
	}

	*hpp = h;
	return (0);
}

int
nni_http_server_set_tls(nni_http_server *s, nng_tls_config *tcfg)
{
#ifdef NNG_SUPP_TLS
	nng_tls_config *old;
	nni_mtx_lock(&s->mtx);
	if (s->starts) {
		nni_mtx_unlock(&s->mtx);
		return (NNG_EBUSY);
	}
	old    = s->tls;
	s->tls = tcfg;
	if (tcfg) {
		nni_tls_config_hold(tcfg);
	}
	nni_mtx_unlock(&s->mtx);
	if (old) {
		nni_tls_config_fini(old);
	}
	return (0);
#else
	NNI_ARG_UNUSED(s);
	NNI_ARG_UNUSED(tcfg);
	return (NNG_ENOTSUP);
#endif
}

int
nni_http_server_get_tls(nni_http_server *s, nng_tls_config **tp)
{
#ifdef NNG_SUPP_TLS
	nni_mtx_lock(&s->mtx);
	if (s->tls == NULL) {
		nni_mtx_unlock(&s->mtx);
		return (NNG_EINVAL);
	}
	*tp = s->tls;
	nni_mtx_unlock(&s->mtx);
	return (0);
#else
	NNI_ARG_UNUSED(s);
	NNI_ARG_UNUSED(tp);
	return (NNG_ENOTSUP);
#endif
}

static int
http_server_sys_init(void)
{
	NNI_LIST_INIT(&http_servers, nni_http_server, node);
	nni_mtx_init(&http_servers_lk);
	return (0);
}

static void
http_server_sys_fini(void)
{
	nni_mtx_fini(&http_servers_lk);
}
