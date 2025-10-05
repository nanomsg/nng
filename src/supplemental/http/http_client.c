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

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../core/nng_impl.h"

#include "http_api.h"
#include "http_msg.h"

static nni_mtx http_txn_lk = NNI_MTX_INITIALIZER;

struct nng_http_client {
	nni_list           aios;
	nni_mtx            mtx;
	bool               closed;
	nni_aio            aio;
	char               host[260];
	nng_stream_dialer *dialer;
};

static void
http_dial_start(nni_http_client *c)
{
	if (nni_list_empty(&c->aios)) {
		return;
	}
	nng_stream_dialer_dial(c->dialer, &c->aio);
}

static void
http_dial_cb(void *arg)
{
	nni_http_client *c = arg;
	nni_aio         *aio;
	nng_err          rv;
	nng_stream      *stream;
	nni_http_conn   *conn;

	nni_mtx_lock(&c->mtx);
	rv = nni_aio_result(&c->aio);

	if ((aio = nni_list_first(&c->aios)) == NULL) {
		// User abandoned request, and no residuals left.
		nni_mtx_unlock(&c->mtx);
		if (rv == 0) {
			stream = nni_aio_get_output(&c->aio, 0);
			nng_stream_free(stream);
		}
		return;
	}

	if (rv != NNG_OK) {
		nni_aio_list_remove(aio);
		http_dial_start(c);
		nni_mtx_unlock(&c->mtx);
		nni_aio_finish_error(aio, rv);
		return;
	}

	nni_aio_list_remove(aio);
	stream = nni_aio_get_output(&c->aio, 0);
	NNI_ASSERT(stream != NULL);

	rv = nni_http_init(&conn, stream, true);

	// set up the host header
	http_dial_start(c);
	nni_mtx_unlock(&c->mtx);

	if (rv != NNG_OK) {
		// the conn_init function will have already discard stream.
		nni_aio_finish_error(aio, rv);
		return;
	}
	nni_http_set_host(conn, c->host);
	nni_aio_set_output(aio, 0, conn);
	nni_aio_finish(aio, NNG_OK, 0);
}

void
nni_http_client_fini(nni_http_client *c)
{
	nni_aio_stop(&c->aio);
	nng_stream_dialer_stop(c->dialer);
	nni_aio_fini(&c->aio);
	nng_stream_dialer_free(c->dialer);
	nni_mtx_fini(&c->mtx);
	NNI_FREE_STRUCT(c);
}

nng_err
nni_http_client_init(nni_http_client **cp, const nng_url *url)
{
	nng_err          rv;
	nni_http_client *c;
	nng_url          my_url;
	const char      *scheme;

	if ((scheme = nni_http_stream_scheme(url->u_scheme)) == NULL) {
		return (NNG_EADDRINVAL);
	}
	// Rewrite URLs to either TLS or TCP.
	memcpy(&my_url, url, sizeof(my_url));
	my_url.u_scheme = (char *) scheme;

	if ((strlen(url->u_hostname) == 0) ||
	    (strlen(url->u_hostname) > 253)) {
		// We require a valid hostname.
		return (NNG_EADDRINVAL);
	}

	if ((c = NNI_ALLOC_STRUCT(c)) == NULL) {
		return (NNG_ENOMEM);
	}
	nni_mtx_init(&c->mtx);
	nni_aio_list_init(&c->aios);
	nni_aio_init(&c->aio, http_dial_cb, c);

	if (nni_url_default_port(url->u_scheme) == url->u_port) {
		snprintf(c->host, sizeof(c->host), "%s", url->u_hostname);
	} else if (strchr(url->u_hostname, ':') != NULL) {
		// IPv6 address, needs [wrapping]
		snprintf(c->host, sizeof(c->host), "[%s]:%d", url->u_hostname,
		    url->u_port);
	} else {
		snprintf(c->host, sizeof(c->host), "%s:%d", url->u_hostname,
		    url->u_port);
	}
	if ((rv = nng_stream_dialer_alloc_url(&c->dialer, &my_url)) != 0) {
		nni_http_client_fini(c);
		return (rv);
	}

	*cp = c;
	return (NNG_OK);
}

nng_err
nni_http_client_set_tls(nni_http_client *c, nng_tls_config *tls)
{
	return (nng_stream_dialer_set_tls(c->dialer, tls));
}

nng_err
nni_http_client_get_tls(nni_http_client *c, nng_tls_config **tlsp)
{
	return (nng_stream_dialer_get_tls(c->dialer, tlsp));
}

int
nni_http_client_set(nni_http_client *c, const char *name, const void *buf,
    size_t sz, nni_type t)
{
	// We have no local options, but we just pass them straight through.
	return (nni_stream_dialer_set(c->dialer, name, buf, sz, t));
}

int
nni_http_client_get(
    nni_http_client *c, const char *name, void *buf, size_t *szp, nni_type t)
{
	return (nni_stream_dialer_get(c->dialer, name, buf, szp, t));
}

static void
http_dial_cancel(nni_aio *aio, void *arg, nng_err rv)
{
	nni_http_client *c = arg;
	nni_mtx_lock(&c->mtx);
	nni_aio_abort(&c->aio, rv);
	if (nni_aio_list_active(aio)) {
		nni_aio_list_remove(aio);
		nni_aio_finish_error(aio, rv);
	}
	nni_mtx_unlock(&c->mtx);
}

void
nni_http_client_connect(nni_http_client *c, nni_aio *aio)
{
	nni_aio_reset(aio);
	nni_mtx_lock(&c->mtx);
	if (!nni_aio_start(aio, http_dial_cancel, c)) {
		nni_mtx_unlock(&c->mtx);
		return;
	}
	nni_list_append(&c->aios, aio);
	if (nni_list_first(&c->aios) == aio) {
		http_dial_start(c);
	}
	nni_mtx_unlock(&c->mtx);
}

typedef enum http_txn_state {
	HTTP_SENDING,
	HTTP_RECVING,
	HTTP_RECVING_BODY,
	HTTP_RECVING_CHUNKS,
} http_txn_state;

typedef struct http_txn {
	nni_aio          aio;  // lower level aio
	nni_list         aios; // upper level aio(s) -- maximum one
	nni_http_client *client;
	nni_http_conn   *conn;
	nni_http_res    *res;
	nni_http_chunks *chunks;
	http_txn_state   state;
	nni_reap_node    reap;
} http_txn;

static void
http_txn_reap(void *arg)
{
	http_txn *txn = arg;

	nni_aio_stop(&txn->aio);
	if (txn->client != NULL) {
		// We only close the connection if we created it.
		if (txn->conn != NULL) {
			nni_http_conn_fini(txn->conn);
			txn->conn = NULL;
		}
	}
	nni_http_chunks_free(txn->chunks);
	nni_aio_fini(&txn->aio);
	NNI_FREE_STRUCT(txn);
}

static nni_reap_list http_txn_reaplist = {
	.rl_offset = offsetof(http_txn, reap),
	.rl_func   = (nni_cb) http_txn_reap,
};

static void
http_txn_fini(http_txn *txn)
{
	nni_reap(&http_txn_reaplist, txn);
}

static void
http_txn_finish_aios(http_txn *txn, int rv)
{
	nni_aio *aio;
	while ((aio = nni_list_first(&txn->aios)) != NULL) {
		nni_list_remove(&txn->aios, aio);
		nni_aio_finish_error(aio, rv);
	}
}

static void
http_txn_cb(void *arg)
{
	http_txn       *txn = arg;
	const char     *str;
	char           *end;
	nng_err         rv;
	uint64_t        len;
	nni_iov         iov;
	char           *dst;
	size_t          sz;
	nni_http_chunk *chunk = NULL;

	nni_mtx_lock(&http_txn_lk);
	if ((rv = nni_aio_result(&txn->aio)) != NNG_OK) {
		http_txn_finish_aios(txn, rv);
		nni_mtx_unlock(&http_txn_lk);
		http_txn_fini(txn);
		return;
	}
	switch (txn->state) {
	case HTTP_SENDING:
		txn->state = HTTP_RECVING;
		nni_http_read_res(txn->conn, &txn->aio);
		nni_mtx_unlock(&http_txn_lk);
		return;

	case HTTP_RECVING:

		// Detect chunked encoding.  You poor bastard.  (Only if not
		// HEAD.)
		if ((strcmp(nni_http_get_method(txn->conn), "HEAD") != 0) &&
		    ((str = nni_http_get_header(
		          txn->conn, "Transfer-Encoding")) != NULL) &&
		    (strstr(str, "chunked") != NULL)) {

			if ((rv = nni_http_chunks_init(&txn->chunks, 0)) !=
			    NNG_OK) {
				goto error;
			}
			txn->state = HTTP_RECVING_CHUNKS;
			nni_http_read_chunks(
			    txn->conn, txn->chunks, &txn->aio);
			nni_mtx_unlock(&http_txn_lk);
			return;
		}

		if ((strcmp(nni_http_get_method(txn->conn), "HEAD") == 0) ||
		    ((str = nni_http_get_header(
		          txn->conn, "Content-Length")) == NULL) ||
		    ((len = (uint64_t) strtoull(str, &end, 10)) == 0) ||
		    (end == NULL) || (*end != '\0')) {
			// If no content-length, or HEAD (which per RFC
			// never transfers data), then we are done.
			http_txn_finish_aios(txn, 0);
			nni_mtx_unlock(&http_txn_lk);
			http_txn_fini(txn);
			return;
		}

		if ((rv = nni_http_res_alloc_data(txn->res, (size_t) len)) !=
		    NNG_OK) {
			goto error;
		}
		nni_http_get_body(txn->conn, &iov.iov_buf, &iov.iov_len);
		nni_aio_set_iov(&txn->aio, 1, &iov);
		txn->state = HTTP_RECVING_BODY;
		nni_http_read_full(txn->conn, &txn->aio);
		nni_mtx_unlock(&http_txn_lk);
		return;

	case HTTP_RECVING_BODY:
		// All done!
		http_txn_finish_aios(txn, 0);
		nni_mtx_unlock(&http_txn_lk);
		http_txn_fini(txn);
		return;

	case HTTP_RECVING_CHUNKS:
		// All done, but now we need to coalesce the chunks, for
		// yet *another* copy.  Chunked transfers are such crap.
		sz = nni_http_chunks_size(txn->chunks);
		if ((rv = nni_http_res_alloc_data(txn->res, sz)) != 0) {
			goto error;
		}
		nni_http_get_body(txn->conn, (void **) &dst, &sz);
		while ((chunk = nni_http_chunks_iter(txn->chunks, chunk)) !=
		    NULL) {
			memcpy(dst, nni_http_chunk_data(chunk),
			    nni_http_chunk_size(chunk));
			dst += nni_http_chunk_size(chunk);
		}
		http_txn_finish_aios(txn, 0);
		nni_mtx_unlock(&http_txn_lk);
		http_txn_fini(txn);
		return;
	}

error:
	http_txn_finish_aios(txn, rv);
	nni_http_conn_close(txn->conn);
	nni_mtx_unlock(&http_txn_lk);
	http_txn_fini(txn);
}

static void
http_txn_cancel(nni_aio *aio, void *arg, nng_err rv)
{
	http_txn *txn = arg;
	nni_mtx_lock(&http_txn_lk);
	if (nni_aio_list_active(aio)) {
		nni_aio_abort(&txn->aio, rv);
	}
	nni_mtx_unlock(&http_txn_lk);
}

// nni_http_transact_conn sends a request to an HTTP server, and reads the
// response.  It also attempts to read any associated data.  Note that
// at present it can only read data that comes in normally, as support
// for Chunked Transfer Encoding is missing.  Note that cancelling the aio
// is generally fatal to the connection.
void
nni_http_transact_conn(nni_http_conn *conn, nni_aio *aio)
{
	http_txn *txn;

	nni_aio_reset(aio);
	if ((txn = NNI_ALLOC_STRUCT(txn)) == NULL) {
		nni_aio_finish_error(aio, NNG_ENOMEM);
		return;
	}
	nni_aio_init(&txn->aio, http_txn_cb, txn);
	nni_aio_list_init(&txn->aios);
	txn->client = NULL;
	txn->conn   = conn;
	txn->res    = nni_http_conn_res(conn);
	txn->state  = HTTP_SENDING;

	nni_http_res_reset(txn->res);
	nni_http_set_status(txn->conn, 0, NULL);

	nni_mtx_lock(&http_txn_lk);
	if (!nni_aio_start(aio, http_txn_cancel, txn)) {
		nni_mtx_unlock(&http_txn_lk);
		http_txn_fini(txn);
		return;
	}
	nni_list_append(&txn->aios, aio);
	nni_http_write_req(conn, &txn->aio);
	nni_mtx_unlock(&http_txn_lk);
}
