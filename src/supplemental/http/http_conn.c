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

#include <complex.h>
#include <ctype.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "../../core/list.h"
#include "../../core/nng_impl.h"
#include "../../supplemental/tls/tls_api.h"
#include "nng/http.h"

#include "http_api.h"
#include "http_msg.h"
#include "nng/nng.h"

// We insist that individual headers fit in 8K.
// If you need more than that, you need something we can't do.
// We leave some room for allocator overhead (32 bytes should
// be more than enough), to avoid possibly wasting an extra page.
#define HTTP_BUFSIZE (8192 - 32)

// types of reads
enum read_flavor {
	HTTP_RD_RAW,
	HTTP_RD_FULL,
	HTTP_RD_REQ,
	HTTP_RD_RES,
	HTTP_RD_CHUNK,
	HTTP_RD_DISCARD,
};

enum write_flavor {
	HTTP_WR_RAW,
	HTTP_WR_FULL,
	HTTP_WR_REQ,
	HTTP_WR_RES,
};

struct nng_http_conn {
	nng_stream *sock;
	void       *ctx;
	nni_list    rdq; // high level http read requests
	nni_list    wrq; // high level http write requests

	nng_aio *rd_uaio; // user aio for read
	nng_aio *wr_uaio; // user aio for write
	nng_aio  rd_aio;  // bottom half read operations
	nng_aio  wr_aio;  // bottom half write operations

	nni_mtx mtx;

	nng_http_req req;
	nng_http_res res;

	nng_http_status code;
	char            meth[32];
	char            host[260]; // 253 per IETF, plus 6 for :port plus null
	char            ubuf[200]; // Most URIs are smaller than this
	const char     *vers;
	char           *uri;
	char           *rsn;

	uint8_t *buf;
	size_t   bufsz;
	size_t   rd_get;
	size_t   rd_put;
	size_t   rd_discard;

	// some common headers
	http_header host_header; // request
	http_header location;    // response (redirects)

	enum read_flavor  rd_flavor;
	enum write_flavor wr_flavor;
	bool              buffered;
	bool              client; // true if a client's connection
	bool              res_sent;
	bool              closed;
	bool              iserr;
};

nng_http_req *
nni_http_conn_req(nng_http *conn)
{
	return (&conn->req);
}

nng_http_res *
nni_http_conn_res(nng_http *conn)
{
	return (&conn->res);
}

void
nni_http_conn_set_ctx(nni_http_conn *conn, void *ctx)
{
	conn->ctx = ctx;
}

void *
nni_http_conn_get_ctx(nni_http_conn *conn)
{
	return (conn->ctx);
}

static void
http_close(nni_http_conn *conn)
{
	// Call with lock held.
	nni_aio *aio;

	if (conn->closed) {
		return;
	}

	conn->closed = true;
	nni_aio_close(&conn->wr_aio);
	nni_aio_close(&conn->rd_aio);

	if ((aio = conn->rd_uaio) != NULL) {
		conn->rd_uaio = NULL;
		nni_aio_finish_error(aio, NNG_ECLOSED);
	}
	if ((aio = conn->wr_uaio) != NULL) {
		conn->wr_uaio = NULL;
		nni_aio_finish_error(aio, NNG_ECLOSED);
	}

	// Abort all operations except the one in flight.
	while ((aio = nni_list_first(&conn->wrq)) != NULL) {
		nni_aio_list_remove(aio);
		nni_aio_finish_error(aio, NNG_ECLOSED);
	}
	while ((aio = nni_list_first(&conn->rdq)) != NULL) {
		nni_aio_list_remove(aio);
		nni_aio_finish_error(aio, NNG_ECLOSED);
	}

	if (conn->sock != NULL) {
		nng_stream_close(conn->sock);
	}
}

void
nni_http_conn_close(nni_http_conn *conn)
{
	nni_mtx_lock(&conn->mtx);
	http_close(conn);
	nni_mtx_unlock(&conn->mtx);
}

const nng_sockaddr *
nni_http_peer_addr(nni_http_conn *conn)
{
	return (nng_stream_peer_addr(conn->sock));
}

const nng_sockaddr *
nni_http_self_addr(nni_http_conn *conn)
{
	return (nng_stream_self_addr(conn->sock));
}

// http_buf_pull_up pulls the content of the read buffer back to the
// beginning, so that the next read can go at the end.  This avoids the problem
// of dealing with a read that might wrap.
static void
http_buf_pull_up(nni_http_conn *conn)
{
	if (conn->rd_get != 0) {
		memmove(conn->buf, conn->buf + conn->rd_get,
		    conn->rd_put - conn->rd_get);
		conn->rd_put -= conn->rd_get;
		conn->rd_get = 0;
	}
}

// http_rd_buf attempts to satisfy the read from data in the buffer.
static nng_err
http_rd_buf(nni_http_conn *conn, nni_aio *aio)
{
	size_t   cnt = conn->rd_put - conn->rd_get;
	size_t   n;
	uint8_t *rbuf = conn->buf;
	nng_err  rv;
	bool     raw = false;
	nni_iov *iov;
	unsigned nio;

	rbuf += conn->rd_get;

	switch (conn->rd_flavor) {
	case HTTP_RD_RAW:
		raw = true; // FALLTHROUGH
	case HTTP_RD_FULL:
		nni_aio_get_iov(aio, &nio, &iov);
		while ((nio != 0) && (cnt != 0)) {
			// Pull up data from the buffer if possible.
			n = iov[0].iov_len;
			if (n > cnt) {
				n = cnt;
			}
			memcpy(iov[0].iov_buf, rbuf, n);
			iov[0].iov_len -= n;
			NNI_INCPTR(iov[0].iov_buf, n);
			conn->rd_get += n;
			rbuf += n;
			nni_aio_bump_count(aio, n);
			cnt -= n;

			if (iov[0].iov_len == 0) {
				nio--;
				iov = &iov[1];
			}
		}

		nni_aio_set_iov(aio, nio, iov);

		if ((nio == 0) || (raw && (nni_aio_count(aio) != 0))) {
			// Finished the read.  (We are finished if we either
			// got *all* the data, or we got *some* data for
			// a raw read.)
			return (NNG_OK);
		}

		// No more data left in the buffer, so use a physio.
		// (Note that we get here if we either have not completed
		// a full transaction on a FULL read, or were not even able
		// to get *any* data for a partial RAW read.)
		conn->buffered = false;
		nni_aio_set_iov(&conn->rd_aio, nio, iov);
		nng_stream_recv(conn->sock, &conn->rd_aio);
		return (NNG_EAGAIN);

	case HTTP_RD_DISCARD:
		n = conn->rd_put - conn->rd_get;
		if (n > conn->rd_discard) {
			n = conn->rd_discard;
		}
		conn->rd_get += n;
		conn->rd_discard -= n;
		http_buf_pull_up(conn);
		if (conn->rd_discard > 0) {
			nni_iov iov1;
			iov1.iov_buf   = conn->buf + conn->rd_put;
			iov1.iov_len   = conn->bufsz - conn->rd_put;
			conn->buffered = true;
			nni_aio_set_iov(&conn->rd_aio, 1, &iov1);
			nng_stream_recv(conn->sock, &conn->rd_aio);
			return (NNG_EAGAIN);
		}
		return (NNG_OK);

	case HTTP_RD_REQ:
		conn->client = true;
		rv           = nni_http_req_parse(conn, rbuf, cnt, &n);
		conn->client = false;
		conn->rd_get += n;
		if (conn->rd_get == conn->rd_put) {
			conn->rd_get = conn->rd_put = 0;
		}
		if (rv == NNG_EAGAIN) {
			nni_iov iov1;
			http_buf_pull_up(conn);
			if (conn->rd_put == conn->bufsz) {
				nng_http_set_status(conn,
				    conn->req.data.parsed
				        ? NNG_HTTP_STATUS_HEADERS_TOO_LARGE
				        : NNG_HTTP_STATUS_URI_TOO_LONG,
				    NULL);
				// leave a "header" so we don't confuse parsing
				// We want to ensure this is an overlong
				// request.
				strcpy((char *) conn->buf, "NNG-DISCARD: X");
				conn->rd_get = 0;
				conn->rd_put = strlen((char *) conn->buf);
			}
			iov1.iov_buf   = conn->buf + conn->rd_put;
			iov1.iov_len   = conn->bufsz - conn->rd_put;
			conn->buffered = true;
			nni_aio_set_iov(&conn->rd_aio, 1, &iov1);
			nng_stream_recv(conn->sock, &conn->rd_aio);
		}
		return (rv);

	case HTTP_RD_RES:
		conn->client = false;
		rv           = nni_http_res_parse(conn, rbuf, cnt, &n);
		conn->client = true;
		conn->rd_get += n;
		if (conn->rd_get == conn->rd_put) {
			conn->rd_get = conn->rd_put = 0;
		}
		if (rv == NNG_EAGAIN) {
			nni_iov iov1;
			http_buf_pull_up(conn);
			iov1.iov_buf   = conn->buf + conn->rd_put;
			iov1.iov_len   = conn->bufsz - conn->rd_put;
			conn->buffered = true;
			if (iov1.iov_len == 0) {
				return (NNG_EMSGSIZE);
			}
			nni_aio_set_iov(&conn->rd_aio, 1, &iov1);
			nng_stream_recv(conn->sock, &conn->rd_aio);
		}
		return (rv);

	case HTTP_RD_CHUNK:
		rv = nni_http_chunks_parse(
		    nni_aio_get_prov_data(aio), rbuf, cnt, &n);
		conn->rd_get += n;
		if (conn->rd_get == conn->rd_put) {
			conn->rd_get = conn->rd_put = 0;
		}
		if (rv == NNG_EAGAIN) {
			nni_iov iov1;
			iov1.iov_buf   = conn->buf + conn->rd_put;
			iov1.iov_len   = conn->bufsz - conn->rd_put;
			conn->buffered = true;
			nni_aio_set_iov(&conn->rd_aio, 1, &iov1);
			nng_stream_recv(conn->sock, &conn->rd_aio);
		}
		return (rv);
	}
	return (NNG_EINVAL);
}

static void
http_rd_start(nni_http_conn *conn)
{
	for (;;) {
		nni_aio *aio;
		int      rv;

		if ((aio = conn->rd_uaio) == NULL) {
			if ((aio = nni_list_first(&conn->rdq)) == NULL) {
				// No more stuff waiting for read.
				return;
			}
			nni_list_remove(&conn->rdq, aio);
			conn->rd_uaio = aio;
		}

		if (conn->closed) {
			rv = NNG_ECLOSED;
		} else {
			rv = http_rd_buf(conn, aio);
		}
		switch (rv) {
		case NNG_EAGAIN:
			return;
		case 0:
			conn->rd_uaio = NULL;
			nni_aio_finish(aio, NNG_OK, nni_aio_count(aio));
			break;
		default:
			conn->rd_uaio = NULL;
			nni_aio_finish_error(aio, rv);
			http_close(conn);
			break;
		}
	}
}

static void
http_rd_cb(void *arg)
{
	nni_http_conn *conn = arg;
	nni_aio       *aio  = &conn->rd_aio;
	nni_aio       *uaio;
	size_t         cnt;
	nng_err        rv;
	unsigned       niov;
	nni_iov       *iov;

	nni_mtx_lock(&conn->mtx);

	if ((rv = nni_aio_result(aio)) != 0) {
		if ((uaio = conn->rd_uaio) != NULL) {
			conn->rd_uaio = NULL;
			nni_aio_finish_error(uaio, rv);
		}
		http_close(conn);
		nni_mtx_unlock(&conn->mtx);
		return;
	}

	cnt = nni_aio_count(aio);

	// If we were reading into the buffer, then advance location(s).
	if (conn->buffered) {
		conn->rd_put += cnt;
		NNI_ASSERT(conn->rd_put <= conn->bufsz);
		http_rd_start(conn);
		nni_mtx_unlock(&conn->mtx);
		return;
	}

	// Otherwise we are completing a USER request, and there should
	// be no data left in the user buffer.
	NNI_ASSERT(conn->rd_get == conn->rd_put);

	if ((uaio = conn->rd_uaio) == NULL) {
		// This indicates that a read request was canceled.  This
		// can occur only when shutting down, really.
		nni_mtx_unlock(&conn->mtx);
		return;
	}

	nni_aio_get_iov(uaio, &niov, &iov);

	while ((niov != 0) && (cnt != 0)) {
		// Pull up data from the buffer if possible.
		size_t n = iov[0].iov_len;
		if (n > cnt) {
			n = cnt;
		}
		iov[0].iov_len -= n;
		NNI_INCPTR(iov[0].iov_buf, n);
		nni_aio_bump_count(uaio, n);
		cnt -= n;

		if (iov[0].iov_len == 0) {
			niov--;
			iov = &iov[1];
		}
	}
	nni_aio_set_iov(uaio, niov, iov);

	// Resubmit the start.  This will attempt to consume data
	// from the read buffer (there won't be any), and then either
	// complete the I/O (for HTTP_RD_RAW, or if there is nothing left),
	// or submit another physio.
	http_rd_start(conn);
	nni_mtx_unlock(&conn->mtx);
}

static void
http_rd_cancel(nni_aio *aio, void *arg, nng_err rv)
{
	nni_http_conn *conn = arg;

	nni_mtx_lock(&conn->mtx);
	if (aio == conn->rd_uaio) {
		conn->rd_uaio = NULL;
		nni_aio_abort(&conn->rd_aio, rv);
		nni_aio_finish_error(aio, rv);
	} else if (nni_aio_list_active(aio)) {
		nni_aio_list_remove(aio);
		nni_aio_finish_error(aio, rv);
	}
	nni_mtx_unlock(&conn->mtx);
}

static void
http_rd_submit(nni_http_conn *conn, nni_aio *aio, enum read_flavor flavor)
{
	nni_aio_reset(aio);
	if (conn->closed) {
		nni_aio_finish_error(aio, NNG_ECLOSED);
		return;
	}
	if (!nni_aio_start(aio, http_rd_cancel, conn)) {
		return;
	}
	conn->rd_flavor = flavor;
	nni_list_append(&conn->rdq, aio);
	if (conn->rd_uaio == NULL) {
		http_rd_start(conn);
	}
}

static void
http_wr_start(nni_http_conn *conn)
{
	nni_aio *aio;
	nni_iov *iov;
	unsigned niov;

	if ((aio = conn->wr_uaio) == NULL) {
		if ((aio = nni_list_first(&conn->wrq)) == NULL) {
			// No more stuff waiting for read.
			return;
		}
		nni_list_remove(&conn->wrq, aio);
		conn->wr_uaio = aio;
	}

	nni_aio_get_iov(aio, &niov, &iov);
	nni_aio_set_iov(&conn->wr_aio, niov, iov);
	nng_stream_send(conn->sock, &conn->wr_aio);
}

static void
http_wr_cb(void *arg)
{
	nni_http_conn *conn = arg;
	nni_aio       *aio  = &conn->wr_aio;
	nni_aio       *uaio;
	nng_err        rv;
	size_t         n;

	nni_mtx_lock(&conn->mtx);

	uaio = conn->wr_uaio;

	if ((rv = nni_aio_result(aio)) != NNG_OK) {
		// We failed to complete the aio.
		if (uaio != NULL) {
			conn->wr_uaio = NULL;
			nni_aio_finish_error(uaio, rv);
		}
		http_close(conn);
		nni_mtx_unlock(&conn->mtx);
		return;
	}

	if (uaio == NULL) {
		// Write canceled?  This happens pretty much only during
		// shutdown/close, so we don't want to resume writing.
		// The stream is probably corrupted at this point anyway.
		nni_mtx_unlock(&conn->mtx);
		return;
	}

	n = nni_aio_count(aio);
	nni_aio_bump_count(uaio, n);

	if (conn->wr_flavor == HTTP_WR_RAW) {
		// For raw data, we just send partial completion
		// notices to the consumer.
		goto done;
	}
	nni_aio_iov_advance(aio, n);
	if (nni_aio_iov_count(aio) > 0) {
		// We have more to transmit - start another and leave
		// (we will get called again when it is done).
		nng_stream_send(conn->sock, aio);
		nni_mtx_unlock(&conn->mtx);
		return;
	}

done:
	conn->wr_uaio = NULL;
	nni_aio_finish(uaio, NNG_OK, nni_aio_count(uaio));

	// Start next write if another is ready.
	http_wr_start(conn);

	nni_mtx_unlock(&conn->mtx);
}

static void
http_wr_cancel(nni_aio *aio, void *arg, nng_err rv)
{
	nni_http_conn *conn = arg;

	nni_mtx_lock(&conn->mtx);
	if (aio == conn->wr_uaio) {
		conn->wr_uaio = NULL;
		nni_aio_abort(&conn->wr_aio, rv);
		nni_aio_finish_error(aio, rv);
	} else if (nni_aio_list_active(aio)) {
		nni_aio_list_remove(aio);
		nni_aio_finish_error(aio, rv);
	}
	nni_mtx_unlock(&conn->mtx);
}

static void
http_wr_submit(nni_http_conn *conn, nni_aio *aio, enum write_flavor flavor)
{
	nni_aio_reset(aio);
	if (conn->closed) {
		nni_aio_finish_error(aio, NNG_ECLOSED);
		return;
	}
	if (!nni_aio_start(aio, http_wr_cancel, conn)) {
		return;
	}
	conn->wr_flavor = flavor;
	nni_list_append(&conn->wrq, aio);

	if (conn->wr_uaio == NULL) {
		http_wr_start(conn);
	}
}

void
nni_http_conn_reset(nng_http *conn)
{
	nni_http_req_reset(&conn->req);
	nni_http_res_reset(&conn->res);
	(void) snprintf(conn->meth, sizeof(conn->meth), "GET");
	if (strlen(conn->host)) {
		nni_http_set_host(conn, conn->host);
	}
	if (conn->uri != NULL && conn->uri != conn->ubuf) {
		nni_strfree(conn->uri);
	}
	conn->uri = NULL;
	nni_http_set_version(conn, NNG_HTTP_VERSION_1_1);
	nni_http_set_status(conn, 0, NULL);
}

void
nni_http_read_req(nni_http_conn *conn, nni_aio *aio)
{
	// clear the sent flag (used for the server)
	conn->res_sent = false;
	nni_http_conn_reset(conn);
	nni_mtx_lock(&conn->mtx);
	http_rd_submit(conn, aio, HTTP_RD_REQ);
	nni_mtx_unlock(&conn->mtx);
}

void
nni_http_read_res(nni_http_conn *conn, nni_aio *aio)
{
	nni_mtx_lock(&conn->mtx);
	http_rd_submit(conn, aio, HTTP_RD_RES);
	nni_mtx_unlock(&conn->mtx);
}

void
nni_http_read_chunks(nni_http_conn *conn, nni_http_chunks *cl, nni_aio *aio)
{
	nni_aio_set_prov_data(aio, cl);

	nni_mtx_lock(&conn->mtx);
	conn->rd_discard = 0;
	http_rd_submit(conn, aio, HTTP_RD_CHUNK);
	nni_mtx_unlock(&conn->mtx);
}

void
nni_http_read_full(nni_http_conn *conn, nni_aio *aio)
{
	nni_aio_set_prov_data(aio, NULL);

	nni_mtx_lock(&conn->mtx);
	conn->rd_discard = 0;
	http_rd_submit(conn, aio, HTTP_RD_FULL);
	nni_mtx_unlock(&conn->mtx);
}

void
nni_http_read_discard(nng_http *conn, size_t discard, nng_aio *aio)
{
	nni_mtx_lock(&conn->mtx);
	conn->rd_discard = discard;
	http_rd_submit(conn, aio, HTTP_RD_DISCARD);
	nni_mtx_unlock(&conn->mtx);
}

void
nni_http_read(nni_http_conn *conn, nni_aio *aio)
{
	nni_aio_set_prov_data(aio, NULL);

	nni_mtx_lock(&conn->mtx);
	http_rd_submit(conn, aio, HTTP_RD_RAW);
	nni_mtx_unlock(&conn->mtx);
}

static size_t
http_sprintf_headers(char *buf, size_t sz, nni_list *list)
{
	size_t       rv = 0;
	http_header *h;

	if (buf == NULL) {
		sz = 0;
	}

	NNI_LIST_FOREACH (list, h) {
		size_t l;
		l = snprintf(buf, sz, "%s: %s\r\n", h->name, h->value);
		if (buf != NULL) {
			buf += l;
		}
		sz = (sz > l) ? sz - l : 0;
		rv += l;
	}
	return (rv);
}

static int
http_snprintf(nng_http *conn, char *buf, size_t sz)
{
	size_t    len;
	size_t    n;
	nni_list *hdrs;

	if (conn->client) {
		len  = snprintf(buf, sz, "%s %s %s\r\n",
		     nni_http_get_method(conn), nni_http_get_uri(conn),
		     nni_http_get_version(conn));
		hdrs = &conn->req.data.hdrs;
	} else {
		len  = snprintf(buf, sz, "%s %d %s\r\n",
		     nni_http_get_version(conn), nni_http_get_status(conn),
		     nni_http_get_reason(conn));
		hdrs = &conn->res.data.hdrs;
	}

	if (len < sz) {
		sz -= len;
		buf += len;
	} else {
		sz  = 0;
		buf = NULL;
	}

	n = http_sprintf_headers(buf, sz, hdrs);
	len += n;
	if (n < sz) {
		sz -= n;
		buf += n;
	} else {
		sz  = 0;
		buf = NULL;
	}

	len += snprintf(buf, sz, "\r\n");
	return (len);
}

static nng_err
http_prepare(nng_http *conn, void **data, size_t *szp)
{
	size_t len;

	// get length needed first
	len = http_snprintf(conn, NULL, 0);

	// If it fits in the fixed buffer, use it. It should cover
	// like 99% or more cases, as this buffer is 8KB.
	if (len < conn->bufsz) {
		http_snprintf(conn, (char *) conn->buf, conn->bufsz);
		*data = conn->buf;
		*szp  = len;
		return (NNG_OK);
	}

	// we have to allocate.
	if ((*data = nni_alloc(len + 1)) == NULL) {
		return (NNG_ENOMEM);
	}
	http_snprintf(conn, *data, len + 1);
	*szp = len; // this does not include the terminating null
	return (NNG_OK);
}

void
nni_http_write_req(nng_http *conn, nni_aio *aio)
{
	nng_err rv;
	void   *buf;
	size_t  bufsz;
	nni_iov iov[2];
	int     niov;

	if ((rv = http_prepare(conn, &buf, &bufsz)) != 0) {
		nni_aio_finish_error(aio, rv);
		return;
	}
	if (buf != conn->buf) {
		nni_free(conn->req.data.buf, conn->req.data.bufsz);
		conn->req.data.buf   = buf;
		conn->req.data.bufsz = bufsz + 1; // including \0
	}
	niov           = 1;
	iov[0].iov_len = bufsz;
	iov[0].iov_buf = buf;
	iov[1].iov_len = conn->req.data.size;
	iov[1].iov_buf = conn->req.data.data;
	if ((iov[1].iov_len > 0) && (iov[1].iov_buf != NULL)) {
		niov++;
	}
	nni_aio_set_iov(aio, niov, iov);

	nni_mtx_lock(&conn->mtx);
	http_wr_submit(conn, aio, HTTP_WR_REQ);
	nni_mtx_unlock(&conn->mtx);
}

void
nni_http_write_res(nng_http *conn, nni_aio *aio)
{
	nng_err rv;
	void   *buf;
	size_t  bufsz;
	nni_iov iov[2];
	int     nio;

	if ((rv = http_prepare(conn, &buf, &bufsz)) != 0) {
		nni_aio_finish_error(aio, rv);
		return;
	}
	if (buf != conn->buf) {
		nni_free(conn->res.data.buf, conn->res.data.bufsz);
		conn->res.data.buf   = buf;
		conn->res.data.bufsz = bufsz + 1; // including \0
	}

	conn->res_sent = true;
	nio            = 1;
	iov[0].iov_len = bufsz;
	iov[0].iov_buf = buf;
	iov[1].iov_len = conn->res.data.size;
	iov[1].iov_buf = conn->res.data.data;
	if ((iov[1].iov_len > 0) && (iov[1].iov_buf != NULL)) {
		nio++;
	}
	nni_aio_set_iov(aio, nio, iov);

	nni_mtx_lock(&conn->mtx);
	http_wr_submit(conn, aio, HTTP_WR_RES);
	nni_mtx_unlock(&conn->mtx);
}

void
nni_http_write(nni_http_conn *conn, nni_aio *aio)
{
	nni_mtx_lock(&conn->mtx);
	http_wr_submit(conn, aio, HTTP_WR_RAW);
	nni_mtx_unlock(&conn->mtx);
}

void
nni_http_write_full(nni_http_conn *conn, nni_aio *aio)
{
	nni_mtx_lock(&conn->mtx);
	http_wr_submit(conn, aio, HTTP_WR_FULL);
	nni_mtx_unlock(&conn->mtx);
}

const char *
nni_http_get_version(nng_http *conn)
{
	return (conn->vers);
}

int
nni_http_set_version(nng_http *conn, const char *vers)
{
	static const char *http_versions[] = {
		// for efficiency, we order in most likely first
		"HTTP/1.1",
		"HTTP/2",
		"HTTP/3",
		"HTTP/1.0",
		"HTTP/0.9",
		NULL,
	};

	vers = vers != NULL ? vers : NNG_HTTP_VERSION_1_1;
	for (int i = 0; http_versions[i] != NULL; i++) {
		if (strcmp(vers, http_versions[i]) == 0) {
			conn->vers = http_versions[i];
			return (NNG_OK);
		}
	}
	return (NNG_ENOTSUP);
}

void
nni_http_set_method(nng_http *conn, const char *method)
{
	if (method == NULL) {
		method = "GET";
	}
	// this may truncate the method, but nobody should be sending
	// methods so long.
	(void) snprintf(conn->meth, sizeof(conn->meth), "%s", method);
}

const char *
nni_http_get_method(nng_http *conn)
{
	return (conn->meth);
}

nng_http_status
nni_http_get_status(nng_http *conn)
{
	return (conn->code ? conn->code : NNG_HTTP_STATUS_OK);
}

const char *
nni_http_reason(nng_http_status code)
{
	static struct {
		nng_http_status code;
		const char     *mesg;
	} http_status[] = {
		// 200, listed first because most likely
		{ NNG_HTTP_STATUS_OK, "OK" },

		// 100 series -- informational
		{ NNG_HTTP_STATUS_CONTINUE, "Continue" },
		{ NNG_HTTP_STATUS_SWITCHING, "Switching Protocols" },
		{ NNG_HTTP_STATUS_PROCESSING, "Processing" },

		// 200 series -- successful
		{ NNG_HTTP_STATUS_CREATED, "Created" },
		{ NNG_HTTP_STATUS_ACCEPTED, "Accepted" },
		{ NNG_HTTP_STATUS_NOT_AUTHORITATIVE, "Not Authoritative" },
		{ NNG_HTTP_STATUS_NO_CONTENT, "No Content" },
		{ NNG_HTTP_STATUS_RESET_CONTENT, "Reset Content" },
		{ NNG_HTTP_STATUS_PARTIAL_CONTENT, "Partial Content" },
		{ NNG_HTTP_STATUS_MULTI_STATUS, "Multi-Status" },
		{ NNG_HTTP_STATUS_ALREADY_REPORTED, "Already Reported" },
		{ NNG_HTTP_STATUS_IM_USED, "IM Used" },

		// 300 series -- redirection
		{ NNG_HTTP_STATUS_MULTIPLE_CHOICES, "Multiple Choices" },
		{ NNG_HTTP_STATUS_STATUS_MOVED_PERMANENTLY,
		    "Moved Permanently" },
		{ NNG_HTTP_STATUS_FOUND, "Found" },
		{ NNG_HTTP_STATUS_SEE_OTHER, "See Other" },
		{ NNG_HTTP_STATUS_NOT_MODIFIED, "Not Modified" },
		{ NNG_HTTP_STATUS_USE_PROXY, "Use Proxy" },
		{ NNG_HTTP_STATUS_TEMPORARY_REDIRECT, "Temporary Redirect" },
		{ NNG_HTTP_STATUS_PERMANENT_REDIRECT, "Permanent Redirect" },

		// 400 series -- client errors
		{ NNG_HTTP_STATUS_BAD_REQUEST, "Bad Request" },
		{ NNG_HTTP_STATUS_UNAUTHORIZED, "Unauthorized" },
		{ NNG_HTTP_STATUS_PAYMENT_REQUIRED, "Payment Required" },
		{ NNG_HTTP_STATUS_FORBIDDEN, "Forbidden" },
		{ NNG_HTTP_STATUS_NOT_FOUND, "Not Found" },
		{ NNG_HTTP_STATUS_METHOD_NOT_ALLOWED, "Method Not Allowed" },
		{ NNG_HTTP_STATUS_NOT_ACCEPTABLE, "Not Acceptable" },
		{ NNG_HTTP_STATUS_PROXY_AUTH_REQUIRED,
		    "Proxy Authentication Required" },
		{ NNG_HTTP_STATUS_REQUEST_TIMEOUT, "Request Timeout" },
		{ NNG_HTTP_STATUS_CONFLICT, "Conflict" },
		{ NNG_HTTP_STATUS_GONE, "Gone" },
		{ NNG_HTTP_STATUS_LENGTH_REQUIRED, "Length Required" },
		{ NNG_HTTP_STATUS_PRECONDITION_FAILED, "Precondition Failed" },
		{ NNG_HTTP_STATUS_CONTENT_TOO_LARGE, "Content Too Large" },
		{ NNG_HTTP_STATUS_URI_TOO_LONG, "URI Too Long" },
		{ NNG_HTTP_STATUS_UNSUPPORTED_MEDIA_TYPE,
		    "Unsupported Media Type" },
		{ NNG_HTTP_STATUS_RANGE_NOT_SATISFIABLE,
		    "Range Not Satisfiable" },
		{ NNG_HTTP_STATUS_EXPECTATION_FAILED, "Expectation Failed" },
		{ NNG_HTTP_STATUS_TEAPOT, "I Am A Teapot" },
		{ NNG_HTTP_STATUS_LOCKED, "Locked" },
		{ NNG_HTTP_STATUS_FAILED_DEPENDENCY, "Failed Dependency" },
		{ NNG_HTTP_STATUS_UPGRADE_REQUIRED, "Upgrade Required" },
		{ NNG_HTTP_STATUS_PRECONDITION_REQUIRED,
		    "Precondition Required" },
		{ NNG_HTTP_STATUS_TOO_MANY_REQUESTS, "Too Many Requests" },
		{ NNG_HTTP_STATUS_HEADERS_TOO_LARGE, "Headers Too Large" },
		{ NNG_HTTP_STATUS_UNAVAIL_LEGAL_REASONS,
		    "Unavailable For Legal Reasons" },

		// 500 series -- server errors
		{ NNG_HTTP_STATUS_INTERNAL_SERVER_ERROR,
		    "Internal Server Error" },
		{ NNG_HTTP_STATUS_NOT_IMPLEMENTED, "Not Implemented" },
		{ NNG_HTTP_STATUS_BAD_REQUEST, "Bad Gateway" },
		{ NNG_HTTP_STATUS_SERVICE_UNAVAILABLE, "Service Unavailable" },
		{ NNG_HTTP_STATUS_GATEWAY_TIMEOUT, "Gateway Timeout" },
		{ NNG_HTTP_STATUS_HTTP_VERSION_NOT_SUPP,
		    "HTTP Version Not Supported" },
		{ NNG_HTTP_STATUS_VARIANT_ALSO_NEGOTIATES,
		    "Variant Also Negotiates" },
		{ NNG_HTTP_STATUS_INSUFFICIENT_STORAGE,
		    "Insufficient Storage" },
		{ NNG_HTTP_STATUS_LOOP_DETECTED, "Loop Detected" },
		{ NNG_HTTP_STATUS_NOT_EXTENDED, "Not Extended" },
		{ NNG_HTTP_STATUS_NETWORK_AUTH_REQUIRED,
		    "Network Authentication Required" },

		// Terminator
		{ 0, NULL },
	};

	for (int i = 0; http_status[i].code != 0; i++) {
		if (http_status[i].code == code) {
			return (http_status[i].mesg);
		}
	}
	return ("Unknown HTTP Status");
}

const char *
nni_http_get_reason(nng_http *conn)
{
	return (conn->rsn ? conn->rsn : nni_http_reason(conn->code));
}

void
nni_http_set_status(nng_http *conn, nng_http_status status, const char *reason)
{
	conn->code = status;
	char *dup  = NULL;
	if (reason != NULL) {
		if (strcmp(reason, nni_http_reason(conn->code)) == 0) {
			dup = NULL;
		} else {
			// This might fail, but if it does, we will just
			// use the built in reason, which should not
			// fundamentally affect semantics.  This allows us to
			// make this function void, and avoid some error
			// handling.
			dup = nni_strdup(reason);
		}
	}
	nni_strfree(conn->rsn);
	conn->rsn = dup;
}

bool
nni_http_is_error(nng_http *conn)
{
	return (conn->iserr);
}

static int
http_conn_set_error(nng_http *conn, nng_http_status status, const char *reason,
    const char *body, const char *redirect)
{
	char        content[1024];
	const char *prefix = "<!DOCTYPE html>\n"
	                     "<html><head><title>%d %s</title>\n"
	                     "<style>"
	                     "body { font-family: Arial, sans serif; "
	                     "text-align: center }\n"
	                     "h1 { font-size: 36px; }"
	                     "span { background-color: gray; color: white; "
	                     "padding: 7px; "
	                     "border-radius: 5px }"
	                     "h2 { font-size: 24px; }"
	                     "p { font-size: 20px; }"
	                     "</style></head>"
	                     "<body><p>&nbsp;</p>"
	                     "<h1><span>%d</span></h1>"
	                     "<h2>%s</h2><p>";
	const char *suffix = "</p></body></html>";

	conn->iserr = true;

	nni_http_set_status(conn, status, reason);
	reason = nni_http_get_reason(conn);

	if (body == NULL) {
		snprintf(content, sizeof(content), prefix, status, reason,
		    status, reason);
		size_t avail = sizeof(content) - strlen(content);

		if (redirect != NULL && strlen(redirect) > 200 &&
		    strlen(reason) < 40) {
			// URL is too long for buffer and unlikely to be useful
			// to humans anyway.  600 bytes will fit in the 1K
			// buffer without issue.  (Our prelude and trailer are
			// less than 400 bytes.)
			snprintf(content + strlen(content), avail,
			    "You should be automatically redirected.");
			avail = sizeof(content) - strlen(content);
		} else if (redirect != NULL) {
			// TODO: redirect should be URL encoded.
			snprintf(content + strlen(content), avail,
			    "You should be automatically redirected to <a "
			    "href=\"%s\">%s</a>.",
			    redirect, redirect);
			avail = sizeof(content) - strlen(content);
		}
		snprintf(content + strlen(content), avail, "%s", suffix);
		body = content;
	}
	if (strlen(body) > 0) {
		nni_http_set_content_type(conn, "text/html; charset=UTF-8");
		// if the follow fails, live with it (ENOMEM, so no body).
		(void) nni_http_copy_body(conn, body, strlen(body));
	}
	return (0);
}

nng_err
nni_http_set_error(nng_http *conn, nng_http_status status, const char *reason,
    const char *body)
{
	return (http_conn_set_error(conn, status, reason, body, NULL));
}

nng_err
nni_http_set_redirect(nng_http *conn, nng_http_status status,
    const char *reason, const char *redirect)
{
	char *loc;
	bool  static_value = false;

	// The only users of this api, call do not use the URL buffer after
	// doing so, so we can optimize and use that for most redirections (no
	// more allocs!)
	if (strlen(redirect) < sizeof(conn->ubuf)) {
		snprintf(conn->ubuf, sizeof(conn->ubuf), "%s", redirect);
		loc          = conn->ubuf;
		static_value = true;
	} else if ((loc = nni_strdup(redirect)) == NULL) {
		return (NNG_ENOMEM);
	}
	(void) nni_http_del_header(conn, "Location");
	nni_list_node_remove(&conn->location.node);
	nni_http_free_header(&conn->location);
	conn->location.name         = "Location";
	conn->location.value        = loc;
	conn->location.static_name  = true;
	conn->location.static_value = static_value;
	nni_list_prepend(&conn->res.data.hdrs, &conn->location);
	return (http_conn_set_error(conn, status, reason, NULL, redirect));
}

void
nni_http_set_host(nng_http *conn, const char *host)
{
	if (host != conn->host) {
		snprintf(conn->host, sizeof(conn->host), "%s", host);
	}
	nni_list_node_remove(&conn->host_header.node);
	conn->host_header.name         = "Host";
	conn->host_header.value        = conn->host;
	conn->host_header.static_name  = true;
	conn->host_header.static_value = true;
	conn->host_header.alloc_header = false;
	nni_list_prepend(&conn->req.data.hdrs, &conn->host_header);
}

void
nni_http_set_content_length(nng_http *conn, size_t size)
{
	nni_http_entity *data =
	    conn->client ? &conn->req.data : &conn->res.data;

	snprintf(data->clen, sizeof(data->clen), "%lu", (unsigned long) size);
	nni_http_set_static_header(
	    conn, &data->content_length, "Content-Length", data->clen);
}

void
nni_http_set_content_type(nng_http *conn, const char *ctype)
{
	nni_http_entity *data =
	    conn->client ? &conn->req.data : &conn->res.data;
	snprintf(data->ctype, sizeof(data->ctype), "%s", ctype);
	nni_http_set_static_header(
	    conn, &data->content_type, "Content-Type", data->ctype);
}

const char *
nni_http_get_uri(nng_http *conn)
{
	return ((conn->uri && conn->uri[0]) ? conn->uri : "/");
}

nng_err
nni_http_set_uri(nng_http *conn, const char *uri, const char *query)
{
	size_t      needed;
	const char *fmt;

	if (query != NULL) {
		fmt    = strchr(uri, '?') != NULL ? "%s&%s" : "%s?%s";
		needed = strlen(uri) + strlen(query) + 1;
	} else {
		fmt    = "%s%s";
		query  = "";
		needed = strlen(uri);
	}

	if (conn->uri != NULL && (strcmp(uri, conn->uri) == 0) &&
	    strlen(query) == 0) {
		// no change, do nothing
		return (NNG_OK);
	}
	if (conn->uri != NULL && conn->uri != conn->ubuf) {
		nni_strfree(conn->uri);
	}

	// fast path, small size URI fits in our buffer
	if (needed < sizeof(conn->ubuf)) {
		snprintf(conn->ubuf, sizeof(conn->ubuf), fmt, uri, query);
		conn->uri = conn->ubuf;
		return (NNG_OK);
	}

	// too big, we have to allocate it (slow path)
	if (nni_asprintf(&conn->uri, fmt, uri, query) != 0) {
		return (NNG_ENOMEM);
	}
	return (NNG_OK);
}

static nng_err
http_set_header(nng_http *conn, const char *key, const char *val)
{
	nni_http_entity *data =
	    conn->client ? &conn->req.data : &conn->res.data;
	http_header *h;

	NNI_LIST_FOREACH (&data->hdrs, h) {
		if (nni_strcasecmp(key, h->name) == 0) {
			char *news;
			if ((news = nni_strdup(val)) == NULL) {
				return (NNG_ENOMEM);
			}
			if (!h->static_value) {
				nni_strfree(h->value);
				h->value = NULL;
			}
			h->value = news;
			return (NNG_OK);
		}
	}

	if ((h = NNI_ALLOC_STRUCT(h)) == NULL) {
		return (NNG_ENOMEM);
	}
	h->alloc_header = true;
	if ((h->name = nni_strdup(key)) == NULL) {
		NNI_FREE_STRUCT(h);
		return (NNG_ENOMEM);
	}
	if ((h->value = nni_strdup(val)) == NULL) {
		nni_strfree(h->name);
		NNI_FREE_STRUCT(h);
		return (NNG_ENOMEM);
	}
	nni_list_append(&data->hdrs, h);
	return (NNG_OK);
}

static nng_err
http_add_header(nng_http *conn, const char *key, const char *val)
{
	nni_http_entity *data =
	    conn->client ? &conn->req.data : &conn->res.data;
	http_header *h;
	NNI_LIST_FOREACH (&data->hdrs, h) {
		if (nni_strcasecmp(key, h->name) == 0) {
			char *news;
			int   rv;
			rv = nni_asprintf(&news, "%s, %s", h->value, val);
			if (rv != NNG_OK) {
				return (rv);
			}
			if (!h->static_value) {
				nni_strfree(h->value);
			}
			h->value = news;
			return (NNG_OK);
		}
	}

	if ((h = NNI_ALLOC_STRUCT(h)) == NULL) {
		return (NNG_ENOMEM);
	}
	h->alloc_header = true;
	if ((h->name = nni_strdup(key)) == NULL) {
		NNI_FREE_STRUCT(h);
		return (NNG_ENOMEM);
	}
	if ((h->value = nni_strdup(val)) == NULL) {
		nni_strfree(h->name);
		NNI_FREE_STRUCT(h);
		return (NNG_ENOMEM);
	}
	nni_list_append(&data->hdrs, h);
	return (NNG_OK);
}

static bool
http_set_known_header(nng_http *conn, const char *key, const char *val)
{
	if (nni_strcasecmp(key, "Content-Type") == 0) {
		nni_http_set_content_type(conn, val);
		return (true);
	}
	if (nni_strcasecmp(key, "Content-Length") == 0) {
		nni_http_entity *data =
		    conn->client ? &conn->req.data : &conn->res.data;
		snprintf(data->clen, sizeof(data->clen), "%s", val);
		nni_http_set_static_header(
		    conn, &data->content_length, "Content-Length", data->clen);
		return (true);
	}

	if (conn->client) {
		if (nni_strcasecmp(key, "Host") == 0) {
			nni_http_set_host(conn, val);
			return (true);
		}
	}
	return (false);
}

nng_err
nni_http_add_header(nng_http *conn, const char *key, const char *val)
{
	if (http_set_known_header(conn, key, val)) {
		return (NNG_OK);
	}

	return (http_add_header(conn, key, val));
}

void
nni_http_set_static_header(
    nng_http *conn, nni_http_header *h, const char *key, const char *val)
{
	nni_list *headers;
	if (conn->client) {
		headers = &conn->req.data.hdrs;
	} else {
		headers = &conn->res.data.hdrs;
	}

	nni_http_del_header(conn, key);
	nni_list_node_remove(&h->node);
	h->alloc_header = false;
	h->static_name  = true;
	h->static_value = true;
	h->name         = (char *) key;
	h->value        = (char *) val;
	nni_list_append(headers, h);
}

nng_err
nni_http_set_header(nng_http *conn, const char *key, const char *val)
{
	if (http_set_known_header(conn, key, val)) {
		return (0);
	}
	return (http_set_header(conn, key, val));
}

static bool
http_del_header_one(nni_list *hdrs, const char *key)
{
	http_header *h;
	NNI_LIST_FOREACH (hdrs, h) {
		if (nni_strcasecmp(key, h->name) == 0) {
			nni_http_free_header(h);
			return (true);
		}
	}
	return (false);
}

void
nni_http_del_header(nng_http *conn, const char *key)
{
	nni_list *hdrs =
	    conn->client ? &conn->req.data.hdrs : &conn->res.data.hdrs;
	while (http_del_header_one(hdrs, key)) {
		continue;
	}
}

static const char *
http_get_header(const nni_list *hdrs, const char *key)
{
	http_header *h;
	NNI_LIST_FOREACH (hdrs, h) {
		if (nni_strcasecmp(h->name, key) == 0) {
			return (h->value);
		}
	}
	return (NULL);
}

static bool
http_next_header(
    const nni_list *hdrs, const char **key, const char **val, void **ptr)
{
	http_header *h;

	if (*ptr == NULL) {
		h = nni_list_first(hdrs);
	} else {
		h = nni_list_next(hdrs, *ptr);
	}
	if (h == NULL) {
		return (false);
	}

	*ptr = h;
	*key = h->name;
	*val = h->value;
	return (true);
}

bool
nni_http_next_header(
    nng_http *conn, const char **key, const char **val, void **ptr)
{
	if (conn->client) {
		return (http_next_header(&conn->res.data.hdrs, key, val, ptr));
	} else {
		return (http_next_header(&conn->req.data.hdrs, key, val, ptr));
	}
}

const char *
nni_http_get_header(nng_http *conn, const char *key)
{
	if (conn->client) {
		return (http_get_header(&conn->res.data.hdrs, key));
	} else {
		return (http_get_header(&conn->req.data.hdrs, key));
	}
}

void
nni_http_get_body(nng_http *conn, void **datap, size_t *sizep)
{
	if (conn->client) {
		*datap = conn->res.data.data;
		*sizep = conn->res.data.size;
	} else {
		*datap = conn->req.data.data;
		*sizep = conn->req.data.size;
	}
}

static void
http_set_data(nni_http_entity *entity, const void *data, size_t size)
{
	if (entity->own) {
		nni_free(entity->data, entity->size);
	}
	entity->data = (void *) data;
	entity->size = size;
	entity->own  = false;
}

static nng_err
http_alloc_data(nni_http_entity *entity, size_t size)
{
	void *newdata;
	if (size != 0) {
		if ((newdata = nni_zalloc(size)) == NULL) {
			return (NNG_ENOMEM);
		}
	}
	http_set_data(entity, newdata, size);
	entity->own = true;
	return (NNG_OK);
}

static nng_err
http_copy_data(nni_http_entity *entity, const void *data, size_t size)
{
	nng_err rv;
	if ((rv = http_alloc_data(entity, size)) == 0) {
		memcpy(entity->data, data, size);
	}
	return (rv);
}

void
nni_http_set_body(nng_http *conn, void *data, size_t size)
{
	if (conn->client) {
		http_set_data(&conn->req.data, data, size);
	} else {
		http_set_data(&conn->res.data, data, size);
	}
	nni_http_set_content_length(conn, size);
}

void
nni_http_prune_body(nng_http *conn)
{
	// prune body but leave content-length header intact.
	// This is for HEAD.
	if (conn->client) {
		http_set_data(&conn->req.data, NULL, 0);
	} else {
		http_set_data(&conn->res.data, NULL, 0);
	}
}

nng_err
nni_http_copy_body(nng_http *conn, const void *data, size_t size)
{
	nng_err rv;
	if (conn->client) {
		rv = http_copy_data(&conn->req.data, data, size);
	} else {
		rv = http_copy_data(&conn->res.data, data, size);
	}
	if (rv == NNG_OK) {
		nni_http_set_content_length(conn, size);
	}
	return (rv);
}

int
nni_http_conn_getopt(
    nni_http_conn *conn, const char *name, void *buf, size_t *szp, nni_type t)
{
	int rv;
	nni_mtx_lock(&conn->mtx);
	if (conn->closed) {
		rv = NNG_ECLOSED;
	} else {
		rv = nni_stream_get(conn->sock, name, buf, szp, t);
	}
	nni_mtx_unlock(&conn->mtx);
	return (rv);
}

nng_err
nni_http_conn_peer_cert(nni_http_conn *conn, nng_tls_cert **certp)
{
	int rv;
	nni_mtx_lock(&conn->mtx);
	if (conn->closed) {
		rv = NNG_ECLOSED;
	} else {
		rv = nng_stream_peer_cert(conn->sock, certp);
	}
	nni_mtx_unlock(&conn->mtx);
	return (rv);
}

void
nni_http_conn_fini(nni_http_conn *conn)
{
	nni_aio_stop(&conn->wr_aio);
	nni_aio_stop(&conn->rd_aio);

	nni_mtx_lock(&conn->mtx);
	http_close(conn);
	if (conn->sock != NULL) {
		nng_stream_free(conn->sock);
		conn->sock = NULL;
	}
	nni_mtx_unlock(&conn->mtx);

	nni_aio_fini(&conn->wr_aio);
	nni_aio_fini(&conn->rd_aio);
	nni_http_conn_reset(conn);
	nni_free(conn->buf, conn->bufsz);
	nni_mtx_fini(&conn->mtx);
	NNI_FREE_STRUCT(conn);
}

static nng_err
http_init(nni_http_conn **connp, nng_stream *data, bool client)
{
	nni_http_conn *conn;

	if ((conn = NNI_ALLOC_STRUCT(conn)) == NULL) {
		return (NNG_ENOMEM);
	}
	conn->client = client;
	nni_mtx_init(&conn->mtx);
	nni_aio_list_init(&conn->rdq);
	nni_aio_list_init(&conn->wrq);
	nni_http_req_init(&conn->req);
	nni_http_res_init(&conn->res);
	nni_http_set_version(conn, NNG_HTTP_VERSION_1_1);
	nni_http_set_method(conn, "GET");

	if ((conn->buf = nni_alloc(HTTP_BUFSIZE)) == NULL) {
		nni_http_conn_fini(conn);
		return (NNG_ENOMEM);
	}
	conn->bufsz = HTTP_BUFSIZE;

	nni_aio_init(&conn->wr_aio, http_wr_cb, conn);
	nni_aio_init(&conn->rd_aio, http_rd_cb, conn);

	conn->sock = data;

	*connp = conn;

	return (NNG_OK);
}

nng_err
nni_http_init(nng_http **connp, nng_stream *stream, bool client)
{
	nng_err rv;
	if ((rv = http_init(connp, stream, client)) != NNG_OK) {
		nng_stream_free(stream);
	}
	return (rv);
}

// private to the HTTP framework, used on the server
bool
nni_http_res_sent(nni_http_conn *conn)
{
	return (conn->res_sent);
}

bool
nni_http_parsed(nng_http *conn)
{
	return (conn->client ? conn->res.data.parsed : conn->req.data.parsed);
}
