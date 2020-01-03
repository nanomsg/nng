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

#include <ctype.h>
#include <stdbool.h>
#include <string.h>

#include "core/nng_impl.h"
#include "supplemental/tls/tls_api.h"

#include "http_api.h"

#include <nng/supplemental/tls/tls.h>

// We insist that individual headers fit in 8K.
// If you need more than that, you need something we can't do.
#define HTTP_BUFSIZE 8192

// types of reads
enum read_flavor {
	HTTP_RD_RAW,
	HTTP_RD_FULL,
	HTTP_RD_REQ,
	HTTP_RD_RES,
	HTTP_RD_CHUNK,
};

enum write_flavor {
	HTTP_WR_RAW,
	HTTP_WR_FULL,
	HTTP_WR_REQ,
	HTTP_WR_RES,
};

#define SET_RD_FLAVOR(aio, f) \
	nni_aio_set_prov_extra(aio, 0, ((void *) (intptr_t)(f)))
#define GET_RD_FLAVOR(aio) (int) ((intptr_t) nni_aio_get_prov_extra(aio, 0))
#define SET_WR_FLAVOR(aio, f) \
	nni_aio_set_prov_extra(aio, 0, ((void *) (intptr_t)(f)))
#define GET_WR_FLAVOR(aio) (int) ((intptr_t) nni_aio_get_prov_extra(aio, 0))

struct nng_http_conn {
	nng_stream *sock;
	void *      ctx;
	bool        closed;
	nni_list    rdq; // high level http read requests
	nni_list    wrq; // high level http write requests

	nni_aio *rd_uaio; // user aio for read
	nni_aio *wr_uaio; // user aio for write
	nni_aio *rd_aio;  // bottom half read operations
	nni_aio *wr_aio;  // bottom half write operations

	nni_mtx mtx;

	uint8_t *rd_buf;
	size_t   rd_get;
	size_t   rd_put;
	size_t   rd_bufsz;
};

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
	nni_aio_close(conn->wr_aio);
	nni_aio_close(conn->rd_aio);

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

// http_rd_buf attempts to satisfy the read from data in the buffer.
static int
http_rd_buf(nni_http_conn *conn, nni_aio *aio)
{
	size_t   cnt = conn->rd_put - conn->rd_get;
	size_t   n;
	uint8_t *rbuf = conn->rd_buf;
	int      rv;
	bool     raw = false;
	nni_iov *iov;
	unsigned niov;

	rbuf += conn->rd_get;

	switch (GET_RD_FLAVOR(aio)) {
	case HTTP_RD_RAW:
		raw = true; // FALLTHROUGH
	case HTTP_RD_FULL:
		nni_aio_get_iov(aio, &niov, &iov);
		while ((niov != 0) && (cnt != 0)) {
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
				niov--;
				iov = &iov[1];
			}
		}

		nni_aio_set_iov(aio, niov, iov);

		if ((niov == 0) || (raw && (nni_aio_count(aio) != 0))) {
			// Finished the read.  (We are finished if we either
			// got *all* the data, or we got *some* data for
			// a raw read.)
			return (0);
		}

		// No more data left in the buffer, so use a physio.
		// (Note that we get here if we either have not completed
		// a full transaction on a FULL read, or were not even able
		// to get *any* data for a partial RAW read.)
		nni_aio_set_data(conn->rd_aio, 1, NULL);
		nni_aio_set_iov(conn->rd_aio, niov, iov);
		nng_stream_recv(conn->sock, conn->rd_aio);
		return (NNG_EAGAIN);

	case HTTP_RD_REQ:
		rv = nni_http_req_parse(
		    nni_aio_get_prov_extra(aio, 1), rbuf, cnt, &n);
		conn->rd_get += n;
		if (conn->rd_get == conn->rd_put) {
			conn->rd_get = conn->rd_put = 0;
		}
		if (rv == NNG_EAGAIN) {
			nni_iov iov1;
			iov1.iov_buf = conn->rd_buf + conn->rd_put;
			iov1.iov_len = conn->rd_bufsz - conn->rd_put;
			nni_aio_set_iov(conn->rd_aio, 1, &iov1);
			nni_aio_set_data(conn->rd_aio, 1, aio);
			nng_stream_recv(conn->sock, conn->rd_aio);
		}
		return (rv);

	case HTTP_RD_RES:
		rv = nni_http_res_parse(
		    nni_aio_get_prov_extra(aio, 1), rbuf, cnt, &n);
		conn->rd_get += n;
		if (conn->rd_get == conn->rd_put) {
			conn->rd_get = conn->rd_put = 0;
		}
		if (rv == NNG_EAGAIN) {
			nni_iov iov1;
			iov1.iov_buf = conn->rd_buf + conn->rd_put;
			iov1.iov_len = conn->rd_bufsz - conn->rd_put;
			nni_aio_set_iov(conn->rd_aio, 1, &iov1);
			nni_aio_set_data(conn->rd_aio, 1, aio);
			nng_stream_recv(conn->sock, conn->rd_aio);
		}
		return (rv);

	case HTTP_RD_CHUNK:
		rv = nni_http_chunks_parse(
		    nni_aio_get_prov_extra(aio, 1), rbuf, cnt, &n);
		conn->rd_get += n;
		if (conn->rd_get == conn->rd_put) {
			conn->rd_get = conn->rd_put = 0;
		}
		if (rv == NNG_EAGAIN) {
			nni_iov iov1;
			iov1.iov_buf = conn->rd_buf + conn->rd_put;
			iov1.iov_len = conn->rd_bufsz - conn->rd_put;
			nni_aio_set_iov(conn->rd_aio, 1, &iov1);
			nni_aio_set_data(conn->rd_aio, 1, aio);
			nng_stream_recv(conn->sock, conn->rd_aio);
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
			nni_aio_finish(aio, 0, nni_aio_count(aio));
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
	nni_aio *      aio  = conn->rd_aio;
	nni_aio *      uaio;
	size_t         cnt;
	int            rv;
	unsigned       niov;
	nni_iov *      iov;

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
	if ((uaio = nni_aio_get_data(aio, 1)) != NULL) {
		conn->rd_put += cnt;
		NNI_ASSERT(conn->rd_put <= conn->rd_bufsz);
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
http_rd_cancel(nni_aio *aio, void *arg, int rv)
{
	nni_http_conn *conn = arg;

	nni_mtx_lock(&conn->mtx);
	if (aio == conn->rd_uaio) {
		conn->rd_uaio = NULL;
		nni_aio_abort(conn->rd_aio, rv);
		nni_aio_finish_error(aio, rv);
	} else if (nni_aio_list_active(aio)) {
		nni_aio_list_remove(aio);
		nni_aio_finish_error(aio, rv);
	}
	nni_mtx_unlock(&conn->mtx);
}

static void
http_rd_submit(nni_http_conn *conn, nni_aio *aio)
{
	int rv;

	if (nni_aio_begin(aio) != 0) {
		return;
	}
	if (conn->closed) {
		nni_aio_finish_error(aio, NNG_ECLOSED);
		return;
	}
	if ((rv = nni_aio_schedule(aio, http_rd_cancel, conn)) != 0) {
		nni_aio_finish_error(aio, rv);
		return;
	}
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
	nni_aio_set_iov(conn->wr_aio, niov, iov);
	nng_stream_send(conn->sock, conn->wr_aio);
}

static void
http_wr_cb(void *arg)
{
	nni_http_conn *conn = arg;
	nni_aio *      aio  = conn->wr_aio;
	nni_aio *      uaio;
	int            rv;
	size_t         n;

	nni_mtx_lock(&conn->mtx);

	uaio = conn->wr_uaio;

	if ((rv = nni_aio_result(aio)) != 0) {
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

	if (GET_WR_FLAVOR(uaio) == HTTP_WR_RAW) {
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
	nni_aio_finish(uaio, 0, nni_aio_count(uaio));

	// Start next write if another is ready.
	http_wr_start(conn);

	nni_mtx_unlock(&conn->mtx);
}

static void
http_wr_cancel(nni_aio *aio, void *arg, int rv)
{
	nni_http_conn *conn = arg;

	nni_mtx_lock(&conn->mtx);
	if (aio == conn->wr_uaio) {
		conn->wr_uaio = NULL;
		nni_aio_abort(conn->wr_aio, rv);
		nni_aio_finish_error(aio, rv);
	} else if (nni_aio_list_active(aio)) {
		nni_aio_list_remove(aio);
		nni_aio_finish_error(aio, rv);
	}
	nni_mtx_unlock(&conn->mtx);
}

static void
http_wr_submit(nni_http_conn *conn, nni_aio *aio)
{
	int rv;

	if (nni_aio_begin(aio) != 0) {
		return;
	}
	if (conn->closed) {
		nni_aio_finish_error(aio, NNG_ECLOSED);
		return;
	}
	if ((rv = nni_aio_schedule(aio, http_wr_cancel, conn)) != 0) {
		nni_aio_finish_error(aio, rv);
		return;
	}
	nni_list_append(&conn->wrq, aio);

	if (conn->wr_uaio == NULL) {
		http_wr_start(conn);
	}
}

void
nni_http_read_req(nni_http_conn *conn, nni_http_req *req, nni_aio *aio)
{
	SET_RD_FLAVOR(aio, HTTP_RD_REQ);
	nni_aio_set_prov_extra(aio, 1, req);

	nni_mtx_lock(&conn->mtx);
	http_rd_submit(conn, aio);
	nni_mtx_unlock(&conn->mtx);
}

void
nni_http_read_res(nni_http_conn *conn, nni_http_res *res, nni_aio *aio)
{
	SET_RD_FLAVOR(aio, HTTP_RD_RES);
	nni_aio_set_prov_extra(aio, 1, res);

	nni_mtx_lock(&conn->mtx);
	http_rd_submit(conn, aio);
	nni_mtx_unlock(&conn->mtx);
}

void
nni_http_read_chunks(nni_http_conn *conn, nni_http_chunks *cl, nni_aio *aio)
{
	SET_RD_FLAVOR(aio, HTTP_RD_CHUNK);
	nni_aio_set_prov_extra(aio, 1, cl);

	nni_mtx_lock(&conn->mtx);
	http_rd_submit(conn, aio);
	nni_mtx_unlock(&conn->mtx);
}

void
nni_http_read_full(nni_http_conn *conn, nni_aio *aio)
{
	SET_RD_FLAVOR(aio, HTTP_RD_FULL);
	nni_aio_set_prov_extra(aio, 1, NULL);

	nni_mtx_lock(&conn->mtx);
	http_rd_submit(conn, aio);
	nni_mtx_unlock(&conn->mtx);
}

void
nni_http_read(nni_http_conn *conn, nni_aio *aio)
{
	SET_RD_FLAVOR(aio, HTTP_RD_RAW);
	nni_aio_set_prov_extra(aio, 1, NULL);

	nni_mtx_lock(&conn->mtx);
	http_rd_submit(conn, aio);
	nni_mtx_unlock(&conn->mtx);
}

void
nni_http_write_req(nni_http_conn *conn, nni_http_req *req, nni_aio *aio)
{
	int     rv;
	void *  buf;
	size_t  bufsz;
	void *  data;
	size_t  size;
	nni_iov iov[2];
	int     niov;

	if ((rv = nni_http_req_get_buf(req, &buf, &bufsz)) != 0) {
		nni_aio_finish_error(aio, rv);
		return;
	}
	nni_http_req_get_data(req, &data, &size);
	niov           = 1;
	iov[0].iov_len = bufsz;
	iov[0].iov_buf = buf;
	if ((size > 0) && (data != NULL)) {
		niov++;
		iov[1].iov_len = size;
		iov[1].iov_buf = data;
	}
	nni_aio_set_iov(aio, niov, iov);

	SET_WR_FLAVOR(aio, HTTP_WR_REQ);

	nni_mtx_lock(&conn->mtx);
	http_wr_submit(conn, aio);
	nni_mtx_unlock(&conn->mtx);
}

void
nni_http_write_res(nni_http_conn *conn, nni_http_res *res, nni_aio *aio)
{
	int     rv;
	void *  buf;
	size_t  bufsz;
	void *  data;
	size_t  size;
	nni_iov iov[2];
	int     niov;

	if ((rv = nni_http_res_get_buf(res, &buf, &bufsz)) != 0) {
		nni_aio_finish_error(aio, rv);
		return;
	}
	nni_http_res_get_data(res, &data, &size);
	niov           = 1;
	iov[0].iov_len = bufsz;
	iov[0].iov_buf = buf;
	if ((size > 0) && (data != NULL)) {
		niov++;
		iov[1].iov_len = size;
		iov[1].iov_buf = data;
	}
	nni_aio_set_iov(aio, niov, iov);

	SET_WR_FLAVOR(aio, HTTP_WR_RES);

	nni_mtx_lock(&conn->mtx);
	http_wr_submit(conn, aio);
	nni_mtx_unlock(&conn->mtx);
}

void
nni_http_write(nni_http_conn *conn, nni_aio *aio)
{
	SET_WR_FLAVOR(aio, HTTP_WR_RAW);

	nni_mtx_lock(&conn->mtx);
	http_wr_submit(conn, aio);
	nni_mtx_unlock(&conn->mtx);
}

void
nni_http_write_full(nni_http_conn *conn, nni_aio *aio)
{
	SET_WR_FLAVOR(aio, HTTP_WR_FULL);

	nni_mtx_lock(&conn->mtx);
	http_wr_submit(conn, aio);
	nni_mtx_unlock(&conn->mtx);
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
		rv = nni_stream_getx(conn->sock, name, buf, szp, t);
	}
	nni_mtx_unlock(&conn->mtx);
	return (rv);
}

int
nni_http_conn_setopt(nni_http_conn *conn, const char *name, const void *buf,
    size_t sz, nni_type t)
{
	int rv;
	nni_mtx_lock(&conn->mtx);
	if (conn->closed) {
		rv = NNG_ECLOSED;
	} else {
		rv = nni_stream_setx(conn->sock, name, buf, sz, t);
	}
	nni_mtx_unlock(&conn->mtx);
	return (rv);
}

void
nni_http_conn_fini(nni_http_conn *conn)
{
	nni_aio_stop(conn->wr_aio);
	nni_aio_stop(conn->rd_aio);

	nni_mtx_lock(&conn->mtx);
	http_close(conn);
	if (conn->sock != NULL) {
		nng_stream_free(conn->sock);
		conn->sock = NULL;
	}
	nni_mtx_unlock(&conn->mtx);

	nni_aio_free(conn->wr_aio);
	nni_aio_free(conn->rd_aio);
	nni_free(conn->rd_buf, conn->rd_bufsz);
	nni_mtx_fini(&conn->mtx);
	NNI_FREE_STRUCT(conn);
}

static int
http_init(nni_http_conn **connp, nng_stream *data)
{
	nni_http_conn *conn;
	int            rv;

	if ((conn = NNI_ALLOC_STRUCT(conn)) == NULL) {
		return (NNG_ENOMEM);
	}
	nni_mtx_init(&conn->mtx);
	nni_aio_list_init(&conn->rdq);
	nni_aio_list_init(&conn->wrq);

	if ((conn->rd_buf = nni_alloc(HTTP_BUFSIZE)) == NULL) {
		nni_http_conn_fini(conn);
		return (NNG_ENOMEM);
	}
	conn->rd_bufsz = HTTP_BUFSIZE;

	if (((rv = nni_aio_alloc(&conn->wr_aio, http_wr_cb, conn)) != 0) ||
	    ((rv = nni_aio_alloc(&conn->rd_aio, http_rd_cb, conn)) != 0)) {
		nni_http_conn_fini(conn);
		return (rv);
	}

	conn->sock = data;

	*connp = conn;

	return (0);
}

int
nni_http_conn_init(nni_http_conn **connp, nng_stream *stream)
{
	int rv;
	if ((rv = http_init(connp, stream)) != 0) {
		nng_stream_free(stream);
	}
	return (rv);
}
