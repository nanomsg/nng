//
// Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <stdbool.h>
#include <string.h>

#include "core/nng_impl.h"
#include "supplemental/tls/tls.h"

#include "http.h"

// We insist that individual headers fit in 8K.
// If you need more than that, you need something we can't do.
#define HTTP_BUFSIZE 8192

// types of reads
enum read_flavor {
	HTTP_RD_RAW,
	HTTP_RD_FULL,
	HTTP_RD_REQ,
	HTTP_RD_RES,
};

enum write_flavor {
	HTTP_WR_RAW,
	HTTP_WR_FULL,
	HTTP_WR_REQ,
	HTTP_WR_RES,
};

typedef struct nni_http_tran {
	void (*h_read)(void *, nni_aio *);
	void (*h_write)(void *, nni_aio *);
	int (*h_sock_addr)(void *, nni_sockaddr *);
	int (*h_peer_addr)(void *, nni_sockaddr *);
	bool (*h_verified)(void *);
	void (*h_close)(void *);
	void (*h_fini)(void *);
} nni_http_tran;

#define SET_RD_FLAVOR(aio, f) (aio)->a_prov_extra[0] = ((void *) (intptr_t)(f))
#define GET_RD_FLAVOR(aio) (int) ((intptr_t) aio->a_prov_extra[0])
#define SET_WR_FLAVOR(aio, f) (aio)->a_prov_extra[0] = ((void *) (intptr_t)(f))
#define GET_WR_FLAVOR(aio) (int) ((intptr_t) aio->a_prov_extra[0])

struct nni_http {
	void *sock;
	void (*rd)(void *, nni_aio *);
	void (*wr)(void *, nni_aio *);
	int (*sock_addr)(void *, nni_sockaddr *);
	int (*peer_addr)(void *, nni_sockaddr *);
	bool (*verified)(void *);
	void (*close)(void *);
	void (*fini)(void *);

	bool closed;

	nni_list rdq; // high level http read requests
	nni_list wrq; // high level http write requests

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

static void
http_close(nni_http *http)
{
	// Call with lock held.
	nni_aio *aio;

	if (http->closed) {
		return;
	}

	http->closed = true;
	if (nni_list_first(&http->wrq)) {
		nni_aio_cancel(http->wr_aio, NNG_ECLOSED);
		// Abort all operations except the one in flight.
		while ((aio = nni_list_last(&http->wrq)) !=
		    nni_list_first(&http->wrq)) {
			nni_aio_list_remove(aio);
			nni_aio_finish_error(aio, NNG_ECLOSED);
		}
	}
	if (nni_list_first(&http->rdq)) {
		nni_aio_cancel(http->rd_aio, NNG_ECLOSED);
		while ((aio = nni_list_last(&http->rdq)) !=
		    nni_list_first(&http->rdq)) {
			nni_aio_list_remove(aio);
			nni_aio_finish_error(aio, NNG_ECLOSED);
		}
	}

	if (http->sock != NULL) {
		http->close(http->sock);
	}
}

void
nni_http_close(nni_http *http)
{
	nni_mtx_lock(&http->mtx);
	http_close(http);
	nni_mtx_unlock(&http->mtx);
}

// http_rd_buf attempts to satisfy the read from data in the buffer.
static int
http_rd_buf(nni_http *http, nni_aio *aio)
{
	size_t   cnt = http->rd_put - http->rd_get;
	size_t   n;
	uint8_t *rbuf = http->rd_buf;
	int      i;
	int      rv;
	bool     raw = false;

	rbuf += http->rd_get;

	switch (GET_RD_FLAVOR(aio)) {
	case HTTP_RD_RAW:
		raw = true; // FALLTHROUGH
	case HTTP_RD_FULL:
		for (i = 0; (aio->a_niov != 0) && (cnt != 0); i++) {
			// Pull up data from the buffer if possible.
			n = aio->a_iov[0].iov_len;
			if (n > cnt) {
				n = cnt;
			}
			memcpy(aio->a_iov[0].iov_buf, rbuf, n);
			aio->a_iov[0].iov_len -= n;
			aio->a_iov[0].iov_buf += n;
			http->rd_get += n;
			rbuf += n;
			aio->a_count += n;
			cnt -= n;

			if (aio->a_iov[0].iov_len == 0) {
				aio->a_niov--;
				for (i = 0; i < aio->a_niov; i++) {
					aio->a_iov[i] = aio->a_iov[i + 1];
				}
			}
		}

		if ((aio->a_niov == 0) || (raw && (aio->a_count != 0))) {
			// Finished the read.  (We are finished if we either
			// got *all* the data, or we got *some* data for
			// a raw read.)
			return (0);
		}

		// No more data left in the buffer, so use a physio.
		// (Note that we get here if we either have not completed
		// a full transaction on a FULL read, or were not even able
		// to get *any* data for a partial RAW read.)
		for (i = 0; i < aio->a_niov; i++) {
			http->rd_aio->a_iov[i] = aio->a_iov[i];
		}
		nni_aio_set_data(http->rd_aio, 1, NULL);
		http->rd_aio->a_niov = aio->a_niov;
		http->rd(http->sock, http->rd_aio);
		return (NNG_EAGAIN);

	case HTTP_RD_REQ:
		rv = nni_http_req_parse(aio->a_prov_extra[1], rbuf, cnt, &n);
		http->rd_get += n;
		if (http->rd_get == http->rd_put) {
			http->rd_get = http->rd_put = 0;
		}
		if (rv == NNG_EAGAIN) {
			http->rd_aio->a_niov = 1;
			http->rd_aio->a_iov[0].iov_buf =
			    http->rd_buf + http->rd_put;
			http->rd_aio->a_iov[0].iov_len =
			    http->rd_bufsz - http->rd_put;
			nni_aio_set_data(http->rd_aio, 1, aio);
			http->rd(http->sock, http->rd_aio);
		}
		return (rv);

	case HTTP_RD_RES:
		rv = nni_http_res_parse(aio->a_prov_extra[1], rbuf, cnt, &n);
		http->rd_get += n;
		if (http->rd_get == http->rd_put) {
			http->rd_get = http->rd_put = 0;
		}
		if (rv == NNG_EAGAIN) {
			http->rd_aio->a_niov = 1;
			http->rd_aio->a_iov[0].iov_buf =
			    http->rd_buf + http->rd_put;
			http->rd_aio->a_iov[0].iov_len =
			    http->rd_bufsz - http->rd_put;
			nni_aio_set_data(http->rd_aio, 1, aio);
			http->rd(http->sock, http->rd_aio);
		}
		return (rv);
	}
	return (NNG_EINVAL);
}

static void
http_rd_start(nni_http *http)
{
	for (;;) {
		nni_aio *aio;
		int      rv;

		if ((aio = http->rd_uaio) == NULL) {
			if ((aio = nni_list_first(&http->rdq)) == NULL) {
				// No more stuff waiting for read.
				return;
			}
			nni_list_remove(&http->rdq, aio);
			http->rd_uaio = aio;
		}

		if (http->closed) {
			rv = NNG_ECLOSED;
		} else {
			rv = http_rd_buf(http, aio);
		}
		switch (rv) {
		case NNG_EAGAIN:
			return;
		case 0:
			http->rd_uaio = NULL;
			nni_aio_finish(aio, 0, aio->a_count);
			break;
		default:
			http->rd_uaio = NULL;
			nni_aio_finish_error(aio, rv);
			http_close(http);
			break;
		}
	}
}

static void
http_rd_cb(void *arg)
{
	nni_http *http = arg;
	nni_aio * aio  = http->rd_aio;
	nni_aio * uaio;
	size_t    cnt;
	int       rv;

	nni_mtx_lock(&http->mtx);

	if ((rv = nni_aio_result(aio)) != 0) {
		if ((uaio = http->rd_uaio) != NULL) {
			http->rd_uaio = NULL;
			nni_aio_finish_error(uaio, rv);
		}
		http_close(http);
		nni_mtx_unlock(&http->mtx);
		return;
	}

	cnt = nni_aio_count(aio);

	// If we were reading into the buffer, then advance location(s).
	if ((uaio = nni_aio_get_data(aio, 1)) != NULL) {
		http->rd_put += cnt;
		NNI_ASSERT(http->rd_put <= http->rd_bufsz);
		http_rd_start(http);
		nni_mtx_unlock(&http->mtx);
		return;
	}

	// Otherwise we are completing a USER request, and there should
	// be no data left in the user buffer.
	NNI_ASSERT(http->rd_get == http->rd_put);

	if ((uaio = http->rd_uaio) == NULL) {
		// This indicates that a read request was canceled.  This
		// can occur only when shutting down, really.
		nni_mtx_unlock(&http->mtx);
		return;
	}

	for (int i = 0; (uaio->a_niov != 0) && (cnt != 0); i++) {
		// Pull up data from the buffer if possible.
		size_t n = uaio->a_iov[0].iov_len;
		if (n > cnt) {
			n = cnt;
		}
		uaio->a_iov[0].iov_len -= n;
		uaio->a_iov[0].iov_buf += n;
		uaio->a_count += n;
		cnt -= n;

		if (uaio->a_iov[0].iov_len == 0) {
			uaio->a_niov--;
			for (i = 0; i < uaio->a_niov; i++) {
				uaio->a_iov[i] = uaio->a_iov[i + 1];
			}
		}
	}

	// Resubmit the start.  This will attempt to consume data
	// from the read buffer (there won't be any), and then either
	// complete the I/O (for HTTP_RD_RAW, or if there is nothing left),
	// or submit another physio.
	http_rd_start(http);
	nni_mtx_unlock(&http->mtx);
}

static void
http_rd_cancel(nni_aio *aio, int rv)
{
	nni_http *http = aio->a_prov_data;

	nni_mtx_lock(&http->mtx);
	if (aio == http->rd_uaio) {
		http->rd_uaio = NULL;
		nni_aio_cancel(http->rd_aio, rv);
		nni_aio_finish_error(aio, rv);
	} else if (nni_aio_list_active(aio)) {
		nni_aio_list_remove(aio);
		nni_aio_finish_error(aio, rv);
	}
	nni_mtx_unlock(&http->mtx);
}

static void
http_rd_submit(nni_http *http, nni_aio *aio)
{
	if (nni_aio_start(aio, http_rd_cancel, http) != 0) {
		return;
	}
	if (http->closed) {
		nni_aio_finish_error(aio, NNG_ECLOSED);
		return;
	}
	nni_list_append(&http->rdq, aio);
	if (http->rd_uaio == NULL) {
		http_rd_start(http);
	}
}

static void
http_wr_start(nni_http *http)
{
	nni_aio *aio;

	if ((aio = http->wr_uaio) == NULL) {
		if ((aio = nni_list_first(&http->wrq)) == NULL) {
			// No more stuff waiting for read.
			return;
		}
		nni_list_remove(&http->wrq, aio);
		http->wr_uaio = aio;
	}

	for (int i = 0; i < aio->a_niov; i++) {
		http->wr_aio->a_iov[i] = aio->a_iov[i];
	}
	http->wr_aio->a_niov = aio->a_niov;
	http->wr(http->sock, http->wr_aio);
}

static void
http_wr_cb(void *arg)
{
	nni_http *http = arg;
	nni_aio * aio  = http->wr_aio;
	nni_aio * uaio;
	int       rv;
	size_t    n;

	nni_mtx_lock(&http->mtx);

	uaio = http->wr_uaio;

	if ((rv = nni_aio_result(aio)) != 0) {
		// We failed to complete the aio.
		if (uaio != NULL) {
			http->wr_uaio = NULL;
			nni_aio_finish_error(uaio, rv);
		}
		http_close(http);
		nni_mtx_unlock(&http->mtx);
		return;
	}

	if (uaio == NULL) {
		// Write canceled?  This happens pretty much only during
		// shutdown/close, so we don't want to resume writing.
		// The stream is probably corrupted at this point anyway.
		nni_mtx_unlock(&http->mtx);
		return;
	}

	n = nni_aio_count(aio);
	uaio->a_count += n;
	if (GET_WR_FLAVOR(uaio) == HTTP_WR_RAW) {
		// For raw data, we just send partial completion
		// notices to the consumer.
		goto done;
	}
	while (n) {
		NNI_ASSERT(aio->a_niov != 0);

		if (aio->a_iov[0].iov_len > n) {
			aio->a_iov[0].iov_len -= n;
			aio->a_iov[0].iov_buf += n;
			break;
		}
		n -= aio->a_iov[0].iov_len;
		for (int i = 0; i < aio->a_niov; i++) {
			aio->a_iov[i] = aio->a_iov[i + 1];
		}
		aio->a_niov--;
	}
	if ((aio->a_niov != 0) && (aio->a_iov[0].iov_len != 0)) {
		// We have more to transmit - start another and leave
		// (we will get called again when it is done).
		http->wr(http->sock, aio);
		nni_mtx_unlock(&http->mtx);
		return;
	}

done:
	http->wr_uaio = NULL;
	nni_aio_finish(uaio, 0, uaio->a_count);

	// Start next write if another is ready.
	http_wr_start(http);

	nni_mtx_unlock(&http->mtx);
}

static void
http_wr_cancel(nni_aio *aio, int rv)
{
	nni_http *http = aio->a_prov_data;

	nni_mtx_lock(&http->mtx);
	if (aio == http->wr_uaio) {
		http->wr_uaio = NULL;
		nni_aio_cancel(http->wr_aio, rv);
		nni_aio_finish_error(aio, rv);
	} else if (nni_aio_list_active(aio)) {
		nni_aio_list_remove(aio);
		nni_aio_finish_error(aio, rv);
	}
	nni_mtx_unlock(&http->mtx);
}

static void
http_wr_submit(nni_http *http, nni_aio *aio)
{
	if (nni_aio_start(aio, http_wr_cancel, http) != 0) {
		return;
	}
	if (http->closed) {
		nni_aio_finish_error(aio, NNG_ECLOSED);
		return;
	}
	nni_list_append(&http->wrq, aio);
	if (http->wr_uaio == NULL) {
		http_wr_start(http);
	}
}

void
nni_http_read_req(nni_http *http, nni_http_req *req, nni_aio *aio)
{
	SET_RD_FLAVOR(aio, HTTP_RD_REQ);
	aio->a_prov_extra[1] = req;

	nni_mtx_lock(&http->mtx);
	http_rd_submit(http, aio);
	nni_mtx_unlock(&http->mtx);
}

void
nni_http_read_res(nni_http *http, nni_http_res *res, nni_aio *aio)
{
	SET_RD_FLAVOR(aio, HTTP_RD_RES);
	aio->a_prov_extra[1] = res;

	nni_mtx_lock(&http->mtx);
	http_rd_submit(http, aio);
	nni_mtx_unlock(&http->mtx);
}

void
nni_http_read_full(nni_http *http, nni_aio *aio)
{
	aio->a_count = 0;
	SET_RD_FLAVOR(aio, HTTP_RD_FULL);
	aio->a_prov_extra[1] = NULL;

	nni_mtx_lock(&http->mtx);
	http_rd_submit(http, aio);
	nni_mtx_unlock(&http->mtx);
}

void
nni_http_read(nni_http *http, nni_aio *aio)
{
	SET_RD_FLAVOR(aio, HTTP_RD_RAW);
	aio->a_prov_extra[1] = NULL;

	nni_mtx_lock(&http->mtx);
	http_rd_submit(http, aio);
	nni_mtx_unlock(&http->mtx);
}

void
nni_http_write_req(nni_http *http, nni_http_req *req, nni_aio *aio)
{
	int    rv;
	void * buf;
	size_t bufsz;

	if ((rv = nni_http_req_get_buf(req, &buf, &bufsz)) != 0) {
		nni_aio_finish_error(aio, rv);
		return;
	}
	aio->a_niov           = 1;
	aio->a_iov[0].iov_len = bufsz;
	aio->a_iov[0].iov_buf = buf;
	SET_WR_FLAVOR(aio, HTTP_WR_REQ);

	nni_mtx_lock(&http->mtx);
	http_wr_submit(http, aio);
	nni_mtx_unlock(&http->mtx);
}

void
nni_http_write_res(nni_http *http, nni_http_res *res, nni_aio *aio)
{
	int    rv;
	void * buf;
	size_t bufsz;

	if ((rv = nni_http_res_get_buf(res, &buf, &bufsz)) != 0) {
		nni_aio_finish_error(aio, rv);
		return;
	}
	aio->a_niov           = 1;
	aio->a_iov[0].iov_len = bufsz;
	aio->a_iov[0].iov_buf = buf;
	SET_WR_FLAVOR(aio, HTTP_WR_RES);

	nni_mtx_lock(&http->mtx);
	http_wr_submit(http, aio);
	nni_mtx_unlock(&http->mtx);
}

// Writer.  As with nni_http_conn_write, this is used to write data on
// a connection that has been "upgraded" (e.g. transformed to
// websocket). It is an error to perform other HTTP exchanges on an
// connection after this method is called.  (This mostly exists to
// support websocket.)
void
nni_http_write(nni_http *http, nni_aio *aio)
{
	SET_WR_FLAVOR(aio, HTTP_WR_RAW);

	nni_mtx_lock(&http->mtx);
	http_wr_submit(http, aio);
	nni_mtx_unlock(&http->mtx);
}

void
nni_http_write_full(nni_http *http, nni_aio *aio)
{
	SET_WR_FLAVOR(aio, HTTP_WR_FULL);

	nni_mtx_lock(&http->mtx);
	http_wr_submit(http, aio);
	nni_mtx_unlock(&http->mtx);
}

int
nni_http_sock_addr(nni_http *http, nni_sockaddr *sa)
{
	int rv;
	nni_mtx_lock(&http->mtx);
	rv = http->closed ? NNG_ECLOSED : http->sock_addr(http->sock, sa);
	nni_mtx_unlock(&http->mtx);
	return (rv);
}

int
nni_http_peer_addr(nni_http *http, nni_sockaddr *sa)
{
	int rv;
	nni_mtx_lock(&http->mtx);
	rv = http->closed ? NNG_ECLOSED : http->peer_addr(http->sock, sa);
	nni_mtx_unlock(&http->mtx);
	return (rv);
}

bool
nni_http_tls_verified(nni_http *http)
{
	bool rv;

	nni_mtx_lock(&http->mtx);
	rv = http->closed ? false : http->verified(http->sock);
	nni_mtx_unlock(&http->mtx);
	return (rv);
}

void
nni_http_fini(nni_http *http)
{
	nni_mtx_lock(&http->mtx);
	http_close(http);
	if ((http->sock != NULL) && (http->fini != NULL)) {
		http->fini(http->sock);
		http->sock = NULL;
	}
	nni_mtx_unlock(&http->mtx);
	nni_aio_stop(http->wr_aio);
	nni_aio_stop(http->rd_aio);
	nni_aio_fini(http->wr_aio);
	nni_aio_fini(http->rd_aio);
	nni_free(http->rd_buf, http->rd_bufsz);
	nni_mtx_fini(&http->mtx);
	NNI_FREE_STRUCT(http);
}

static int
http_init(nni_http **httpp, nni_http_tran *tran, void *data)
{
	nni_http *http;
	int       rv;

	if ((http = NNI_ALLOC_STRUCT(http)) == NULL) {
		return (NNG_ENOMEM);
	}
	http->rd_bufsz = HTTP_BUFSIZE;
	if ((http->rd_buf = nni_alloc(http->rd_bufsz)) == NULL) {
		NNI_FREE_STRUCT(http);
		return (NNG_ENOMEM);
	}
	nni_mtx_init(&http->mtx);
	nni_aio_list_init(&http->rdq);
	nni_aio_list_init(&http->wrq);

	http->sock      = data;
	http->rd_bufsz  = HTTP_BUFSIZE;
	http->rd        = tran->h_read;
	http->wr        = tran->h_write;
	http->close     = tran->h_close;
	http->fini      = tran->h_fini;
	http->sock_addr = tran->h_sock_addr;
	http->peer_addr = tran->h_peer_addr;
	http->verified  = tran->h_verified;

	if (((rv = nni_aio_init(&http->wr_aio, http_wr_cb, http)) != 0) ||
	    ((rv = nni_aio_init(&http->rd_aio, http_rd_cb, http)) != 0)) {
		nni_http_fini(http);
		return (rv);
	}

	*httpp = http;

	return (0);
}

static bool
nni_http_verified_tcp(void *arg)
{
	NNI_ARG_UNUSED(arg);
	return (false);
}

static nni_http_tran http_tcp_ops = {
	.h_read      = (void *) nni_plat_tcp_pipe_recv,
	.h_write     = (void *) nni_plat_tcp_pipe_send,
	.h_close     = (void *) nni_plat_tcp_pipe_close,
	.h_fini      = (void *) nni_plat_tcp_pipe_fini,
	.h_sock_addr = (void *) nni_plat_tcp_pipe_sockname,
	.h_peer_addr = (void *) nni_plat_tcp_pipe_peername,
	.h_verified  = nni_http_verified_tcp,
};

int
nni_http_init_tcp(nni_http **hpp, void *tcp)
{
	return (http_init(hpp, &http_tcp_ops, tcp));
}

#ifdef NNG_SUPP_TLS
static nni_http_tran http_tls_ops = {
	.h_read      = (void *) nni_tls_recv,
	.h_write     = (void *) nni_tls_send,
	.h_close     = (void *) nni_tls_close,
	.h_fini      = (void *) nni_tls_fini,
	.h_sock_addr = (void *) nni_tls_sockname,
	.h_peer_addr = (void *) nni_tls_peername,
	.h_verified  = (void *) nni_tls_verified,
};

int
nni_http_init_tls(nni_http **hpp, nng_tls_config *cfg, void *tcp)
{
	nni_tls *tls;
	int      rv;

	if ((rv = nni_tls_init(&tls, cfg, tcp)) != 0) {
		nni_plat_tcp_pipe_fini(tcp);
		return (rv);
	}

	return (http_init(hpp, &http_tls_ops, tls));
}
#else
int
nni_http_init_tls(nni_http **hpp, nng_tls_config *cfg, void *tcp)
{
	NNI_ARG_UNUSED(hpp);
	NNI_ARG_UNUSED(cfg);
	nni_plat_tcp_pipe_fini(tcp);
	return (NNG_ENOTSUP);
}
#endif // NNG_SUPP_TLS