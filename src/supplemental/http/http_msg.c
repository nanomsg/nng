//
// Copyright 2025 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../core/list.h"
#include "../../core/nng_impl.h"
#include "../../core/url.h"
#include "http_api.h"
#include "http_msg.h"
#include "nng/http.h"

void
nni_http_free_header(http_header *h)
{
	nni_list_node_remove(&h->node);
	if (!h->static_name) {
		nni_strfree(h->name);
		h->name = NULL;
	}
	if (!h->static_value) {
		nni_strfree(h->value);
		h->value = NULL;
	}
	if (h->alloc_header) {
		NNI_FREE_STRUCT(h);
	}
}

static void
http_headers_reset(nni_list *hdrs)
{
	http_header *h;
	while ((h = nni_list_first(hdrs)) != NULL) {
		nni_http_free_header(h);
	}
}

static void
http_entity_reset(nni_http_entity *entity)
{
	if (entity->own && entity->size) {
		nni_free(entity->data, entity->size);
	}
	http_headers_reset(&entity->hdrs);
	nni_free(entity->buf, entity->bufsz);
	entity->data   = NULL;
	entity->size   = 0;
	entity->own    = false;
	entity->parsed = false;
	entity->buf    = NULL;
	entity->bufsz  = 0;
}

void
nni_http_req_reset(nni_http_req *req)
{
	http_entity_reset(&req->data);
}

void
nni_http_res_reset(nni_http_res *res)
{
	http_entity_reset(&res->data);
}

// http_entity_set_data sets the entity, but does not update the
// content-length header.
static void
http_entity_set_data(nni_http_entity *entity, const void *data, size_t size)
{
	if (entity->own) {
		nni_free(entity->data, entity->size);
	}
	entity->data = (void *) data;
	entity->size = size;
	entity->own  = false;
}

static nng_err
http_entity_alloc_data(nni_http_entity *entity, size_t size)
{
	void *newdata;
	if (size != 0) {
		if ((newdata = nni_zalloc(size)) == NULL) {
			return (NNG_ENOMEM);
		}
	}
	http_entity_set_data(entity, newdata, size);
	entity->own = true;
	return (NNG_OK);
}

nng_err
nni_http_req_alloc_data(nni_http_req *req, size_t size)
{
	return (http_entity_alloc_data(&req->data, size));
}

// nni_http_res_alloc_data allocates the data region, but does not update any
// headers.  The intended use is for client implementations that want to
// allocate a buffer to receive the entity into.
nng_err
nni_http_res_alloc_data(nni_http_res *res, size_t size)
{
	return (http_entity_alloc_data(&res->data, size));
}

static nng_err
http_parse_header(nng_http *conn, void *line)
{
	char *key = line;
	char *val;
	char *end;

	// Find separation between key and value
	if ((val = strchr(key, ':')) == NULL) {
		return (NNG_EPROTO);
	}

	// Trim leading and trailing whitespace from header
	*val = '\0';
	val++;
	while (*val == ' ' || *val == '\t') {
		val++;
	}
	end = val + strlen(val);
	end--;
	while ((end > val) && (*end == ' ' || *end == '\t')) {
		*end = '\0';
		end--;
	}

	return (nni_http_add_header(conn, key, val));
}

void
nni_http_req_init(nni_http_req *req)
{
	NNI_LIST_INIT(&req->data.hdrs, http_header, node);
	req->data.buf   = NULL;
	req->data.bufsz = 0;
	req->data.data  = NULL;
	req->data.size  = 0;
	req->data.own   = false;
}

void
nni_http_res_init(nni_http_res *res)
{
	NNI_LIST_INIT(&res->data.hdrs, http_header, node);
	res->data.buf   = NULL;
	res->data.bufsz = 0;
	res->data.data  = NULL;
	res->data.size  = 0;
	res->data.own   = false;
}

static nng_err
http_scan_line(void *vbuf, size_t n, size_t *lenp)
{
	size_t   len;
	char     lc;
	uint8_t *buf = vbuf;

	lc = 0;
	for (len = 0; len < n; len++) {
		uint8_t c = buf[len];
		if (c == '\n') {
			// Technically we should be receiving CRLF, but
			// debugging is easier with just LF, so we behave
			// following Postel's Law.
			if (lc != '\r') {
				buf[len] = '\0';
			} else {
				buf[len - 1] = '\0';
			}
			*lenp = len + 1;
			return (0);
		}
		// If we have a control character (other than CR), or a CR
		// followed by anything other than LF, then its an error.
		if (((c < ' ') && (c != '\r')) || (lc == '\r')) {
			return (NNG_EPROTO);
		}
		lc = c;
	}
	// Scanned the entire content, but did not find a line.
	return (NNG_EAGAIN);
}

static nng_err
http_req_parse_line(nng_http *conn, void *line)
{
	char *method;
	char *uri;
	char *version;

	if (nni_http_get_status(conn) >= NNG_HTTP_STATUS_BAD_REQUEST) {
		// we've already failed it, nothing else for us to do
		return (NNG_OK);
	}
	method = line;
	if ((uri = strchr(method, ' ')) == NULL) {
		nni_http_set_status(conn, NNG_HTTP_STATUS_BAD_REQUEST, NULL);
		return (NNG_OK);
	}
	*uri = '\0';
	uri++;

	if ((version = strchr(uri, ' ')) == NULL) {
		nni_http_set_status(conn, NNG_HTTP_STATUS_BAD_REQUEST, NULL);
		return (NNG_OK);
	}
	*version = '\0';
	version++;

	if (nni_url_canonify_uri(uri) != 0) {
		nni_http_set_status(conn, NNG_HTTP_STATUS_BAD_REQUEST, NULL);
		return (NNG_OK);
	}
	if (nni_http_set_version(conn, version)) {
		nni_http_set_status(
		    conn, NNG_HTTP_STATUS_HTTP_VERSION_NOT_SUPP, NULL);
		return (NNG_OK);
	}

	nni_http_set_method(conn, method);

	// this one only can fail due to ENOMEM
	return (nni_http_set_uri(conn, uri, NULL));
}

static nng_err
http_res_parse_line(nng_http *conn, uint8_t *line)
{
	char *reason;
	char *codestr;
	char *version;
	int   status;

	version = (char *) line;
	if ((codestr = strchr(version, ' ')) == NULL) {
		return (NNG_EPROTO);
	}
	*codestr = '\0';
	codestr++;

	if ((reason = strchr(codestr, ' ')) == NULL) {
		return (NNG_EPROTO);
	}
	*reason = '\0';
	reason++;

	status = atoi(codestr);
	if ((status < 100) || (status > 999)) {
		return (NNG_EPROTO);
	}

	nni_http_set_status(conn, (uint16_t) status, reason);

	return (nni_http_set_version(conn, version));
}

// nni_http_req_parse parses a request (but not any attached entity data).
// The amount of data consumed is returned in lenp.  Returns zero on
// success, NNG_EPROTO on parse failure, NNG_EAGAIN if more data is
// required, or NNG_ENOMEM on memory exhaustion.  Note that lenp may
// be updated even in the face of errors (esp. NNG_EAGAIN, which is
// not an error so much as a request for more data.)
nng_err
nni_http_req_parse(nng_http *conn, void *buf, size_t n, size_t *lenp)
{

	size_t        len = 0;
	size_t        cnt;
	int           rv  = 0;
	nni_http_req *req = nni_http_conn_req(conn);

	for (;;) {
		uint8_t *line;
		if ((rv = http_scan_line(buf, n, &cnt)) != 0) {
			break;
		}

		len += cnt;
		line = buf;
		buf  = line + cnt;
		n -= cnt;

		if (*line == '\0') {
			break;
		}

		if (req->data.parsed) {
			rv = http_parse_header(conn, line);
		} else {
			req->data.parsed = true;
			rv               = http_req_parse_line(conn, line);
		}
	}

	if (rv != NNG_EAGAIN) {
		req->data.parsed = false;
	}
	*lenp = len;
	return (rv);
}

nng_err
nni_http_res_parse(nng_http *conn, void *buf, size_t n, size_t *lenp)
{

	size_t        len = 0;
	size_t        cnt;
	int           rv  = 0;
	nng_http_res *res = nni_http_conn_res(conn);
	for (;;) {
		uint8_t *line;
		if ((rv = http_scan_line(buf, n, &cnt)) != 0) {
			break;
		}

		len += cnt;
		line = buf;
		buf  = line + cnt;
		n -= cnt;

		if (*line == '\0') {
			break;
		}

		if (res->data.parsed) {
			rv = http_parse_header(conn, line);
		} else if ((rv = http_res_parse_line(conn, line)) == 0) {
			res->data.parsed = true;
		}

		if (rv != 0) {
			break;
		}
	}

	if (rv == 0) {
		res->data.parsed = false;
	}
	*lenp = len;
	return (rv);
}
