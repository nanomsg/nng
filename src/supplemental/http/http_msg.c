//
// Copyright 2019 Staysail Systems, Inc. <info@staysail.tech>
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

#include "core/nng_impl.h"
#include "http_api.h"

// Note that as we parse headers, the rule is that if a header is already
// present, then we can append it to the existing header, separated by
// a comma.  From experience, for example, Firefox uses a Connection:
// header with two values, "keepalive", and "upgrade".
typedef struct http_header {
	char *        name;
	char *        value;
	nni_list_node node;
} http_header;

typedef struct nni_http_entity {
	char * data;
	size_t size; // allocated/expected size
	size_t len;  // current length
	bool   own;  // if true, data is "ours", and should be freed
} nni_http_entity;

struct nng_http_req {
	nni_list        hdrs;
	nni_http_entity data;
	char *          meth;
	char *          uri;
	char *          vers;
	char *          buf;
	size_t          bufsz;
	bool            parsed;
};

struct nng_http_res {
	nni_list        hdrs;
	nni_http_entity data;
	uint16_t        code;
	char *          rsn;
	char *          vers;
	char *          buf;
	size_t          bufsz;
	bool            parsed;
	bool            iserr;
};

static int
http_set_string(char **strp, const char *val)
{
	char *news;
	if (val == NULL) {
		news = NULL;
	} else if ((news = nni_strdup(val)) == NULL) {
		return (NNG_ENOMEM);
	}
	nni_strfree(*strp);
	*strp = news;
	return (0);
}

static void
http_headers_reset(nni_list *hdrs)
{
	http_header *h;
	while ((h = nni_list_first(hdrs)) != NULL) {
		nni_list_remove(hdrs, h);
		nni_strfree(h->name);
		nni_strfree(h->value);
		NNI_FREE_STRUCT(h);
	}
}

static void
http_entity_reset(nni_http_entity *entity)
{
	if (entity->own && entity->size) {
		nni_free(entity->data, entity->size);
	}
	entity->data = NULL;
	entity->size = 0;
	entity->own  = false;
}

void
nni_http_req_reset(nni_http_req *req)
{
	http_headers_reset(&req->hdrs);
	http_entity_reset(&req->data);
	nni_strfree(req->vers);
	nni_strfree(req->meth);
	nni_strfree(req->uri);
	req->vers = req->meth = req->uri = NULL;
	nni_free(req->buf, req->bufsz);
	req->bufsz  = 0;
	req->buf    = NULL;
	req->parsed = false;
}

void
nni_http_res_reset(nni_http_res *res)
{
	http_headers_reset(&res->hdrs);
	http_entity_reset(&res->data);
	nni_strfree(res->rsn);
	nni_strfree(res->vers);
	res->vers   = NULL;
	res->rsn    = NULL;
	res->code   = NNG_HTTP_STATUS_OK;
	res->parsed = false;
	nni_free(res->buf, res->bufsz);
	res->buf   = NULL;
	res->bufsz = 0;
}

void
nni_http_req_free(nni_http_req *req)
{
	if (req != NULL) {
		nni_http_req_reset(req);
		NNI_FREE_STRUCT(req);
	}
}

void
nni_http_res_free(nni_http_res *res)
{
	if (res != NULL) {
		nni_http_res_reset(res);
		NNI_FREE_STRUCT(res);
	}
}

static int
http_del_header(nni_list *hdrs, const char *key)
{
	http_header *h;
	NNI_LIST_FOREACH (hdrs, h) {
		if (nni_strcasecmp(key, h->name) == 0) {
			nni_list_remove(hdrs, h);
			nni_strfree(h->name);
			nni_free(h->value, strlen(h->value) + 1);
			NNI_FREE_STRUCT(h);
			return (0);
		}
	}
	return (NNG_ENOENT);
}

int
nni_http_req_del_header(nni_http_req *req, const char *key)
{
	return (http_del_header(&req->hdrs, key));
}

int
nni_http_res_del_header(nni_http_res *res, const char *key)
{
	return (http_del_header(&res->hdrs, key));
}

static int
http_set_header(nni_list *hdrs, const char *key, const char *val)
{
	http_header *h;
	NNI_LIST_FOREACH (hdrs, h) {
		if (nni_strcasecmp(key, h->name) == 0) {
			char *news;
			if ((news = nni_strdup(val)) == NULL) {
				return (NNG_ENOMEM);
			}
			nni_strfree(h->value);
			h->value = news;
			return (0);
		}
	}

	if ((h = NNI_ALLOC_STRUCT(h)) == NULL) {
		return (NNG_ENOMEM);
	}
	if ((h->name = nni_strdup(key)) == NULL) {
		NNI_FREE_STRUCT(h);
		return (NNG_ENOMEM);
	}
	if ((h->value = nni_strdup(val)) == NULL) {
		nni_strfree(h->name);
		NNI_FREE_STRUCT(h);
		return (NNG_ENOMEM);
	}
	nni_list_append(hdrs, h);
	return (0);
}

int
nni_http_req_set_header(nni_http_req *req, const char *key, const char *val)
{
	return (http_set_header(&req->hdrs, key, val));
}

int
nni_http_res_set_header(nni_http_res *res, const char *key, const char *val)
{
	return (http_set_header(&res->hdrs, key, val));
}

static int
http_add_header(nni_list *hdrs, const char *key, const char *val)
{
	http_header *h;
	NNI_LIST_FOREACH (hdrs, h) {
		if (nni_strcasecmp(key, h->name) == 0) {
			char *news;
			int   rv;
			rv = nni_asprintf(&news, "%s, %s", h->value, val);
			if (rv != 0) {
				return (rv);
			}
			nni_strfree(h->value);
			h->value = news;
			return (0);
		}
	}

	if ((h = NNI_ALLOC_STRUCT(h)) == NULL) {
		return (NNG_ENOMEM);
	}
	if ((h->name = nni_strdup(key)) == NULL) {
		NNI_FREE_STRUCT(h);
		return (NNG_ENOMEM);
	}
	if ((h->value = nni_strdup(val)) == NULL) {
		nni_strfree(h->name);
		NNI_FREE_STRUCT(h);
		return (NNG_ENOMEM);
	}
	nni_list_append(hdrs, h);
	return (0);
}

int
nni_http_req_add_header(nni_http_req *req, const char *key, const char *val)
{
	return (http_add_header(&req->hdrs, key, val));
}

int
nni_http_res_add_header(nni_http_res *res, const char *key, const char *val)
{
	return (http_add_header(&res->hdrs, key, val));
}

static const char *
http_get_header(nni_list *hdrs, const char *key)
{
	http_header *h;
	NNI_LIST_FOREACH (hdrs, h) {
		if (nni_strcasecmp(h->name, key) == 0) {
			return (h->value);
		}
	}
	return (NULL);
}

const char *
nni_http_req_get_header(nni_http_req *req, const char *key)
{
	return (http_get_header(&req->hdrs, key));
}

const char *
nni_http_res_get_header(nni_http_res *res, const char *key)
{
	return (http_get_header(&res->hdrs, key));
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

static int
http_entity_alloc_data(nni_http_entity *entity, size_t size)
{
	void *newdata;
	if ((newdata = nni_zalloc(size)) == NULL) {
		return (NNG_ENOMEM);
	}
	http_entity_set_data(entity, newdata, size);
	entity->own = true;
	return (0);
}

static int
http_entity_copy_data(nni_http_entity *entity, const void *data, size_t size)
{
	int rv;
	if ((rv = http_entity_alloc_data(entity, size)) == 0) {
		memcpy(entity->data, data, size);
	}
	return (rv);
}

static int
http_set_content_length(nni_http_entity *entity, nni_list *hdrs)
{
	char buf[16];
	(void) snprintf(buf, sizeof(buf), "%u", (unsigned) entity->size);
	return (http_set_header(hdrs, "Content-Length", buf));
}

static void
http_entity_get_data(nni_http_entity *entity, void **datap, size_t *sizep)
{
	*datap = entity->data;
	*sizep = entity->size;
}

void
nni_http_req_get_data(nni_http_req *req, void **datap, size_t *sizep)
{
	http_entity_get_data(&req->data, datap, sizep);
}

void
nni_http_res_get_data(nni_http_res *res, void **datap, size_t *sizep)
{
	http_entity_get_data(&res->data, datap, sizep);
}

int
nni_http_req_set_data(nni_http_req *req, const void *data, size_t size)
{
	int rv;

	http_entity_set_data(&req->data, data, size);
	if ((rv = http_set_content_length(&req->data, &req->hdrs)) != 0) {
		http_entity_set_data(&req->data, NULL, 0);
	}
	return (rv);
}

int
nni_http_res_set_data(nni_http_res *res, const void *data, size_t size)
{
	int rv;

	http_entity_set_data(&res->data, data, size);
	if ((rv = http_set_content_length(&res->data, &res->hdrs)) != 0) {
		http_entity_set_data(&res->data, NULL, 0);
	}
	res->iserr = false;
	return (rv);
}

int
nni_http_req_copy_data(nni_http_req *req, const void *data, size_t size)
{
	int rv;

	if (((rv = http_entity_copy_data(&req->data, data, size)) != 0) ||
	    ((rv = http_set_content_length(&req->data, &req->hdrs)) != 0)) {
		http_entity_set_data(&req->data, NULL, 0);
		return (rv);
	}
	return (0);
}

int
nni_http_req_alloc_data(nni_http_req *req, size_t size)
{
	int rv;

	if ((rv = http_entity_alloc_data(&req->data, size)) != 0) {
		return (rv);
	}
	return (0);
}

int
nni_http_res_copy_data(nni_http_res *res, const void *data, size_t size)
{
	int rv;

	if (((rv = http_entity_copy_data(&res->data, data, size)) != 0) ||
	    ((rv = http_set_content_length(&res->data, &res->hdrs)) != 0)) {
		http_entity_set_data(&res->data, NULL, 0);
		return (rv);
	}
	res->iserr = false;
	return (0);
}

// nni_http_res_alloc_data allocates the data region, but does not update any
// headers.  The intended use is for client implementations that want to
// allocate a buffer to receive the entity into.
int
nni_http_res_alloc_data(nni_http_res *res, size_t size)
{
	int rv;

	if ((rv = http_entity_alloc_data(&res->data, size)) != 0) {
		return (rv);
	}
	return (0);
}

bool
nni_http_res_is_error(nni_http_res *res)
{
	return (res->iserr);
}

static int
http_parse_header(nni_list *hdrs, void *line)
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

	return (http_add_header(hdrs, key, val));
}

// http_sprintf_headers makes headers for an HTTP request or an HTTP response
// object.  Each header is dumped from the list. If the buf is NULL,
// or the sz is 0, then a dryrun is done, in order to allow the caller to
// determine how much space is needed. Returns the size of the space needed,
// not including the terminating NULL byte.  Truncation occurs if the size
// returned is >= the requested size.
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
http_asprintf(char **bufp, size_t *szp, nni_list *hdrs, const char *fmt, ...)
{
	va_list ap;
	size_t  len;
	size_t  n;
	char *  buf;

	va_start(ap, fmt);
	len = vsnprintf(NULL, 0, fmt, ap);
	va_end(ap);

	len += http_sprintf_headers(NULL, 0, hdrs);
	len += 3; // \r\n\0

	if (len <= *szp) {
		buf = *bufp;
	} else {
		if ((buf = nni_alloc(len)) == NULL) {
			return (NNG_ENOMEM);
		}
		nni_free(*bufp, *szp);
		*bufp = buf;
		*szp  = len;
	}
	va_start(ap, fmt);
	n = vsnprintf(buf, len, fmt, ap);
	va_end(ap);
	buf += n;
	len -= n;
	n = http_sprintf_headers(buf, len, hdrs);
	buf += n;
	len -= n;
	snprintf(buf, len, "\r\n");
	NNI_ASSERT(len == 3);
	return (0);
}

static int
http_req_prepare(nni_http_req *req)
{
	int rv;
	if (req->uri == NULL) {
		return (NNG_EINVAL);
	}
	rv = http_asprintf(&req->buf, &req->bufsz, &req->hdrs, "%s %s %s\r\n",
	    req->meth != NULL ? req->meth : "GET", req->uri,
	    req->vers != NULL ? req->vers : "HTTP/1.1");
	return (rv);
}

static int
http_res_prepare(nni_http_res *res)
{
	int rv;
	rv = http_asprintf(&res->buf, &res->bufsz, &res->hdrs, "%s %d %s\r\n",
	    nni_http_res_get_version(res), nni_http_res_get_status(res),
	    nni_http_res_get_reason(res));
	return (rv);
}

char *
nni_http_req_headers(nni_http_req *req)
{
	char * s;
	size_t len;

	len = http_sprintf_headers(NULL, 0, &req->hdrs) + 1;
	if ((s = nni_alloc(len)) != NULL) {
		http_sprintf_headers(s, len, &req->hdrs);
	}
	return (s);
}

char *
nni_http_res_headers(nni_http_res *res)
{
	char * s;
	size_t len;

	len = http_sprintf_headers(NULL, 0, &res->hdrs) + 1;
	if ((s = nni_alloc(len)) != NULL) {
		http_sprintf_headers(s, len, &res->hdrs);
	}
	return (s);
}

int
nni_http_req_get_buf(nni_http_req *req, void **data, size_t *szp)
{
	int rv;

	if ((req->buf == NULL) && (rv = http_req_prepare(req)) != 0) {
		return (rv);
	}
	*data = req->buf;
	*szp  = req->bufsz - 1; // exclude terminating NUL
	return (0);
}

int
nni_http_res_get_buf(nni_http_res *res, void **data, size_t *szp)
{
	int rv;

	if ((res->buf == NULL) && (rv = http_res_prepare(res)) != 0) {
		return (rv);
	}
	*data = res->buf;
	*szp  = res->bufsz - 1; // exclude terminating NUL
	return (0);
}

int
nni_http_req_alloc(nni_http_req **reqp, const nni_url *url)
{
	nni_http_req *req;
	if ((req = NNI_ALLOC_STRUCT(req)) == NULL) {
		return (NNG_ENOMEM);
	}
	NNI_LIST_INIT(&req->hdrs, http_header, node);
	req->buf       = NULL;
	req->bufsz     = 0;
	req->data.data = NULL;
	req->data.size = 0;
	req->data.own  = false;
	req->vers      = NULL;
	req->meth      = NULL;
	req->uri       = NULL;
	if (url != NULL) {
		const char *host;
		int         rv;
		if ((req->uri = nni_strdup(url->u_requri)) == NULL) {
			NNI_FREE_STRUCT(req);
			return (NNG_ENOMEM);
		}

		// Add a Host: header since we know that from the URL. Also,
		// only include the :port portion if it isn't the default port.
		if (strcmp(nni_url_default_port(url->u_scheme), url->u_port) ==
		    0) {
			host = url->u_hostname;
		} else {
			host = url->u_host;
		}
		if ((rv = nni_http_req_add_header(req, "Host", host)) != 0) {
			nni_http_req_free(req);
			return (rv);
		}
	}
	*reqp = req;
	return (0);
}

int
nni_http_res_alloc(nni_http_res **resp)
{
	nni_http_res *res;
	if ((res = NNI_ALLOC_STRUCT(res)) == NULL) {
		return (NNG_ENOMEM);
	}
	NNI_LIST_INIT(&res->hdrs, http_header, node);
	res->buf       = NULL;
	res->bufsz     = 0;
	res->data.data = NULL;
	res->data.size = 0;
	res->data.own  = false;
	res->vers      = NULL;
	res->rsn       = NULL;
	res->code      = NNG_HTTP_STATUS_OK;
	*resp          = res;
	return (0);
}

const char *
nni_http_req_get_method(nni_http_req *req)
{
	return (req->meth != NULL ? req->meth : "GET");
}

const char *
nni_http_req_get_uri(nni_http_req *req)
{
	return (req->uri != NULL ? req->uri : "");
}

const char *
nni_http_req_get_version(nni_http_req *req)
{
	return (req->vers != NULL ? req->vers : "HTTP/1.1");
}

const char *
nni_http_res_get_version(nni_http_res *res)
{
	return (res->vers != NULL ? res->vers : "HTTP/1.1");
}

int
nni_http_req_set_version(nni_http_req *req, const char *vers)
{
	if ((vers != NULL) && (strcmp(vers, "HTTP/1.1") == 0)) {
		vers = NULL;
	}
	return (http_set_string(&req->vers, vers));
}

int
nni_http_res_set_version(nni_http_res *res, const char *vers)
{
	if ((vers != NULL) && (strcmp(vers, "HTTP/1.1") == 0)) {
		vers = NULL;
	}
	return (http_set_string(&res->vers, vers));
}

int
nni_http_req_set_uri(nni_http_req *req, const char *uri)
{
	return (http_set_string(&req->uri, uri));
}

int
nni_http_req_set_method(nni_http_req *req, const char *meth)
{
	if ((meth != NULL) && (strcmp(meth, "GET") == 0)) {
		meth = NULL;
	}
	return (http_set_string(&req->meth, meth));
}

int
nni_http_res_set_status(nni_http_res *res, uint16_t status)
{
	res->code = status;
	return (0);
}

uint16_t
nni_http_res_get_status(nni_http_res *res)
{
	return (res->code);
}

static int
http_scan_line(void *vbuf, size_t n, size_t *lenp)
{
	size_t len;
	char   lc;
	char * buf = vbuf;

	lc = 0;
	for (len = 0; len < n; len++) {
		char c = buf[len];
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

static int
http_req_parse_line(nni_http_req *req, void *line)
{
	int   rv;
	char *method;
	char *uri;
	char *version;

	method = line;
	if ((uri = strchr(method, ' ')) == NULL) {
		return (NNG_EPROTO);
	}
	*uri = '\0';
	uri++;

	if ((version = strchr(uri, ' ')) == NULL) {
		return (NNG_EPROTO);
	}
	*version = '\0';
	version++;

	if (((rv = nni_http_req_set_method(req, method)) != 0) ||
	    ((rv = nni_http_req_set_uri(req, uri)) != 0) ||
	    ((rv = nni_http_req_set_version(req, version)) != 0)) {
		return (rv);
	}
	req->parsed = true;
	return (0);
}

static int
http_res_parse_line(nni_http_res *res, uint8_t *line)
{
	int   rv;
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

	if (((rv = nni_http_res_set_status(res, (uint16_t) status)) != 0) ||
	    ((rv = nni_http_res_set_version(res, version)) != 0) ||
	    ((rv = nni_http_res_set_reason(res, reason)) != 0)) {
		return (rv);
	}
	res->parsed = true;
	return (0);
}

// nni_http_req_parse parses a request (but not any attached entity data).
// The amount of data consumed is returned in lenp.  Returns zero on
// success, NNG_EPROTO on parse failure, NNG_EAGAIN if more data is
// required, or NNG_ENOMEM on memory exhaustion.  Note that lenp may
// be updated even in the face of errors (esp. NNG_EAGAIN, which is
// not an error so much as a request for more data.)
int
nni_http_req_parse(nni_http_req *req, void *buf, size_t n, size_t *lenp)
{

	size_t len = 0;
	size_t cnt;
	int    rv = 0;

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

		if (req->parsed) {
			rv = http_parse_header(&req->hdrs, line);
		} else {
			rv = http_req_parse_line(req, line);
		}

		if (rv != 0) {
			break;
		}
	}

	*lenp = len;
	return (rv);
}

int
nni_http_res_parse(nni_http_res *res, void *buf, size_t n, size_t *lenp)
{

	size_t len = 0;
	size_t cnt;
	int    rv = 0;
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

		if (res->parsed) {
			rv = http_parse_header(&res->hdrs, line);
		} else {
			rv = http_res_parse_line(res, line);
		}

		if (rv != 0) {
			break;
		}
	}

	*lenp = len;
	return (rv);
}

static struct {
	uint16_t    code;
	const char *mesg;
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

	// 300 series -- redirection
	{ NNG_HTTP_STATUS_MULTIPLE_CHOICES, "Multiple Choices" },
	{ NNG_HTTP_STATUS_STATUS_MOVED_PERMANENTLY, "Moved Permanently" },
	{ NNG_HTTP_STATUS_FOUND, "Found" },
	{ NNG_HTTP_STATUS_SEE_OTHER, "See Other" },
	{ NNG_HTTP_STATUS_NOT_MODIFIED, "Not Modified" },
	{ NNG_HTTP_STATUS_USE_PROXY, "Use Proxy" },
	{ NNG_HTTP_STATUS_TEMPORARY_REDIRECT, "Temporary Redirect" },

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
	{ NNG_HTTP_STATUS_ENTITY_TOO_LONG, "Request Entity Too Long" },
	{ NNG_HTTP_STATUS_UNSUPPORTED_MEDIA_TYPE, "Unsupported Media Type" },
	{ NNG_HTTP_STATUS_RANGE_NOT_SATISFIABLE,
	    "Requested Range Not Satisfiable" },
	{ NNG_HTTP_STATUS_EXPECTATION_FAILED, "Expectation Failed" },
	{ NNG_HTTP_STATUS_TEAPOT, "I Am A Teapot" },
	{ NNG_HTTP_STATUS_LOCKED, "Locked" },
	{ NNG_HTTP_STATUS_FAILED_DEPENDENCY, "Failed Dependency" },
	{ NNG_HTTP_STATUS_UPGRADE_REQUIRED, "Upgrade Required" },
	{ NNG_HTTP_STATUS_PRECONDITION_REQUIRED, "Precondition Required" },
	{ NNG_HTTP_STATUS_TOO_MANY_REQUESTS, "Too Many Requests" },
	{ NNG_HTTP_STATUS_HEADERS_TOO_LARGE, "Headers Too Large" },
	{ NNG_HTTP_STATUS_UNAVAIL_LEGAL_REASONS,
	    "Unavailable For Legal Reasons" },

	// 500 series -- server errors
	{ NNG_HTTP_STATUS_INTERNAL_SERVER_ERROR, "Internal Server Error" },
	{ NNG_HTTP_STATUS_NOT_IMPLEMENTED, "Not Implemented" },
	{ NNG_HTTP_STATUS_BAD_REQUEST, "Bad Gateway" },
	{ NNG_HTTP_STATUS_SERVICE_UNAVAILABLE, "Service Unavailable" },
	{ NNG_HTTP_STATUS_GATEWAY_TIMEOUT, "Gateway Timeout" },
	{ NNG_HTTP_STATUS_HTTP_VERSION_NOT_SUPP,
	    "HTTP Version Not Supported" },
	{ NNG_HTTP_STATUS_VARIANT_ALSO_NEGOTIATES, "Variant Also Negotiates" },
	{ NNG_HTTP_STATUS_INSUFFICIENT_STORAGE, "Insufficient Storage" },
	{ NNG_HTTP_STATUS_LOOP_DETECTED, "Loop Detected" },
	{ NNG_HTTP_STATUS_NOT_EXTENDED, "Not Extended" },
	{ NNG_HTTP_STATUS_NETWORK_AUTH_REQUIRED,
	    "Network Authentication Required" },

	// Terminator
	{ 0, NULL },
};

const char *
nni_http_reason(uint16_t code)
{
	for (int i = 0; http_status[i].code != 0; i++) {
		if (http_status[i].code == code) {
			return (http_status[i].mesg);
		}
	}
	return ("Unknown HTTP Status");
}

const char *
nni_http_res_get_reason(nni_http_res *res)
{
	return (res->rsn ? res->rsn : nni_http_reason(res->code));
}

int
nni_http_res_set_reason(nni_http_res *res, const char *reason)
{
	if ((reason != NULL) &&
	    (strcmp(reason, nni_http_reason(res->code)) == 0)) {
		reason = NULL;
	}
	return (http_set_string(&res->rsn, reason));
}

int
nni_http_alloc_html_error(char **html, uint16_t code, const char *details)
{
	const char *rsn = nni_http_reason(code);

	return (nni_asprintf(html,
	    "<!DOCTYPE html>\n"
	    "<html><head><title>%d %s</title>\n"
	    "<style>"
	    "body { font-family: Arial, sans serif; text-align: center }\n"
	    "h1 { font-size: 36px; }"
	    "span { background-color: gray; color: white; padding: 7px; "
	    "border-radius: 5px }"
	    "h2 { font-size: 24px; }"
	    "p { font-size: 20px; }"
	    "</style></head>"
	    "<body><p>&nbsp;</p>"
	    "<h1><span>%d</span></h1>"
	    "<h2>%s</h2>"
	    "<p>%s</p>"
	    "</body></html>",
	    code, rsn, code, rsn, details != NULL ? details : ""));
}

int
nni_http_res_alloc_error(nni_http_res **resp, uint16_t err)
{
	char *        html = NULL;
	nni_http_res *res  = NULL;
	int           rv;

	if (((rv = nni_http_res_alloc(&res)) != 0) ||
	    ((rv = nni_http_alloc_html_error(&html, err, NULL)) != 0) ||
	    ((rv = nni_http_res_set_header(
	          res, "Content-Type", "text/html; charset=UTF-8")) != 0) ||
	    ((rv = nni_http_res_copy_data(res, html, strlen(html))) != 0)) {
		nni_strfree(html);
		nni_http_res_free(res);
	} else {
		nni_strfree(html);
		res->code  = err;
		res->iserr = true;
		*resp      = res;
	}

	return (rv);
}
