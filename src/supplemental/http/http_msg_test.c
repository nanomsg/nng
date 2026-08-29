//
// Copyright 2026 Staysail Systems, Inc. <info@staysail.tech>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "core/nng_impl.h"
#include "http_api.h"

#include <nuts.h>
#include <string.h>

static void
test_http_req_canonify_uri(void)
{
	nni_http_req *req;
	char          plain[] = "GET /../../outside.txt HTTP/1.1\r\n\r\n";
	char          encoded[] =
	    "GET /%2e%2e/%2E%2e/outside.txt HTTP/1.1\r\n\r\n";
	char fragment[] = "GET /#/../../outside.txt HTTP/1.1\r\n\r\n";
	char backslash[] = "GET /..\\..\\outside.txt HTTP/1.1\r\n\r\n";
	size_t        len;

	NUTS_PASS(nni_http_req_alloc(&req, NULL));
	NUTS_PASS(nni_http_req_parse(req, plain, strlen(plain), &len));
	NUTS_MATCH(nni_http_req_get_uri(req), "/outside.txt");
	nni_http_req_free(req);

	NUTS_PASS(nni_http_req_alloc(&req, NULL));
	NUTS_PASS(nni_http_req_parse(req, encoded, strlen(encoded), &len));
	NUTS_MATCH(nni_http_req_get_uri(req), "/outside.txt");
	nni_http_req_free(req);

	NUTS_PASS(nni_http_req_alloc(&req, NULL));
	NUTS_FAIL(nni_http_req_parse(req, fragment, strlen(fragment), &len),
	    NNG_EPROTO);
	nni_http_req_free(req);

	NUTS_PASS(nni_http_req_alloc(&req, NULL));
	NUTS_FAIL(nni_http_req_parse(req, backslash, strlen(backslash), &len),
	    NNG_EPROTO);
	nni_http_req_free(req);
}

static void
test_http_chunk_size_overflow(void)
{
	nni_http_chunks *chunks = NULL;
	char             body[] = "10000000000000000\r\n";
	size_t           len    = 0;

	NUTS_PASS(nni_http_chunks_init(&chunks, 0));
	NUTS_FAIL(nni_http_chunks_parse(chunks, body, strlen(body), &len),
	    NNG_EMSGSIZE);
	nni_http_chunks_free(chunks);
}

static void
test_http_chunk_alloc_overflow(void)
{
	nni_http_chunks *chunks = NULL;
	char             body[] = "ffffffffffffffff\r\n";
	size_t           len    = 0;

	NUTS_PASS(nni_http_chunks_init(&chunks, 0));
	NUTS_FAIL(nni_http_chunks_parse(chunks, body, strlen(body), &len),
	    NNG_EMSGSIZE);
	nni_http_chunks_free(chunks);
}

NUTS_TESTS = {
	{ "http request URI canonicalization", test_http_req_canonify_uri },
	{ "http chunk size overflow", test_http_chunk_size_overflow },
	{ "http chunk allocation overflow", test_http_chunk_alloc_overflow },
	{ NULL, NULL },
};
