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
#include <string.h>

#include "core/nng_impl.h"

#include "http_api.h"

// Chunked transfer encoding support.

// Note that HTTP/1.1 chunked transfer encoding is horrible, and should
// be avoided if at all possible.  It necessarily creates extra need for
// data copies, creates a lot of extra back and forth complexity.  If you're
// stuck in this code, we feel great sympathy for you.
//
// We feel strongly enough about this that we refuse to provide any
// method to automatically generate chunked transfers.  If you think
// you need to send chunked transfers (because you have no idea how
// much data you will send, such as a streaming workload), consider a
// different method such as WebSocket to send your data.  Unbounded
// entity body data is just impolite.

enum chunk_state {
	CS_INIT,   // initial state
	CS_LEN,    // length
	CS_EXT,    // random extension text (we ignore)
	CS_CR,     // carriage return after length (and extensions)
	CS_DATA,   // actual data
	CS_TRLR,   // trailer
	CS_TRLRCR, // CRLF at end of trailer
	CS_DONE,
};

struct nng_http_chunks {
	nni_list         cl_chunks;
	size_t           cl_maxsz;
	size_t           cl_size; // parsed size (so far)
	size_t           cl_line; // bytes since last newline
	enum chunk_state cl_state;
};

struct nng_http_chunk {
	nni_list_node c_node;
	size_t        c_size;
	size_t        c_alloc;
	size_t        c_resid; // residual data to transfer
	char *        c_data;
};

int
nni_http_chunks_init(nni_http_chunks **clp, size_t maxsz)
{
	nni_http_chunks *cl;

	if ((cl = NNI_ALLOC_STRUCT(cl)) == NULL) {
		return (NNG_ENOMEM);
	}
	NNI_LIST_INIT(&cl->cl_chunks, nni_http_chunk, c_node);
	cl->cl_maxsz = maxsz;
	*clp         = cl;
	return (0);
}

void
nni_http_chunks_free(nni_http_chunks *cl)
{
	nni_http_chunk *ch;
	if (cl == NULL) {
		return;
	}
	while ((ch = nni_list_first(&cl->cl_chunks)) != NULL) {
		nni_list_remove(&cl->cl_chunks, ch);
		if (ch->c_data != NULL) {
			nni_free(ch->c_data, ch->c_alloc);
		}
		NNI_FREE_STRUCT(ch);
	}
	NNI_FREE_STRUCT(cl);
}

nni_http_chunk *
nni_http_chunks_iter(nni_http_chunks *cl, nni_http_chunk *last)
{
	if (last == NULL) {
		return (nni_list_first(&cl->cl_chunks));
	}
	return (nni_list_next(&cl->cl_chunks, last));
}

size_t
nni_http_chunks_size(nni_http_chunks *cl)
{
	size_t          tot = 0;
	nni_http_chunk *ch;
	NNI_LIST_FOREACH (&cl->cl_chunks, ch) {
		tot += ch->c_size;
	}
	return (tot);
}

size_t
nni_http_chunk_size(nni_http_chunk *ch)
{
	return (ch->c_size);
}

void *
nni_http_chunk_data(nni_http_chunk *ch)
{
	return (ch->c_data);
}

static int
chunk_ingest_len(nni_http_chunks *cl, char c)
{
	if (isdigit(c)) {
		cl->cl_size *= 16;
		cl->cl_size += (c - '0');
	} else if ((c >= 'A') && (c <= 'F')) {
		cl->cl_size *= 16;
		cl->cl_size += (c - 'A') + 10;
	} else if ((c >= 'a') && (c <= 'f')) {
		cl->cl_size *= 16;
		cl->cl_size += (c - 'a') + 10;
	} else if (c == ';') {
		cl->cl_state = CS_EXT;
	} else if (c == '\r') {
		cl->cl_state = CS_CR;
	} else {
		return (NNG_EPROTO);
	}
	return (0);
}

static int
chunk_ingest_ext(nni_http_chunks *cl, char c)
{
	if (c == '\r') {
		cl->cl_state = CS_CR;
	} else if (!isprint(c)) {
		return (NNG_EPROTO);
	}
	return (0);
}

static int
chunk_ingest_newline(nni_http_chunks *cl, char c)
{
	nni_http_chunk *chunk;

	if (c != '\n') {
		return (NNG_EPROTO);
	}
	if (cl->cl_size == 0) {
		cl->cl_line  = 0;
		cl->cl_state = CS_TRLR;
		return (0);
	}
	if ((cl->cl_maxsz > 0) &&
	    ((nni_http_chunks_size(cl) + cl->cl_size) > cl->cl_maxsz)) {
		return (NNG_EMSGSIZE);
	}
	if ((chunk = NNI_ALLOC_STRUCT(chunk)) == NULL) {
		return (NNG_ENOMEM);
	}
	// two extra bytes to accommodate trailing CRLF
	if ((chunk->c_data = nni_alloc(cl->cl_size + 2)) == NULL) {
		NNI_FREE_STRUCT(chunk);
		return (NNG_ENOMEM);
	}

	// Data, so allocate a new chunk, stick it on the end of the list,
	// and note that we have residual data needs.  The residual is
	// to allow for the trailing CRLF to be consumed.
	cl->cl_state   = CS_DATA;
	chunk->c_size  = cl->cl_size;
	chunk->c_alloc = cl->cl_size + 2;
	chunk->c_resid = chunk->c_alloc;
	nni_list_append(&cl->cl_chunks, chunk);

	return (0);
}

static int
chunk_ingest_trailer(nni_http_chunks *cl, char c)
{
	if (c == '\r') {
		cl->cl_state = CS_TRLRCR;
		return (0);
	}
	if (!isprint(c)) {
		return (NNG_EPROTO);
	}
	cl->cl_line++;
	return (0);
}

static int
chunk_ingest_trailercr(nni_http_chunks *cl, char c)
{
	if (c != '\n') {
		return (NNG_EPROTO);
	}
	if (cl->cl_line == 0) {
		cl->cl_state = CS_DONE;
		return (0);
	}
	cl->cl_line  = 0;
	cl->cl_state = CS_TRLR;
	return (0);
}

static int
chunk_ingest_char(nni_http_chunks *cl, char c)
{
	int rv;
	switch (cl->cl_state) {
	case CS_INIT:
		if (!isalnum(c)) {
			rv = NNG_EPROTO;
			break;
		}
		cl->cl_state = CS_LEN;
		// fallthrough
	case CS_LEN:
		rv = chunk_ingest_len(cl, c);
		break;
	case CS_EXT:
		rv = chunk_ingest_ext(cl, c);
		break;
	case CS_CR:
		rv = chunk_ingest_newline(cl, c);
		break;
	case CS_TRLR:
		rv = chunk_ingest_trailer(cl, c);
		break;
	case CS_TRLRCR:
		rv = chunk_ingest_trailercr(cl, c);
		break;
	default:
		// NB: No support for CS_DATA here, as that is handled
		// in the caller for reasons of efficiency.
		rv = NNG_EPROTO;
		break;
	}

	return (rv);
}

static int
chunk_ingest_data(nni_http_chunks *cl, char *buf, size_t n, size_t *lenp)
{
	nni_http_chunk *chunk;
	size_t          offset;
	char *          dest;

	chunk = nni_list_last(&cl->cl_chunks);

	NNI_ASSERT(chunk != NULL);
	NNI_ASSERT(cl->cl_state == CS_DATA);
	NNI_ASSERT(chunk->c_resid <= chunk->c_alloc);
	NNI_ASSERT(chunk->c_alloc > 2); // not be zero, plus newlines

	dest   = chunk->c_data;
	offset = chunk->c_alloc - chunk->c_resid;
	dest += offset;

	if (n >= chunk->c_resid) {
		n = chunk->c_resid;
		memcpy(dest, buf, n);

		if ((chunk->c_data[chunk->c_size] != '\r') ||
		    (chunk->c_data[chunk->c_size + 1] != '\n')) {
			return (NNG_EPROTO);
		}
		chunk->c_resid = 0;
		cl->cl_state   = CS_INIT;
		cl->cl_size    = 0;
		cl->cl_line    = 0;
		*lenp          = n;
		return (0);
	}

	memcpy(dest, buf, n);
	chunk->c_resid -= n;
	*lenp = n;
	return (0);
}

int
nni_http_chunks_parse(nni_http_chunks *cl, void *buf, size_t n, size_t *lenp)
{
	size_t i   = 0;
	char * src = buf;

	// Format of this data is <hexdigits> [ ; <ascii> CRLF ]
	// The <ascii> are chunk extensions, and we don't support any.

	while ((cl->cl_state != CS_DONE) && (i < n)) {
		int    rv;
		size_t cnt;
		switch (cl->cl_state) {
		case CS_DONE:
			// Completed parse!
			break;

		case CS_DATA:
			if ((rv = chunk_ingest_data(cl, src + i, n - i, &cnt)) !=
			    0) {
				return (rv);
			}
			i += cnt;
			break;

		default:
			// All others character by character parse through
			// the state machine grinder.
			if ((rv = chunk_ingest_char(cl, src[i])) != 0) {
				return (rv);
			}
			i++;
			break;
		}
	}

	*lenp = i;
	if (cl->cl_state != CS_DONE) {
		return (NNG_EAGAIN);
	}
	return (0);
}
