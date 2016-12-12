/*
 * Copyright 2016 Garrett D'Amore <garrett@damore.org>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom
 * the Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#include <stdlib.h>
#include <string.h>

#include "core/nng_impl.h"

/*
 * Message API.
 */

/* Message chunk, internal to the message implementation. */
typedef struct {
	size_t		ch_cap;		/* allocated size */
	size_t		ch_len;		/* length in use */
	uint8_t		*ch_buf;	/* underlying buffer */
	uint8_t		*ch_ptr;	/* pointer to actual data */
} chunk_t;

/* Underlying message chunk. */
struct nng_msg {
	chunk_t		m_header;
	chunk_t		m_body;
	int64_t		m_expire;	/* Unix usec */
	nng_pipe_t	m_pipe;		/* Pipe message was received on */
};

/*
 * chunk_grow increases the underlying space for a chunk.  It ensures
 * that the desired amount of trailing space (including the length)
 * and headroom (excluding the length) are available.  It also copies
 * any extant referenced data.  Note that the capacity will increase,
 * but not the length.  To increase the length of the referenced data,
 * use either chunk_append or chunk_prepend.
 *
 * Note that having some headroom is useful when data must be prepended
 * to a message - it avoids having to perform extra data copies, so we
 * encourage initial allocations to start with sufficient room.
 */
static int
chunk_grow(chunk_t *ch, size_t newsz, size_t headwanted)
{
	size_t headroom = 0;
	uint8_t *newbuf;

	/*
	 * We assume that if the pointer is a valid pointer, and inside
	 * the backing store, then the entire data length fits.  In this
	 * case we perform a logical realloc, except we don't copy any
	 * unreferenced data.  We do preserve the headroom of the previous
	 * use, since that may be there for a reason.
	 *
	 * The test below also covers the case where the pointers are both
	 * NULL, or the capacity is zero.
	 */

	if ((ch->ch_ptr >= ch->ch_buf) &&
	    (ch->ch_ptr < (ch->ch_buf + ch->ch_cap))) {

		headroom = (size_t)(ch->ch_ptr - ch->ch_buf);
		if (((newsz + headwanted) < ch->ch_cap) &&
		    (headwanted <= headroom)) {
			/* We have enough space at the ends already. */
			return (0);
		}
		if (headwanted < headroom) {
			/* We never shrink... headroom either. */
			headwanted = headroom;
		}
		if ((newbuf = nni_alloc(newsz + headwanted)) == NULL) {
			return (NNG_ENOMEM);
		}
		/* Copy all the data, but not header or trailer. */
		memcpy(newbuf + headwanted, ch->ch_buf + headroom, ch->ch_len);
		nni_free(ch->ch_buf, ch->ch_cap);
		ch->ch_buf = newbuf;
		ch->ch_ptr = newbuf + headwanted;
		ch->ch_cap = newsz + headwanted;
		return (0);
	}

	/*
	 * We either don't have a data pointer yet, or it doesn't reference
	 * the backing store.  In this case, we just check against the
	 * allocated capacity and grow, or don't grow.
	 */
	if (newsz > ch->ch_cap) {
		/* Enough space at end, so just use it. */
		if (ch->ch_ptr == NULL) {
			ch->ch_ptr = ch->ch_buf + headwanted;
		}
		return (0);

	} else if ((newbuf = nni_alloc(newsz)) == NULL) {
		return (NNG_ENOMEM);
	}

	nni_free(ch->ch_buf, ch->ch_cap);
	ch->ch_buf = newbuf;
	ch->ch_cap = newsz;
	if (ch->ch_ptr == NULL) {
		ch->ch_ptr = ch->ch_buf + headwanted;
	}
	return (0);
}

static void
chunk_free(chunk_t *ch)
{
	if ((ch->ch_cap != 0) && (ch->ch_buf != NULL)) {
		nni_free(ch->ch_buf, ch->ch_cap);
	}
	ch->ch_ptr = NULL;
	ch->ch_buf = NULL;
	ch->ch_len = 0;
	ch->ch_cap = 0;
}

/* chunk_trunc truncates the number of bytes from the end of the chunk. */
static int
chunk_trunc(chunk_t *ch, size_t len)
{
	if (ch->ch_len < len) {
		return (NNG_EINVAL);
	}
	ch->ch_len -= len;
	return (0);
}

/* chunk_trim removes the number of bytes from the beginning of the chunk. */
static int
chunk_trim(chunk_t *ch, size_t len)
{
	if (ch->ch_len < len) {
		return (NNG_EINVAL);
	}
	ch->ch_ptr += len;
	ch->ch_len -= len;
	return (0);
}

/*
 * chunk_append appends the data to the chunk, growing the size as necessary.
 * If the data pointer is NULL, then the chunk data region is allocated, but
 * uninitialized.
 */
static int
chunk_append(chunk_t *ch, const void *data, size_t len)
{
	int rv;
	if (len == 0) {
		return (0);
	}
	if ((rv = chunk_grow(ch, len + ch->ch_len, 0)) != 0) {
		return (rv);
	}
	if (ch->ch_ptr == NULL) {
		ch->ch_ptr = ch->ch_buf;
	}
	if (data != NULL) {
		memcpy(ch->ch_ptr + ch->ch_len, data, len);
	}
	ch->ch_len += len;
	return (0);
}

/*
 * chunk_prepend prepends data to the chunk, as efficiently as possible.
 * If the data pointer is NULL, then no data is actually copied, but the
 * data region will have "grown" in the beginning, with uninitialized data.
 */
static int
chunk_prepend(chunk_t *ch, const void *data, size_t len)
{
	int rv;

	if (ch->ch_ptr == NULL) {
		ch->ch_ptr = ch->ch_buf;
	}

	if ((ch->ch_ptr >= ch->ch_buf) &&
	    (ch->ch_ptr < (ch->ch_buf + ch->ch_cap)) &&
	    (len <= (size_t)(ch->ch_ptr - ch->ch_buf))) {
		/* There is already enough room at the beginning. */
		ch->ch_ptr -= len;

	} else if ((ch->ch_len + len) <= ch->ch_cap) {
		/* We had enough capacity, just shuffle data down. */
		memmove(ch->ch_ptr + len, ch->ch_ptr, ch->ch_len);

	} else if ((rv = chunk_grow(ch, 0, len)) == 0) {
		/* We grew the chunk, so adjust. */
		ch->ch_ptr -= len;

	} else {
		/* Couldn't grow the chunk either.  Error. */
		return (rv);
	}

	ch->ch_len += len;
	if (data) {
		memcpy(ch->ch_ptr, data, len);
	}

	return (0);
}

int
nng_msg_alloc(nng_msg_t *mp, size_t sz)
{
	nng_msg_t m;
	int rv;

	if ((m = nni_alloc(sizeof (*m))) == NULL) {
		return (NNG_ENOMEM);
	}

	/*
	 * 64-bytes of header, including room for 32 bytes
	 * of headroom and 32 bytes of trailer.
	 */
	if ((rv = chunk_grow(&m->m_header, 32, 32)) != 0) {
		nni_free(m, sizeof (*m));
		return (rv);
	}

	/*
	 * If the message is less than 1024 bytes, or is not power
	 * of two aligned, then we insert a 32 bytes of headroom
	 * to allow for inlining backtraces, etc.  We also allow the
	 * amount of space at the end for the same reason.  Large aligned
	 * allocations are unmolested to avoid excessive overallocation.
	 */
	if ((sz < 1024) || ((sz & (sz-1)) != 0)) {
		rv = chunk_grow(&m->m_body, sz + 32, 32);
	} else {
		rv = chunk_grow(&m->m_body, sz, 0);
	}
	if (rv != 0) {
		chunk_free(&m->m_header);
		nni_free(m, sizeof (*m));
	}
	if ((rv = chunk_append(&m->m_body, NULL, sz)) != 0) {
		/* Should not happen since we just grew it to fit. */
		nni_panic("chunk_append failed");
	}

	*mp = m;
	return (0);
}

void
nng_msg_free(nng_msg_t m)
{
	chunk_free(&m->m_header);
	chunk_free(&m->m_body);
	nni_free(m, sizeof (*m));
}

int
nng_msg_realloc(nng_msg_t m, size_t sz)
{
	int rv = 0;
	if (m->m_body.ch_len < sz) {
		rv = chunk_append(&m->m_body, NULL, sz - m->m_body.ch_len);
		if (rv != 0) {
			return (rv);
		}
	} else {
		/* "Shrinking", just mark bytes at end usable again. */
		chunk_trunc(&m->m_body, m->m_body.ch_len - sz);
	}
	return (0);
}

void *
nng_msg_header(nng_msg_t m, size_t *szp)
{
	if (szp != NULL) {
		*szp = m->m_header.ch_len;
	}
	return (m->m_header.ch_ptr);
}

void *
nng_msg_body(nng_msg_t m, size_t *szp)
{
	if (szp != NULL) {
		*szp = m->m_body.ch_len;
	}
	return (m->m_body.ch_ptr);
}

int
nng_msg_append(nng_msg_t m, const void *data, size_t len)
{
	return (chunk_append(&m->m_body, data, len));
}

int
nng_msg_prepend(nng_msg_t m, const void *data, size_t len)
{
	return (chunk_prepend(&m->m_body, data, len));
}

int
nng_msg_trim(nng_msg_t m, size_t len)
{
	return (chunk_trim(&m->m_body, len));
}

int
nng_msg_trunc(nng_msg_t m, size_t len)
{
	return (chunk_trunc(&m->m_body, len));
}

int
nng_msg_append_header(nng_msg_t m, const void *data, size_t len)
{
	return (chunk_append(&m->m_header, data, len));
}

int
nng_msg_prepend_header(nng_msg_t m, const void *data, size_t len)
{
	return (chunk_prepend(&m->m_header, data, len));
}

int
nng_msg_trim_header(nng_msg_t m, size_t len)
{
	return (chunk_trim(&m->m_header, len));
}

int
nng_msg_trunc_header(nng_msg_t m, size_t len)
{
	return (chunk_trunc(&m->m_header, len));
}

int
nng_msg_pipe(nng_msg_t m, nng_pipe_t *pp)
{
	*pp = m->m_pipe;
	return (0);
}
