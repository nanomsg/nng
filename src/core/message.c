//
// Copyright 2016 Garrett D'Amore <garrett@damore.org>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <stdlib.h>
#include <string.h>

#include "core/nng_impl.h"

// Message API.

// Message chunk, internal to the message implementation.
typedef struct {
	size_t		ch_cap;         // allocated size
	size_t		ch_len;         // length in use
	uint8_t *	ch_buf;         // underlying buffer
	uint8_t *	ch_ptr;         // pointer to actual data
} nni_chunk;

// Underlying message structure.
struct nng_msg {
	nni_chunk	m_header;
	nni_chunk	m_body;
	nni_time	m_expire;       // usec
	nni_list	m_options;
};

typedef struct {
	int		mo_num;
	size_t		mo_sz;
	void *		mo_val;
	nni_list_node	mo_node;
} nni_msgopt;


// nni_chunk_grow increases the underlying space for a chunk.  It ensures
// that the desired amount of trailing space (including the length)
// and headroom (excluding the length) are available.  It also copies
// any extant referenced data.  Note that the capacity will increase,
// but not the length.  To increase the length of the referenced data,
// use either chunk_append or chunk_prepend.
//
// Note that having some headroom is useful when data must be prepended
// to a message - it avoids having to perform extra data copies, so we
// encourage initial allocations to start with sufficient room.
static int
nni_chunk_grow(nni_chunk *ch, size_t newsz, size_t headwanted)
{
	size_t headroom = 0;
	uint8_t *newbuf;

	// We assume that if the pointer is a valid pointer, and inside
	// the backing store, then the entire data length fits.  In this
	// case we perform a logical realloc, except we don't copy any
	// unreferenced data.  We do preserve the headroom of the previous
	// use, since that may be there for a reason.
	//
	// The test below also covers the case where the pointers are both
	// NULL, or the capacity is zero.

	if ((ch->ch_ptr >= ch->ch_buf) &&
	    (ch->ch_ptr < (ch->ch_buf + ch->ch_cap))) {
		headroom = (size_t) (ch->ch_ptr - ch->ch_buf);
		if (((newsz + headwanted) < ch->ch_cap) &&
		    (headwanted <= headroom)) {
			// We have enough space at the ends already.
			return (0);
		}
		if (headwanted < headroom) {
			// We never shrink... headroom either.
			headwanted = headroom;
		}
		if ((newbuf = nni_alloc(newsz + headwanted)) == NULL) {
			return (NNG_ENOMEM);
		}
		// Copy all the data, but not header or trailer.
		memcpy(newbuf + headwanted, ch->ch_buf + headroom, ch->ch_len);
		nni_free(ch->ch_buf, ch->ch_cap);
		ch->ch_buf = newbuf;
		ch->ch_ptr = newbuf + headwanted;
		ch->ch_cap = newsz + headwanted;
		return (0);
	}

	// We either don't have a data pointer yet, or it doesn't reference
	// the backing store.  In this case, we just check against the
	// allocated capacity and grow, or don't grow.
	if (newsz < ch->ch_cap) {
		// Enough space at end, so just use it.
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
nni_chunk_free(nni_chunk *ch)
{
	if ((ch->ch_cap != 0) && (ch->ch_buf != NULL)) {
		nni_free(ch->ch_buf, ch->ch_cap);
	}
	ch->ch_ptr = NULL;
	ch->ch_buf = NULL;
	ch->ch_len = 0;
	ch->ch_cap = 0;
}


// nni_chunk_trunc truncates bytes from the end of the chunk.
static int
nni_chunk_trunc(nni_chunk *ch, size_t len)
{
	if (ch->ch_len < len) {
		return (NNG_EINVAL);
	}
	ch->ch_len -= len;
	return (0);
}


// nni_chunk_trim removes bytes from the beginning of the chunk.
static int
nni_chunk_trim(nni_chunk *ch, size_t len)
{
	if (ch->ch_len < len) {
		return (NNG_EINVAL);
	}
	ch->ch_ptr += len;
	ch->ch_len -= len;
	return (0);
}


// nni_chunk_append appends the data to the chunk, growing as necessary.
// If the data pointer is NULL, then the chunk data region is allocated,
// but uninitialized.
static int
nni_chunk_append(nni_chunk *ch, const void *data, size_t len)
{
	int rv;

	if (len == 0) {
		return (0);
	}
	if ((rv = nni_chunk_grow(ch, len + ch->ch_len, 0)) != 0) {
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


// nni_chunk_prepend prepends data to the chunk, as efficiently as possible.
// If the data pointer is NULL, then no data is actually copied, but the
// data region will have "grown" in the beginning, with uninitialized data.
static int
nni_chunk_prepend(nni_chunk *ch, const void *data, size_t len)
{
	int rv;

	if (ch->ch_ptr == NULL) {
		ch->ch_ptr = ch->ch_buf;
	}

	if ((ch->ch_ptr >= ch->ch_buf) &&
	    (ch->ch_ptr < (ch->ch_buf + ch->ch_cap)) &&
	    (len <= (size_t) (ch->ch_ptr - ch->ch_buf))) {
		// There is already enough room at the beginning.
		ch->ch_ptr -= len;
	} else if ((ch->ch_len + len) <= ch->ch_cap) {
		// We had enough capacity, just shuffle data down.
		memmove(ch->ch_ptr + len, ch->ch_ptr, ch->ch_len);
	} else if ((rv = nni_chunk_grow(ch, 0, len)) == 0) {
		// We grew the chunk, so adjust.
		ch->ch_ptr -= len;
	} else {
		// Couldn't grow the chunk either.  Error.
		return (rv);
	}

	ch->ch_len += len;
	if (data) {
		memcpy(ch->ch_ptr, data, len);
	}

	return (0);
}


int
nni_msg_alloc(nni_msg **mp, size_t sz)
{
	nni_msg *m;
	int rv;

	if ((m = nni_alloc(sizeof (*m))) == NULL) {
		return (NNG_ENOMEM);
	}

	// 64-bytes of header, including room for 32 bytes
	// of headroom and 32 bytes of trailer.
	if ((rv = nni_chunk_grow(&m->m_header, 32, 32)) != 0) {
		nni_free(m, sizeof (*m));
		return (rv);
	}

	// If the message is less than 1024 bytes, or is not power
	// of two aligned, then we insert a 32 bytes of headroom
	// to allow for inlining backtraces, etc.  We also allow the
	// amount of space at the end for the same reason.  Large aligned
	// allocations are unmolested to avoid excessive overallocation.
	if ((sz < 1024) || ((sz & (sz-1)) != 0)) {
		rv = nni_chunk_grow(&m->m_body, sz + 32, 32);
	} else {
		rv = nni_chunk_grow(&m->m_body, sz, 0);
	}
	if (rv != 0) {
		nni_chunk_free(&m->m_header);
		nni_free(m, sizeof (*m));
	}
	if ((rv = nni_chunk_append(&m->m_body, NULL, sz)) != 0) {
		// Should not happen since we just grew it to fit.
		nni_panic("chunk_append failed");
	}

	NNI_LIST_INIT(&m->m_options, nni_msgopt, mo_node);
	*mp = m;
	return (0);
}


void
nni_msg_free(nni_msg *m)
{
	nni_msgopt *mo;

	nni_chunk_free(&m->m_header);
	nni_chunk_free(&m->m_body);
	while ((mo = nni_list_first(&m->m_options)) != NULL) {
		nni_list_remove(&m->m_options, mo);
		nni_free(mo, sizeof (*mo) + mo->mo_sz);
	}
	nni_free(m, sizeof (*m));
}


int
nni_msg_setopt(nni_msg *m, int opt, const void *val, size_t sz)
{
	// Find the existing option if present.  Note that if we alter
	// a value, we can wind up trashing old data due to ENOMEM.
	nni_msgopt *oldmo, *newmo;

	NNI_LIST_FOREACH (&m->m_options, oldmo) {
		if (oldmo->mo_num == opt) {
			if (sz == oldmo->mo_sz) {
				// nice! we can just overwrite old value
				memcpy(oldmo->mo_val, val, sz);
				return (0);
			}
			break;
		}
	}
	if ((newmo = nni_alloc(sizeof (*newmo) + sz)) == NULL) {
		return (NNG_ENOMEM);
	}
	newmo->mo_val = ((char *) newmo + sizeof (*newmo));
	newmo->mo_sz = sz;
	newmo->mo_num = opt;
	memcpy(newmo->mo_val, val, sz);
	if (oldmo != NULL) {
		nni_list_remove(&m->m_options, oldmo);
		nni_free(oldmo, sizeof (*oldmo) + oldmo->mo_sz);
	}
	nni_list_append(&m->m_options, newmo);
	return (0);
}


int
nni_msg_getopt(nni_msg *m, int opt, void *val, size_t *szp)
{
	nni_msgopt *mo;

	NNI_LIST_FOREACH (&m->m_options, mo) {
		if (mo->mo_num == opt) {
			int sz = *szp;
			if (sz > mo->mo_sz) {
				sz = mo->mo_sz;
				memcpy(val, mo->mo_val, sz);
				*szp = mo->mo_sz;
				return (0);
			}
		}
	}
	return (NNG_ENOTSUP);
}


int
nni_msg_realloc(nni_msg *m, size_t sz)
{
	int rv = 0;

	if (m->m_body.ch_len < sz) {
		rv = nni_chunk_append(&m->m_body, NULL, sz - m->m_body.ch_len);
		if (rv != 0) {
			return (rv);
		}
	} else {
		// "Shrinking", just mark bytes at end usable again.
		nni_chunk_trunc(&m->m_body, m->m_body.ch_len - sz);
	}
	return (0);
}


void *
nni_msg_header(nni_msg *m, size_t *szp)
{
	if (szp != NULL) {
		*szp = m->m_header.ch_len;
	}
	return (m->m_header.ch_ptr);
}


void *
nni_msg_body(nni_msg *m, size_t *szp)
{
	if (szp != NULL) {
		*szp = m->m_body.ch_len;
	}
	return (m->m_body.ch_ptr);
}


int
nni_msg_append(nni_msg *m, const void *data, size_t len)
{
	return (nni_chunk_append(&m->m_body, data, len));
}


int
nni_msg_prepend(nni_msg *m, const void *data, size_t len)
{
	return (nni_chunk_prepend(&m->m_body, data, len));
}


int
nni_msg_trim(nni_msg *m, size_t len)
{
	return (nni_chunk_trim(&m->m_body, len));
}


int
nni_msg_trunc(nni_msg *m, size_t len)
{
	return (nni_chunk_trunc(&m->m_body, len));
}


int
nni_msg_append_header(nni_msg *m, const void *data, size_t len)
{
	return (nni_chunk_append(&m->m_header, data, len));
}


int
nni_msg_prepend_header(nni_msg *m, const void *data, size_t len)
{
	return (nni_chunk_prepend(&m->m_header, data, len));
}


int
nni_msg_trim_header(nni_msg *m, size_t len)
{
	return (nni_chunk_trim(&m->m_header, len));
}


int
nni_msg_trunc_header(nni_msg *m, size_t len)
{
	return (nni_chunk_trunc(&m->m_header, len));
}
