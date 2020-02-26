//
// Copyright 2020 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <string.h>

#include "core/nng_impl.h"

// Message API.

// Message chunk, internal to the message implementation.
typedef struct {
	size_t   ch_cap; // allocated size
	size_t   ch_len; // length in use
	uint8_t *ch_buf; // underlying buffer
	uint8_t *ch_ptr; // pointer to actual data
} nni_chunk;

// Underlying message structure.
struct nng_msg {
	uint32_t       m_header_buf[(NNI_MAX_MAX_TTL + 1)];
	size_t         m_header_len;
	nni_chunk      m_body;
	uint32_t       m_pipe; // set on receive
	nni_atomic_int m_refcnt;
};

#if 0
static void
nni_chunk_dump(const nni_chunk *chunk, char *prefix)
{
	size_t  i, j;
	uint8_t x;
	char    buf[128];

	(void) snprintf(buf, sizeof(buf),
	    " %s (cap %d, len %d, offset %d ptr %p):", prefix,
	    (int) chunk->ch_cap, (int) chunk->ch_len,
	    (int) (chunk->ch_ptr - chunk->ch_buf), chunk->ch_ptr);
	nni_println(buf);

	buf[0] = 0;
	for (i = 0, j = 0; i < chunk->ch_len; i++) {
		if ((i % 16) == 0) {
			if (j > 0) {
				buf[j++] = '\0';
				nni_println(buf);
				j = 0;
			}
			snprintf(buf, sizeof(buf), " %4x: ", (unsigned) i);
			j += strlen(buf);
		}
		buf[j++] = ' ';
		x        = (chunk->ch_ptr[i] >> 4);
		buf[j++] = x > 9 ? ('A' + (x - 10)) : '0' + x;
		x        = (chunk->ch_ptr[i] & 0x0f);
		buf[j++] = x > 9 ? ('A' + (x - 10)) : '0' + x;
	}
	if (j > 0) {
		buf[j++] = '\0';
		nni_println(buf);
	}
}

void
nni_msg_dump(const char *banner, const nni_msg *msg)
{
	char buf[128];

	(void) snprintf(buf, sizeof(buf), "--- %s BEGIN ---", banner);
	nni_println(buf);
	// TODO: dump the header
	nni_chunk_dump(&msg->m_body, "BODY");
	nni_println("--- END ---");
}
#endif

// nni_chunk_grow increases the underlying space for a chunk.  It ensures
// that the desired amount of trailing space (including the length)
// and headroom (excluding the length) are available.  It also copies
// any extant referenced data.  Note that the capacity will increase,
// but not the length.  To increase the length of the referenced data,
// use either chunk_append or chunk_insert.
//
// Note that having some headroom is useful when data must be prepended
// to a message - it avoids having to perform extra data copies, so we
// encourage initial allocations to start with sufficient room.
static int
nni_chunk_grow(nni_chunk *ch, size_t newsz, size_t headwanted)
{
	uint8_t *newbuf;

	// We assume that if the pointer is a valid pointer, and inside
	// the backing store, then the entire data length fits.  In this
	// case we perform a logical realloc, except we don't copy any
	// unreferenced data.  We do preserve the headroom of the previous
	// use, since that may be there for a reason.
	//
	// The test below also covers the case where the pointers are both
	// NULL, or the capacity is zero.

	// No shrinking (violets)
	if (newsz < ch->ch_len) {
		newsz = ch->ch_len;
	}

	if ((ch->ch_ptr >= ch->ch_buf) &&
	    (ch->ch_ptr < (ch->ch_buf + ch->ch_cap))) {
		size_t headroom = (size_t)(ch->ch_ptr - ch->ch_buf);
		if (headwanted < headroom) {
			headwanted = headroom; // Never shrink this.
		}
		if (((newsz + headwanted) <= ch->ch_cap) &&
		    (headwanted <= headroom)) {
			// We have enough space at the ends already.
			return (0);
		}
		// Make sure we allocate at least as much tail room as we
		// previously had.

		if (newsz < (ch->ch_cap - headroom)) {
			newsz = ch->ch_cap - headroom;
		}

		if ((newbuf = nni_zalloc(newsz + headwanted)) == NULL) {
			return (NNG_ENOMEM);
		}
		// Copy all the data, but not header or trailer.
		if (ch->ch_len > 0) {
			memcpy(newbuf + headwanted, ch->ch_ptr, ch->ch_len);
		}
		nni_free(ch->ch_buf, ch->ch_cap);
		ch->ch_buf = newbuf;
		ch->ch_ptr = newbuf + headwanted;
		ch->ch_cap = newsz + headwanted;
		return (0);
	}

	// We either don't have a data pointer yet, or it doesn't reference
	// the backing store.  In this case, we just check against the
	// allocated capacity and grow, or don't grow.
	if ((newsz + headwanted) >= ch->ch_cap) {
		if ((newbuf = nni_zalloc(newsz + headwanted)) == NULL) {
			return (NNG_ENOMEM);
		}
		nni_free(ch->ch_buf, ch->ch_cap);
		ch->ch_cap = newsz + headwanted;
		ch->ch_buf = newbuf;
	}

	ch->ch_ptr = ch->ch_buf + headwanted;
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

// nni_chunk_clear just resets the length to zero.
static void
nni_chunk_clear(nni_chunk *ch)
{
	ch->ch_len = 0;
}

// nni_chunk_chop truncates bytes from the end of the chunk.
static int
nni_chunk_chop(nni_chunk *ch, size_t len)
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
	ch->ch_len -= len;
	// Don't advance the pointer if we are just removing the whole content
	if (ch->ch_len != 0) {
		ch->ch_ptr += len;
	}
	return (0);
}

// nni_chunk_dup allocates storage for a new chunk, and copies
// the contents of the source to the destination.  The new chunk will
// have the same size, headroom, and capacity as the original.
static int
nni_chunk_dup(nni_chunk *dst, const nni_chunk *src)
{
	if ((dst->ch_buf = nni_zalloc(src->ch_cap)) == NULL) {
		return (NNG_ENOMEM);
	}
	dst->ch_cap = src->ch_cap;
	dst->ch_len = src->ch_len;
	dst->ch_ptr = dst->ch_buf + (src->ch_ptr - src->ch_buf);
	if (dst->ch_len > 0) {
		memcpy(dst->ch_ptr, src->ch_ptr, dst->ch_len);
	}
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

// nni_chunk_room determines the extra space we have left in the chunk.
// This is useful to determine whether we will need to reallocate and
// copy in order to save space.
static size_t
nni_chunk_room(nni_chunk *ch)
{
	return (ch->ch_cap - ch->ch_len);
}

// nni_chunk_insert prepends data to the chunk, as efficiently as possible.
// If the data pointer is NULL, then no data is actually copied, but the
// data region will have "grown" in the beginning, with uninitialized data.
static int
nni_chunk_insert(nni_chunk *ch, const void *data, size_t len)
{
	int rv;

	if (ch->ch_ptr == NULL) {
		ch->ch_ptr = ch->ch_buf;
	}

	if ((ch->ch_ptr >= ch->ch_buf) &&
	    (ch->ch_ptr < (ch->ch_buf + ch->ch_cap)) &&
	    (len <= (size_t)(ch->ch_ptr - ch->ch_buf))) {
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
	if (data != NULL) {
		memcpy(ch->ch_ptr, data, len);
	}

	return (0);
}

static uint32_t
nni_chunk_trim_u32(nni_chunk *ch)
{
	uint32_t v;
	NNI_ASSERT(ch->ch_len >= sizeof(v));
	NNI_GET32(ch->ch_ptr, v);
	nni_chunk_trim(ch, sizeof(v));
	return (v);
}

void
nni_msg_clone(nni_msg *m)
{
	nni_atomic_inc(&m->m_refcnt);
}

// This returns either the original message or a new message on success.
// If it fails, then NULL is returned.  Either way the original message
// has its reference count dropped (and freed if zero).
nni_msg *
nni_msg_unique(nni_msg *m)
{
	nni_msg *m2;

	// If we already have an exclusive copy, just keep using it.
	if (nni_atomic_get(&m->m_refcnt) == 1) {
		return (m);
	}
	// Otherwise we need to make a copy
	if (nni_msg_dup(&m2, m) != 0) {
		m2 = NULL;
	}
	nni_msg_free(m);
	return (m2);
}

// nni_msg_pull_up ensures that the message is unique, and that any header
// is merged with the message.  The main purpose of doing this is to break
// up the inproc binding -- protocols send messages to inproc with a
// separate header, but they really would like receive a unified
// message so they can pick apart the header.
nni_msg *
nni_msg_pull_up(nni_msg *m)
{
	// This implementation is optimized to ensure that this function
	// will not copy the message more than once, and it will not
	// allocate unless there is no other option.
	if (((nni_chunk_room(&m->m_body) < nni_msg_header_len(m))) ||
	    (nni_atomic_get(&m->m_refcnt) != 1)) {
		// We have to duplicate the message.
		nni_msg *m2;
		uint8_t *dst;
		size_t   len = nni_msg_len(m) + nni_msg_header_len(m);
		if (nni_msg_alloc(&m2, len) != 0) {
			return (NULL);
		}
		dst = nni_msg_body(m2);
		len = nni_msg_header_len(m);
		memcpy(dst, nni_msg_header(m), len);
		dst += len;
		memcpy(dst, nni_msg_body(m), nni_msg_len(m));
		nni_msg_free(m);
		return (m2);
	}

	// At this point, we have a unique instance of the message.
	// We also know that we have sufficient space in the message,
	// so this insert operation cannot fail.
	nni_msg_insert(m, nni_msg_header(m), nni_msg_header_len(m));
	nni_msg_header_clear(m);
	return (m);
}

int
nni_msg_alloc(nni_msg **mp, size_t sz)
{
	nni_msg *m;
	int      rv;

	if ((m = NNI_ALLOC_STRUCT(m)) == NULL) {
		return (NNG_ENOMEM);
	}

	// If the message is less than 1024 bytes, or is not power
	// of two aligned, then we insert a 32 bytes of headroom
	// to allow for inlining backtraces, etc.  We also allow the
	// amount of space at the end for the same reason.  Large aligned
	// allocations are unmolested to avoid excessive overallocation.
	if ((sz < 1024) || ((sz & (sz - 1)) != 0)) {
		rv = nni_chunk_grow(&m->m_body, sz + 32, 32);
	} else {
		rv = nni_chunk_grow(&m->m_body, sz, 0);
	}
	if (rv != 0) {
		NNI_FREE_STRUCT(m);
		return (rv);
	}
	if (nni_chunk_append(&m->m_body, NULL, sz) != 0) {
		// Should not happen since we just grew it to fit.
		nni_panic("chunk_append failed");
	}

	// We always start with a single valid reference count.
	nni_atomic_init(&m->m_refcnt);
	nni_atomic_set(&m->m_refcnt, 1);
	*mp = m;
	return (0);
}

int
nni_msg_dup(nni_msg **dup, const nni_msg *src)
{
	nni_msg *m;
	int      rv;

	if ((m = NNI_ALLOC_STRUCT(m)) == NULL) {
		return (NNG_ENOMEM);
	}

	memcpy(m->m_header_buf, src->m_header_buf, src->m_header_len);
	m->m_header_len = src->m_header_len;

	if ((rv = nni_chunk_dup(&m->m_body, &src->m_body)) != 0) {
		NNI_FREE_STRUCT(m);
		return (rv);
	}

	m->m_pipe = src->m_pipe;
	nni_atomic_init(&m->m_refcnt);
	nni_atomic_set(&m->m_refcnt, 1);

	*dup = m;
	return (0);
}

void
nni_msg_free(nni_msg *m)
{
	if ((m != NULL) && (nni_atomic_dec_nv(&m->m_refcnt) == 0)) {
		nni_chunk_free(&m->m_body);
		NNI_FREE_STRUCT(m);
	}
}

int
nni_msg_realloc(nni_msg *m, size_t sz)
{
	if (m->m_body.ch_len < sz) {
		int rv =
		    nni_chunk_append(&m->m_body, NULL, sz - m->m_body.ch_len);
		if (rv != 0) {
			return (rv);
		}
	} else {
		// "Shrinking", just mark bytes at end usable again.
		nni_chunk_chop(&m->m_body, m->m_body.ch_len - sz);
	}
	return (0);
}

void *
nni_msg_header(nni_msg *m)
{
	return (m->m_header_buf);
}

size_t
nni_msg_header_len(const nni_msg *m)
{
	return (m->m_header_len);
}

void *
nni_msg_body(nni_msg *m)
{
	return (m->m_body.ch_ptr);
}

size_t
nni_msg_len(const nni_msg *m)
{
	return (m->m_body.ch_len);
}

int
nni_msg_append(nni_msg *m, const void *data, size_t len)
{
	return (nni_chunk_append(&m->m_body, data, len));
}

int
nni_msg_insert(nni_msg *m, const void *data, size_t len)
{
	return (nni_chunk_insert(&m->m_body, data, len));
}

int
nni_msg_trim(nni_msg *m, size_t len)
{
	return (nni_chunk_trim(&m->m_body, len));
}

uint32_t
nni_msg_trim_u32(nni_msg *m)
{
	return (nni_chunk_trim_u32(&m->m_body));
}

int
nni_msg_chop(nni_msg *m, size_t len)
{
	return (nni_chunk_chop(&m->m_body, len));
}

int
nni_msg_header_append(nni_msg *m, const void *data, size_t len)
{
	if ((len + m->m_header_len) > sizeof(m->m_header_buf)) {
		return (NNG_EINVAL);
	}
	memcpy(((uint8_t *) m->m_header_buf) + m->m_header_len, data, len);
	m->m_header_len += len;
	return (0);
}

int
nni_msg_header_insert(nni_msg *m, const void *data, size_t len)
{
	if ((len + m->m_header_len) > sizeof(m->m_header_buf)) {
		return (NNG_EINVAL);
	}
	memmove(((uint8_t *) m->m_header_buf) + len, m->m_header_buf,
	    m->m_header_len);
	memcpy(m->m_header_buf, data, len);
	m->m_header_len += len;
	return (0);
}

int
nni_msg_header_trim(nni_msg *m, size_t len)
{
	if (len > m->m_header_len) {
		return (NNG_EINVAL);
	}
	memmove(m->m_header_buf, ((uint8_t *) m->m_header_buf) + len,
	    m->m_header_len - len);
	m->m_header_len -= len;
	return (0);
}

int
nni_msg_header_chop(nni_msg *m, size_t len)
{
	if (len > m->m_header_len) {
		return (NNG_EINVAL);
	}
	m->m_header_len -= len;
	return (0);
}

uint32_t
nni_msg_header_trim_u32(nni_msg *m)
{
	uint32_t val;
	uint8_t *dst;
	dst = (void *) m->m_header_buf;
	NNI_GET32(dst, val);
	m->m_header_len -= sizeof(val);
	memmove(m->m_header_buf, &m->m_header_buf[1], m->m_header_len);
	return (val);
}

void
nni_msg_header_append_u32(nni_msg *m, uint32_t val)
{
	uint8_t *dst;
	if ((m->m_header_len + sizeof(val)) >= (sizeof(m->m_header_buf))) {
		nni_panic("impossible header over-run");
	}
	dst = (void *) m->m_header_buf;
	dst += m->m_header_len;
	NNI_PUT32(dst, val);
	m->m_header_len += sizeof(val);
}

void
nni_msg_clear(nni_msg *m)
{
	m->m_header_len = 0;
	nni_chunk_clear(&m->m_body);
}

void
nni_msg_header_clear(nni_msg *m)
{
	m->m_header_len = 0;
}

void
nni_msg_set_pipe(nni_msg *m, uint32_t pid)
{
	m->m_pipe = pid;
}

uint32_t
nni_msg_get_pipe(const nni_msg *m)
{
	return (m->m_pipe);
}
