//
// Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <stdio.h>
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
	nni_chunk m_header;
	nni_chunk m_body;
	nni_time  m_expire; // usec
	nni_list  m_options;
	uint32_t  m_pipe; // set on receive
};

typedef struct {
	int           mo_num;
	size_t        mo_sz;
	void *        mo_val;
	nni_list_node mo_node;
} nni_msgopt;

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
	nni_chunk_dump(&msg->m_header, "HEADER");
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
		memcpy(newbuf + headwanted, ch->ch_ptr, ch->ch_len);
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
	memcpy(dst->ch_ptr, src->ch_ptr, dst->ch_len);
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
	if (data) {
		memcpy(ch->ch_ptr, data, len);
	}

	return (0);
}

static int
nni_chunk_insert_u16(nni_chunk *ch, uint16_t val)
{
	unsigned char buf[sizeof(uint16_t)];
	NNI_PUT16(buf, val);
	return (nni_chunk_insert(ch, buf, sizeof(buf)));
}

static int
nni_chunk_append_u16(nni_chunk *ch, uint16_t val)
{
	unsigned char buf[sizeof(uint16_t)];
	NNI_PUT16(buf, val);
	return (nni_chunk_append(ch, buf, sizeof(buf)));
}

static uint16_t
nni_chunk_trim_u16(nni_chunk *ch)
{
	uint16_t v;
	NNI_ASSERT(ch->ch_len >= sizeof(v));
	NNI_GET16(ch->ch_ptr, v);
	nni_chunk_trim(ch, sizeof(v));
	return (v);
}

static uint16_t
nni_chunk_chop_u16(nni_chunk *ch)
{
	uint16_t v;
	NNI_ASSERT(ch->ch_len >= sizeof(v));
	NNI_GET16(ch->ch_ptr + ch->ch_len - sizeof(v), v);
	nni_chunk_chop(ch, sizeof(v));
	return (v);
}

static int
nni_chunk_insert_u32(nni_chunk *ch, uint32_t val)
{
	unsigned char buf[sizeof(uint32_t)];
	NNI_PUT32(buf, val);
	return (nni_chunk_insert(ch, buf, sizeof(buf)));
}

static int
nni_chunk_append_u32(nni_chunk *ch, uint32_t val)
{
	unsigned char buf[sizeof(uint32_t)];
	NNI_PUT32(buf, val);
	return (nni_chunk_append(ch, buf, sizeof(buf)));
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

static uint32_t
nni_chunk_chop_u32(nni_chunk *ch)
{
	uint32_t v;
	NNI_ASSERT(ch->ch_len >= sizeof(v));
	NNI_GET32(ch->ch_ptr + ch->ch_len - sizeof(v), v);
	nni_chunk_chop(ch, sizeof(v));
	return (v);
}

static int
nni_chunk_insert_u64(nni_chunk *ch, uint64_t val)
{
	unsigned char buf[sizeof(uint64_t)];
	NNI_PUT64(buf, val);
	return (nni_chunk_insert(ch, buf, sizeof(buf)));
}

static int
nni_chunk_append_u64(nni_chunk *ch, uint64_t val)
{
	unsigned char buf[sizeof(uint64_t)];
	NNI_PUT64(buf, val);
	return (nni_chunk_append(ch, buf, sizeof(buf)));
}

static uint64_t
nni_chunk_trim_u64(nni_chunk *ch)
{
	uint64_t v;
	NNI_ASSERT(ch->ch_len >= sizeof(v));
	NNI_GET64(ch->ch_ptr, v);
	nni_chunk_trim(ch, sizeof(v));
	return (v);
}

static uint64_t
nni_chunk_chop_u64(nni_chunk *ch)
{
	uint64_t v;
	NNI_ASSERT(ch->ch_len >= sizeof(v));
	NNI_GET64(ch->ch_ptr + ch->ch_len - sizeof(v), v);
	nni_chunk_chop(ch, sizeof(v));
	return (v);
}

int
nni_msg_alloc(nni_msg **mp, size_t sz)
{
	nni_msg *m;
	int      rv;

	if ((m = NNI_ALLOC_STRUCT(m)) == NULL) {
		return (NNG_ENOMEM);
	}

	// 64-bytes of header, including room for 32 bytes
	// of headroom and 32 bytes of trailer.
	if ((rv = nni_chunk_grow(&m->m_header, 32, 32)) != 0) {
		NNI_FREE_STRUCT(m);
		return (rv);
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
		nni_chunk_free(&m->m_header);
		NNI_FREE_STRUCT(m);
	}
	if ((rv = nni_chunk_append(&m->m_body, NULL, sz)) != 0) {
		// Should not happen since we just grew it to fit.
		nni_panic("chunk_append failed");
	}

	NNI_LIST_INIT(&m->m_options, nni_msgopt, mo_node);
	*mp = m;
	return (0);
}

int
nni_msg_dup(nni_msg **dup, const nni_msg *src)
{
	nni_msg *   m;
	nni_msgopt *mo;
	nni_msgopt *newmo;
	int         rv;

	if ((m = NNI_ALLOC_STRUCT(m)) == NULL) {
		return (NNG_ENOMEM);
	}
	NNI_LIST_INIT(&m->m_options, nni_msgopt, mo_node);

	if ((rv = nni_chunk_dup(&m->m_header, &src->m_header)) != 0) {
		NNI_FREE_STRUCT(m);
		return (rv);
	}
	if ((rv = nni_chunk_dup(&m->m_body, &src->m_body)) != 0) {
		nni_chunk_free(&m->m_header);
		NNI_FREE_STRUCT(m);
		return (rv);
	}

	NNI_LIST_FOREACH (&src->m_options, mo) {
		newmo = nni_zalloc(sizeof(*newmo) + mo->mo_sz);
		if (newmo == NULL) {
			nni_msg_free(m);
			return (NNG_ENOMEM);
		}
		newmo->mo_val = ((char *) newmo + sizeof(*newmo));
		newmo->mo_sz  = mo->mo_sz;
		newmo->mo_num = mo->mo_num;
		memcpy(newmo->mo_val, mo->mo_val, mo->mo_sz);
		nni_list_append(&m->m_options, newmo);
	}
	m->m_pipe = src->m_pipe;

	*dup = m;
	return (0);
}

void
nni_msg_free(nni_msg *m)
{
	nni_msgopt *mo;

	if (m != NULL) {
		nni_chunk_free(&m->m_header);
		nni_chunk_free(&m->m_body);
		while ((mo = nni_list_first(&m->m_options)) != NULL) {
			nni_list_remove(&m->m_options, mo);
			nni_free(mo, sizeof(*mo) + mo->mo_sz);
		}
		NNI_FREE_STRUCT(m);
	}
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
	if ((newmo = nni_zalloc(sizeof(*newmo) + sz)) == NULL) {
		return (NNG_ENOMEM);
	}
	newmo->mo_val = ((char *) newmo + sizeof(*newmo));
	newmo->mo_sz  = sz;
	newmo->mo_num = opt;
	memcpy(newmo->mo_val, val, sz);
	if (oldmo != NULL) {
		nni_list_remove(&m->m_options, oldmo);
		nni_free(oldmo, sizeof(*oldmo) + oldmo->mo_sz);
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
			size_t sz = *szp;
			if (sz > mo->mo_sz) {
				sz = mo->mo_sz;
				memcpy(val, mo->mo_val, sz);
				*szp = mo->mo_sz;
				return (0);
			}
		}
	}
	return (NNG_ENOENT);
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
	return (m->m_header.ch_ptr);
}

size_t
nni_msg_header_len(const nni_msg *m)
{
	return (m->m_header.ch_len);
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

int
nni_msg_chop(nni_msg *m, size_t len)
{
	return (nni_chunk_chop(&m->m_body, len));
}

int
nni_msg_header_append(nni_msg *m, const void *data, size_t len)
{
	return (nni_chunk_append(&m->m_header, data, len));
}

int
nni_msg_header_insert(nni_msg *m, const void *data, size_t len)
{
	return (nni_chunk_insert(&m->m_header, data, len));
}

int
nni_msg_header_trim(nni_msg *m, size_t len)
{
	return (nni_chunk_trim(&m->m_header, len));
}

int
nni_msg_header_chop(nni_msg *m, size_t len)
{
	return (nni_chunk_chop(&m->m_header, len));
}

#define DEF_MSG_ADD_N(z, x)                                      \
	int nni_msg_##z##_u##x(nni_msg *m, uint##x##_t v)        \
	{                                                        \
		return (nni_chunk_##z##_u##x(&m->m_body, v));    \
	}                                                        \
	int nni_msg_header_##z##_u##x(nni_msg *m, uint##x##_t v) \
	{                                                        \
		return (nni_chunk_##z##_u##x(&m->m_header, v));  \
	}

#define DEF_MSG_REM_N(z, x)                                  \
	uint##x##_t nni_msg_##z##_u##x(nni_msg *m)           \
	{                                                    \
		return (nni_chunk_##z##_u##x(&m->m_body));   \
	}                                                    \
	uint##x##_t nni_msg_header_##z##_u##x(nni_msg *m)    \
	{                                                    \
		return (nni_chunk_##z##_u##x(&m->m_header)); \
	}

#define DEF_MSG_ADD(op) \
	DEF_MSG_ADD_N(op, 16) DEF_MSG_ADD_N(op, 32) DEF_MSG_ADD_N(op, 64)
#define DEF_MSG_REM(op) \
	DEF_MSG_REM_N(op, 16) DEF_MSG_REM_N(op, 32) DEF_MSG_REM_N(op, 64)

DEF_MSG_ADD(append)
DEF_MSG_ADD(insert)
DEF_MSG_REM(chop)
DEF_MSG_REM(trim)

#undef DEF_MSG_ADD_N
#undef DEF_MSG_REM_N
#undef DEF_MSG_ADD
#undef DEF_MSG_REM

void
nni_msg_clear(nni_msg *m)
{
	nni_chunk_clear(&m->m_body);
}

void
nni_msg_header_clear(nni_msg *m)
{
	nni_chunk_clear(&m->m_header);
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
