//
// Copyright 2024 Staysail Systems, Inc. <info@staysail.tech>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "defs.h"

#include <stdio.h>
#include <string.h>

static const char *
str_sa_inproc(const nng_sockaddr_inproc *sa, char *buf, size_t bufsz)
{
	snprintf(buf, bufsz, "inproc[%s]", sa->sa_name);
	return buf;
}

static const char *
str_sa_inet(const nng_sockaddr_in *sa, char *buf, size_t bufsz)
{
	uint8_t *a_bytes = (uint8_t *) &sa->sa_addr;
	uint8_t *p_bytes = (uint8_t *) &sa->sa_port;
	char     ipbuf[46];

	snprintf(buf, bufsz, "%s:%u",
	    nni_inet_ntop(NNG_AF_INET, a_bytes, ipbuf),
	    (((uint16_t) p_bytes[0]) << 8) + p_bytes[1]);
	return (buf);
}

// emit an IP address, only NNG_AF_INET and NNG_AF_INET6 explicitly are
// supported.  (NO support for NNG_AF_UNSPEC.)
char *
nni_inet_ntop(enum nng_sockaddr_family af, const uint8_t *addr, char *buf)
{
	if (af == NNG_AF_INET) {
		snprintf(buf, 46, "%u.%u.%u.%u", addr[0], addr[1], addr[2],
		    addr[3]);
		return (buf);
	}
	if (af != NNG_AF_INET6) {
		return (NULL);
	}

	const uint8_t v4map[12] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff };

	if (memcmp(addr, v4map, 12) == 0) {
		snprintf(buf, 46, "::ffff:%u.%u.%u.%u", addr[12], addr[13],
		    addr[14], addr[15]);
		return (buf);
	}

	uint8_t off    = 0; // offset of first set of elided zeros
	uint8_t cnt    = 0; // how many elided zeros so far
	uint8_t maxoff = 0; // offset of largest compressed region
	uint8_t maxcnt = 0; // how many elided zeros at maxoff

	// look for the largest compressible region
	for (uint8_t i = 0; i < 16; i += 2) {
		// is this word zero?
		if ((addr[i] == 0) && (addr[i + 1] == 0)) {
			cnt += 2;
			// if this was the first zero word in region, record it
			if (cnt == 2) {
				off = i;
			}
			// possibly update the maximums
			if (cnt > maxcnt) {
				maxcnt = cnt;
				maxoff = off;
			}
		} else {
			cnt = 0;
		}
	}
	if (maxcnt < 2) {
		maxoff = 0xff; // too big for anything
	}

	int  idx = 0;
	bool sep = false;
	buf[0]   = 0;
	for (uint8_t i = 0; i < 16; i += 2) {
		// We have 46 bytes allocated, which is a "theoretical"
		// maximum only.  In practice the worst case is really
		// 8 groups of four digits with 7 colons, so 39 bytes plus
		// the null is 40 bytes.  We only use the v4 mapped syntax
		// when presented with ::ffff: - so 23 bytes for that syntax.
		if (i == maxoff) {
			NNI_ASSERT(idx <= 43);
			strcat(buf + idx, "::");
			idx += 2;
			sep = false;
		} else if (i < maxoff || i >= maxoff + maxcnt) {
			// this takes at most six bytes -- four hex digits a
			// colon, and a null
			NNI_ASSERT(idx <= 40);
			snprintf(buf + idx, 6, sep ? ":%x" : "%x",
			    (((uint16_t) addr[i]) << 8) + addr[i + 1]);
			idx += strlen(buf + idx);
			sep = true;
		}
	}
	return (buf);
}

static const char *
str_sa_inet6(const nng_sockaddr_in6 *sa, char *buf, size_t bufsz)
{
	const uint8_t *p_bytes = (uint8_t *) &sa->sa_port;
	char           istr[46];

	if (sa->sa_scope) {
		snprintf(buf, bufsz, "[%s%%%u]:%u",
		    nni_inet_ntop(NNG_AF_INET6, sa->sa_addr, istr),
		    sa->sa_scope,
		    (((uint16_t) (p_bytes[0])) << 8) + p_bytes[1]);
	} else {
		snprintf(buf, bufsz, "[%s]:%u",
		    nni_inet_ntop(NNG_AF_INET6, sa->sa_addr, istr),
		    (((uint16_t) (p_bytes[0])) << 8) + p_bytes[1]);
	}
	return (buf);
}

static const char *
str_sa_ipc(const nng_sockaddr_ipc *sa, char *buf, size_t bufsz)
{
	// does not deal well with embedded "{}" chars
	snprintf(buf, bufsz, "%s", sa->sa_path);
	return (buf);
}

static const char *
str_sa_abstract(const nng_sockaddr_abstract *sa, char *buf, size_t bufsz)
{
	// does not deal well with embedded "{}" chars
	snprintf(buf, bufsz, "abstract[%s]", sa->sa_name);
	return (buf);
}

const char *
nng_str_sockaddr(const nng_sockaddr *sa, char *buf, size_t bufsz)
{
	switch (sa->s_family) {
	case NNG_AF_INPROC:
		return (str_sa_inproc(&sa->s_inproc, buf, bufsz));
	case NNG_AF_INET:
		return (str_sa_inet(&sa->s_in, buf, bufsz));
	case NNG_AF_INET6:
		return (str_sa_inet6(&sa->s_in6, buf, bufsz));
	case NNG_AF_IPC:
		return (str_sa_ipc(&sa->s_ipc, buf, bufsz));
	case NNG_AF_ABSTRACT:
		return (str_sa_abstract(&sa->s_abstract, buf, bufsz));
	case NNG_AF_UNSPEC:
	default:
		return ("unknown");
	}
}

uint32_t
nng_sockaddr_port(const nng_sockaddr *sa)
{
	uint16_t port16;
	switch (sa->s_family) {
	case NNG_AF_INET:
		NNI_GET16(&sa->s_in.sa_port, port16);
		return (port16);
	case NNG_AF_INET6:
		NNI_GET16(&sa->s_in6.sa_port, port16);
		return (port16);
	default:
		return (0);
	}
}

bool
nng_sockaddr_equal(const nng_sockaddr *sa1, const nng_sockaddr *sa2)
{
	if (sa1->s_family != sa2->s_family) {
		return false;
	}
	switch (sa1->s_family) {
	case NNG_AF_INET:
		return ((sa1->s_in.sa_addr == sa2->s_in.sa_addr) &&
		    (sa1->s_in.sa_port == sa2->s_in.sa_port));
	case NNG_AF_INET6:
		return (
		    memcmp(&sa1->s_in6, &sa2->s_in6, sizeof(sa1->s_in6)) == 0);
	case NNG_AF_INPROC:
		return (
		    strcmp(sa1->s_inproc.sa_name, sa2->s_inproc.sa_name) == 0);
	case NNG_AF_IPC:
		return (strcmp(sa1->s_ipc.sa_path, sa2->s_ipc.sa_path) == 0);
	case NNG_AF_ABSTRACT:
		return (strcmp((char *) sa1->s_abstract.sa_name,
		            (char *) sa2->s_abstract.sa_name) == 0);
	default:
		return (false);
	}
}

// generate a quick non-zero 64-bit value for the sockaddr.
// This should usually be unique, but collisions are possible.
// The resulting hash is not portable and should not be used for
// anything except ephemeral uses (e.g. as an index into a id map.)
uint64_t
nng_sockaddr_hash(const nng_sockaddr *sa)
{
	uint64_t       val1, val2;
	size_t         len;
	const uint8_t *ptr;

	switch (sa->s_family) {
	case NNG_AF_INET:
		return (
		    ((uint64_t) (sa->s_in.sa_addr) << 16) + sa->s_in.sa_port);
	case NNG_AF_INET6:
		memcpy(&val1, sa->s_in6.sa_addr, sizeof(val1));
		memcpy(&val2, sa->s_in6.sa_addr + sizeof(val1), sizeof(val2));
		// the high order bit is set to ensure it cannot be zero
		return ((1ULL << 63) | (val1 ^ val2 ^ sa->s_in6.sa_port));
	case NNG_AF_IPC:
		len = strlen(sa->s_ipc.sa_path);
		ptr = (const uint8_t *) sa->s_ipc.sa_path;
		break;
	case NNG_AF_INPROC:
		len = strlen(sa->s_inproc.sa_name);
		ptr = (const uint8_t *) sa->s_inproc.sa_name;
		break;
	case NNG_AF_ABSTRACT:
		len = strlen((const char *) sa->s_abstract.sa_name);
		ptr = (const uint8_t *) sa->s_abstract.sa_name;
		break;
	default:
		// should never happen!
		return (sa->s_family);
	}

	// sort of a string based hash done 64-bits at time.
	val1 = 0;
	while (len >= sizeof(val2)) {
		memcpy(&val2, ptr, sizeof(val2));
		val1 ^= val2;
		len -= sizeof(val2);
		ptr += sizeof(val2);
	}
	if (len > 0) {
		val2 = 0;
		memcpy(&val2, ptr, len);
		val1 ^= val2;
	}
	return ((1ULL << 63) | val1);
}
