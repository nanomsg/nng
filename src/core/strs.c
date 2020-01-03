//
// Copyright 2020 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2017 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/nng_impl.h"

// This file contains implementation of utility functions that are not
// part of standard C99.  (C11 has added some things here, but we cannot
// count on them.)

// Note that we supply our own version of strdup and strfree unconditionally,
// so that these can be freed with nni_free(strlen(s)+1) if desired.  (Likewise
// a string buffer allocated with nni_alloc can be freed with nni_strfree
// provided the length is correct.)

char *
nni_strdup(const char *src)
{
	char * dst;
	size_t len = strlen(src) + 1;

	if ((dst = nni_alloc(len)) != NULL) {
		memcpy(dst, src, len);
	}
	return (dst);
}

void
nni_strfree(char *s)
{
	if (s != NULL) {
		nni_free(s, strlen(s) + 1);
	}
}

size_t
nni_strlcpy(char *dst, const char *src, size_t len)
{
#ifdef NNG_HAVE_STRLCPY
	return (strlcpy(dst, src, len));
#else
	size_t n;
	char   c;

	n = 0;
	do {
		c = *src++;
		n++;
		if (n < len) {
			*dst++ = c;
		} else if (n == len) {
			*dst = '\0';
		}
	} while (c);
	return (n - 1);
#endif
}

size_t
nni_strnlen(const char *s, size_t len)
{
#ifdef NNG_HAVE_STRNLEN
	return (strnlen(s, len));
#else
	size_t n;
	for (n = 0; (n < len) && (*s); n++) {
		s++;
	}
	return (n);
#endif
}

char *
nni_strcasestr(const char *s1, const char *s2)
{
#ifdef NNG_HAVE_STRCASESTR
	return (strcasestr(s1, s2));
#else
	const char *t1, *t2;
	while (*s1) {
		for (t1 = s1, t2 = s2; *t1 && *t2; t2++, t1++) {
			if (tolower(*t1) != tolower(*t2)) {
				break;
			}
		}
		if (*t2 == 0) {
			return ((char *) s1);
		}
		s1++;
	}
	return (NULL);
#endif
}

int
nni_strcasecmp(const char *s1, const char *s2)
{
#if defined(_WIN32)
	return (_stricmp(s1, s2));
#elif defined(NNG_HAVE_STRCASECMP)
	return (strcasecmp(s1, s2));
#else
	for (;;) {
		uint8_t c1 = (uint8_t) tolower(*s1++);
		uint8_t c2 = (uint8_t) tolower(*s2++);
		if (c1 == c2) {
			if (c1 == 0) {
				return (0);
			}
			continue;
		}
		return ((c1 < c2) ? -1 : 1);
	}
	return (0);
#endif
}

int
nni_strncasecmp(const char *s1, const char *s2, size_t n)
{
#if defined(_WIN32)
	return (_strnicmp(s1, s2, n));
#elif defined(NNG_HAVE_STRNCASECMP)
	return (strncasecmp(s1, s2, n));
#else
	for (int i = 0; i < n; i++) {
		uint8_t c1 = (uint8_t) tolower(*s1++);
		uint8_t c2 = (uint8_t) tolower(*s2++);
		if (c1 == c2) {
			if (c1 == 0) {
				return (0);
			}
			continue;
		}
		return ((c1 < c2) ? -1 : 1);
	}
	return (0);
#endif
}

// As with strdup, we always use our own, so that our strings
// can be freed with nni_strfree().
int
nni_asprintf(char **sp, const char *fmt, ...)
{
	va_list ap;
	size_t  len;
	char *  s;

	va_start(ap, fmt);
	len = vsnprintf(NULL, 0, fmt, ap);
	va_end(ap);
	len++;

	if ((s = nni_alloc(len)) == NULL) {
		return (NNG_ENOMEM);
	}
	va_start(ap, fmt);
	(void) vsnprintf(s, len, fmt, ap);
	va_end(ap);
	*sp = s;
	return (0);
}

int
nni_strtou64(const char *s, uint64_t *u)
{
	uint64_t v = 0;

	// Arguably we could use strtoull, but Windows doesn't conform
	// to C99, and so lacks it.

	if ((s == NULL) || (*s == '\0')) {
		// Require a non-empty string.
		return (NNG_EINVAL);
	}
	while (*s) {
		uint64_t last = v;
		if (isdigit(*s)) {
			v *= 10;
			v += (*s - '0');
		} else {
			return (NNG_EINVAL);
		}
		if (v < last) {
			// Overflow!
			return (NNG_EINVAL);
		}
		s++;
	}
	*u = v;
	return (0);
}

int
nni_strtox64(const char *s, uint64_t *u)
{
	uint64_t v = 0;

	// Arguably we could use strtoull, but Windows doesn't conform
	// to C99, and so lacks it.

	if (s == NULL) {
		return (NNG_EINVAL);
	}
	// Skip over 0x if present.
	if ((s[0] == '0') && ((s[1] == 'x') || (s[1] == 'X'))) {
		s += 2;
	}
	if (*s == '\0') {
		// Require a non-empty string.
		return (NNG_EINVAL);
	}

	while (*s) {
		uint64_t last = v;
		if (isdigit(*s)) {
			v *= 16;
			v += (*s - '0');
		} else if ((*s >= 'a') && (*s <= 'f')) {
			v *= 16;
			v += (*s - 'a') + 10;
		} else if ((*s >= 'A') && (*s <= 'F')) {
			v *= 16;
			v += (*s - 'A') + 10;
		} else {
			return (NNG_EINVAL);
		}
		if (v < last) {
			// Overflow!
			return (NNG_EINVAL);
		}
		s++;
	}
	*u = v;
	return (0);
}
