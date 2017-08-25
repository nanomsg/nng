//
// Copyright 2017 Garrett D'Amore <garrett@damore.org>
// Copyright 2017 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <stdlib.h>
#include <string.h>

#include "core/nng_impl.h"

// This file contains implementation of utility functions that are not
// part of standard C99.  (C11 has added some things here, but we cannot
// count on them.)

char *
nni_strdup(const char *src)
{
#ifdef NNG_HAVE_STRDUP
	return (strdup(src));
#else
	char * dst;
	size_t len = strlen(src);

	if ((dst = nni_alloc(len)) != NULL) {
		memcpy(dst, src, len);
	}
	return (dst);
#endif
}

void
nni_strfree(char *s)
{
	if (s != NULL) {
#ifdef NNG_HAVE_STRDUP
		free(s);
#else
		nni_free(s, strlen(s) + 1);
#endif
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
nni_strlcat(char *dst, const char *src, size_t len)
{
#ifdef NNG_HAVE_STRLCAT
	return (strlcat(dst, src, len));
#else
	size_t n;
	char   c;

	n = 0;
	while ((*dst != '\0') && (n < len)) {
		n++;
		dst++;
	}

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
