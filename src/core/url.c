//
// Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "core/nng_impl.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>

#include "url.h"

static char
url_hexval(char c)
{
	if ((c >= '0') && (c <= '9')) {
		return (c - '0');
	}
	if ((c >= 'A') && (c <= 'F')) {
		return (c - 'A');
	}
	if ((c >= 'a') && (c <= 'f')) {
		return (c - 'a');
	}
	return (0);
}

static int
url_decode_buf(const char *in, char *out, int len)
{
	int            dlen;
	const uint8_t *src;
	uint8_t *      dst;
	int            c;

	src = (const uint8_t *) in;
	dst = (uint8_t *) out;

	dlen = 0;
	while ((c = *src) != 0) {
		switch (c) {
		case '%':
			if ((!isxdigit(src[1])) || (!isxdigit(src[2]))) {
				return (-1);
			}
			c = (url_hexval(src[1]) * 16) + url_hexval(src[2]);
			// We don't support encoded control characters.
			if ((c < ' ') || (c == 0x7F)) {
				return (-1);
			}
			src += 3;
			break;
		case '+':
			src++;
			c = ' ';
			break;
		default:
			// Reject control characters and non-ASCII
			if ((c >= 0x7F) || (c <= ' ')) {
				return (-1);
			}
			// Technically this will accept some "unsafe"
			// characters as is.
			src++;
			break;
		}

		if (dlen < len) {
			*dst++ = c;
		}
		dlen++;
	}
	if (dlen < len) {
		*dst = '\0';
	}
	dlen++; // for null terminator
	return (dlen);
}

int
nni_url_decode(char **out, const char *in)
{
	int   len = 0;
	char *dst;

	if ((len = url_decode_buf(in, NULL, 0)) < 1) {
		return (NNG_EINVAL);
	}
	if ((dst = nni_alloc(len)) == NULL) {
		return (NNG_ENOMEM);
	}
	url_decode_buf(in, dst, len);
	*out = dst;
	return (0);
}

static const char *url_hexdigits = "0123456789ABCDEF";
static const char *url_safe      = "-_.~";

static int
url_encode_buf(const char *in, char *out, int len, const char *specials)
{
	uint8_t *      dst;
	const uint8_t *src;
	int            dlen;
	int            c;

	dlen = 0;
	src  = (const uint8_t *) in;
	dst  = (uint8_t *) out;

	while ((c = *src) != 0) {
		if ((c < ' ') || (c == 0x7F)) {
			// No encoding of control characters
			return (-1);
		}
		if ((c < 0x80) &&
		    ((isalnum(c) || (strchr(specials, c) != NULL) ||
		        (strchr(url_safe, c) != NULL)))) {
			if (dlen < len) {
				*dst++ = c;
			}
			dlen++;
			src++;
			continue;
		}

		if (dlen < len) {
			*dst++ = '%';
		}
		dlen++;
		if (dlen < len) {
			*dst++ = url_hexdigits[((c & 0xf0) >> 4)];
		}
		dlen++;
		if (dlen < len) {
			*dst++ = url_hexdigits[(c & 0xf)];
		}
		dlen++;
		src++;
	}
	if (dlen < len) {
		*dst = '\0';
	}
	dlen++;
	return (dlen);
}

int
nni_url_encode_ext(char **out, const char *in, const char *specials)
{
	int   len;
	char *dst;

	if ((len = url_encode_buf(in, NULL, 0, specials)) < 0) {
		return (NNG_EINVAL);
	}
	if ((dst = nni_alloc(len)) == NULL) {
		return (NNG_ENOMEM);
	}
	url_encode_buf(in, dst, len, specials);
	*out = dst;
	return (0);
}

int
nni_url_encode(char **out, const char *in)
{
	return (nni_url_encode_ext(out, in, ""));
}

// URLs usually follow the following format:
//
// scheme:[//[userinfo@]host][/]path[?query][#fragment]
//
// There are other URL formats, for example mailto: but these are
// generally not used with nanomsg transports.  Golang calls these
//
// scheme:opaque[?query][#fragment]
//
// Nanomsg URLs are always of the first form, we always require a
// scheme with a leading //, such as http:// or tcp://. So our parser
// is a bit more restricted, but sufficient for our needs.
int
nni_url_parse(nni_url **urlp, const char *raw)
{
	nni_url *   url;
	size_t      len;
	const char *s;
	char        c;
	int         rv;

	if ((url = NNI_ALLOC_STRUCT(url)) == NULL) {
		return (NNG_ENOMEM);
	}

	if ((url->u_rawurl = nni_strdup(raw)) == NULL) {
		rv = NNG_ENOMEM;
		goto error;
	}

	// Grab the scheme.
	s = raw;
	for (len = 0; (c = s[len]) != ':'; len++) {
		if (c == 0) {
			break;
		}
	}
	if (strncmp(s + len, "://", 3) != 0) {
		rv = NNG_EINVAL;
		goto error;
	}

	if ((url->u_scheme = nni_alloc(len + 1)) == NULL) {
		rv = NNG_ENOMEM;
		goto error;
	}
	memcpy(url->u_scheme, s, len);
	url->u_scheme[len] = '\0';

	// Look for host part (including colon).  Will be terminated by
	// a path, or NUL.  May also include an "@", separating a user
	// field.
	s += len + 3; // strlen("://")
	for (len = 0; (c = s[len]) != '/'; len++) {
		if ((c == '\0') || (c == '#') || (c == '?')) {
			break;
		}
		if (c == '@') {
			// This is a username.
			if (url->u_userinfo != NULL) { // we already have one
				rv = NNG_EINVAL;
				goto error;
			}
			if ((url->u_userinfo = nni_alloc(len + 1)) == NULL) {
				rv = NNG_ENOMEM;
				goto error;
			}
			memcpy(url->u_userinfo, s, len);
			url->u_userinfo[len] = '\0';
			s += len + 1; // skip past user@ ...
			len = 0;
		}
	}

	if ((url->u_host = nni_alloc(len + 1)) == NULL) {
		rv = NNG_ENOMEM;
		goto error;
	}
	memcpy(url->u_host, s, len);
	url->u_host[len] = '\0';
	s += len;

	if ((url->u_rawpath = nni_strdup(s)) == NULL) {
		rv = NNG_ENOMEM;
		goto error;
	}
	for (len = 0; (c = s[len]) != '\0'; len++) {
		if ((c == '?') || (c == '#')) {
			break;
		}
	}

	if ((url->u_path = nni_alloc(len + 1)) == NULL) {
		rv = NNG_ENOMEM;
		goto error;
	}

	memcpy(url->u_path, s, len);
	url->u_path[len] = '\0';

	s += len;
	len = 0;

	// Look for query info portion.
	if (s[0] == '?') {
		s++;
		for (len = 0; (c = s[len]) != '\0'; len++) {
			if (c == '#') {
				break;
			}
		}
		if ((url->u_query = nni_alloc(len + 1)) == NULL) {
			rv = NNG_ENOMEM;
			goto error;
		}
		memcpy(url->u_query, s, len);
		url->u_query[len] = '\0';
		s += len;
	}

	// Look for fragment.  Will always be last, so we just use
	// strdup.
	if (s[0] == '#') {
		if ((url->u_fragment = nni_strdup(s + 1)) == NULL) {
			rv = NNG_ENOMEM;
			goto error;
		}
	}

	// Now go back to the host portion, and look for a separate
	// port We also yank off the "[" part for IPv6 addresses.
	s = url->u_host;
	if (s[0] == '[') {
		s++;
		for (len = 0; s[len] != ']'; len++) {
			if (s[len] == '\0') {
				rv = NNG_EINVAL;
				goto error;
			}
		}
		if ((s[len + 1] != ':') && (s[len + 1] != '\0')) {
			rv = NNG_EINVAL;
			goto error;
		}
	} else {
		for (len = 0; s[len] != ':'; len++) {
			if (s[len] == '\0') {
				break;
			}
		}
	}
	if ((url->u_hostname = nni_alloc(len + 1)) == NULL) {
		rv = NNG_ENOMEM;
		goto error;
	}
	memcpy(url->u_hostname, s, len);
	url->u_hostname[len] = '\0';
	s += len;

	if (s[0] == ']') {
		s++; // skip over ']', only used with IPv6 addresses
	}
	if (s[0] == ':') {
		if ((url->u_port = nni_strdup(s + 1)) == NULL) {
			rv = NNG_ENOMEM;
			goto error;
		}
	} else if ((url->u_port = nni_strdup("")) == NULL) {
		rv = NNG_ENOMEM;
		goto error;
	}

	*urlp = url;
	return (0);

error:
	nni_url_free(url);
	return (rv);
}

void
nni_url_free(nni_url *url)
{
	nni_strfree(url->u_rawurl);
	nni_strfree(url->u_scheme);
	nni_strfree(url->u_userinfo);
	nni_strfree(url->u_host);
	nni_strfree(url->u_hostname);
	nni_strfree(url->u_port);
	nni_strfree(url->u_path);
	nni_strfree(url->u_query);
	nni_strfree(url->u_fragment);
	nni_strfree(url->u_rawpath);
	NNI_FREE_STRUCT(url);
}