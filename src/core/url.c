//
// Copyright 2019 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "core/nng_impl.h"

#include <ctype.h>
#include <stdbool.h>
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
		return ((c - 'A') + 10);
	}
	if ((c >= 'a') && (c <= 'f')) {
		return ((c - 'a') + 10);
	}
	return (0);
}

// This returns either 0, or NNG_EINVAL, if the supplied input string
// is malformed UTF-8.  We consider UTF-8 malformed when the sequence
// is an invalid code point, not the shortest possible code point, or
// incomplete.
static int
url_utf8_validate(void *arg)
{
	uint8_t *s = arg;
	uint32_t v, minv;
	int      nb;

	while (*s) {
		if ((s[0] & 0x80) == 0) {
			s++;
			continue;
		}
		if ((s[0] & 0xe0) == 0xc0) {
			// 0x80 thru 0x7ff
			v    = (s[0] & 0x1f);
			minv = 0x80;
			nb   = 1;
		} else if ((s[0] & 0xf0) == 0xe0) {
			v    = (s[0] & 0xf);
			minv = 0x800;
			nb   = 2;
		} else if ((s[0] & 0xf8) == 0xf0) {
			v    = (s[0] & 0x7);
			minv = 0x10000;
			nb   = 3;
		} else {
			// invalid byte, either continuation, or too many
			// leading 1 bits.
			return (NNG_EINVAL);
		}
		s++;
		for (int i = 0; i < nb; i++) {
			if ((s[0] & 0xc0) != 0x80) {
				return (NNG_EINVAL); // not continuation
			}
			s++;
			v <<= 6;
			v += s[0] & 0x3f;
		}
		if (v < minv) {
			return (NNG_EINVAL);
		}
		if ((v >= 0xd800) && (v <= 0xdfff)) {
			return (NNG_EINVAL);
		}
		if (v > 0x10ffff) {
			return (NNG_EINVAL);
		}
	}
	return (0);
}

static int
url_canonify_uri(char **outp, const char *in)
{
	char * out;
	size_t src, dst, len;
	int    c;
	int    rv;
	bool   skip;

	// We know that the transform is strictly "reducing".
	if ((out = nni_strdup(in)) == NULL) {
		return (NNG_ENOMEM);
	}
	len = strlen(out);

	// First pass, convert '%xx' for safe characters to unescaped forms.
	src = dst = 0;
	while ((c = out[src]) != 0) {
		if (c == '%') {
			if ((!isxdigit(out[src + 1])) ||
			    (!isxdigit(out[src + 2]))) {
				nni_free(out, len);
				return (NNG_EINVAL);
			}
			c = url_hexval(out[src + 1]);
			c *= 16;
			c += url_hexval(out[src + 2]);
			// If it's a safe character, decode, otherwise leave
			// it alone.  We also decode valid high-bytes for
			// UTF-8, which will let us validate them and use
			// those characters in file names later.
			if (((c >= 'A') && (c <= 'Z')) ||
			    ((c >= 'a') && (c <= 'z')) ||
			    ((c >= '0') && (c <= '9')) || (c == '.') ||
			    (c == '~') || (c == '_') || (c == '-') ||
			    (c >= 0x80)) {
				out[dst++] = (char) c;
			} else {
				out[dst++] = '%';
				out[dst++] = (char) toupper(out[src + 1]);
				out[dst++] = (char) toupper(out[src + 2]);
			}
			src += 3;
			continue;
		} else {
			out[dst++] = out[src++];
		}
	}
	out[dst] = 0;

	// Second pass, eliminate redundant //.
	src = dst = 0;
	skip      = false;
	while ((c = out[src]) != 0) {
		if ((c == '/') && (!skip)) {
			out[dst++] = '/';
			while (out[src] == '/') {
				src++;
			}
			continue;
		}
		if ((c == '?') || (c == '#')) {
			skip = true;
		}
		out[dst++] = (char) c;
		src++;
	}
	out[dst] = 0;

	// Second pass, reduce /. and /.. elements, but only in the path.
	src = dst = 0;
	skip      = false;
	while ((c = out[src]) != 0) {
		if ((c == '/') && (!skip)) {
			if ((strncmp(out + src, "/..", 3) == 0) &&
			    (out[src + 3] == 0 || out[src + 3] == '#' ||
			        out[src + 3] == '?' || out[src + 3] == '/')) {

				if (dst > 0) {
					do {
						dst--;
					} while ((dst) && (out[dst] != '/'));
				}
				src += 3;
				continue;
			}
			if ((strncmp(out + src, "/.", 2) == 0) &&
			    (out[src + 2] == 0 || out[src + 2] == '#' ||
			        out[src + 2] == '?' || out[src + 2] == '/')) {
				src += 2; // just skip over it
				continue;
			}
			out[dst++] = '/';
			src++;
		} else {
			if ((c == '?') || (c == '#')) {
				skip = true;
			}
			out[dst++] = (char) c;
			src++;
		}
	}
	out[dst] = 0;

	// Finally lets make sure that the results are valid UTF-8.
	// This guards against using UTF-8 redundancy to break security.
	if ((rv = url_utf8_validate(out)) != 0) {
		nni_free(out, len);
		return (rv);
	}

	*outp = nni_strdup(out);
	nni_free(out, len);
	return (*outp == NULL ? NNG_ENOMEM : 0);
}

static struct {
	const char *scheme;
	const char *port;
} nni_url_default_ports[] = {
	// This list is not exhaustive, but likely covers the main ones we
	// care about.  Feel free to add additional ones as use cases arise.
	// Note also that we don't use "default" ports for SP protocols
	// that have no "default" port, like tcp:// or tls+tcp://.
	// clang-format off
	{ "git", "9418" },
	{ "gopher", "70" },
	{ "http", "80" },
	{ "https", "443" },
	{ "ssh", "22" },
	{ "telnet", "23" },
	{ "ws", "80" },
	{ "wss", "443" },
	{ NULL, NULL },
	// clang-format on
};

const char *
nni_url_default_port(const char *scheme)
{
	const char *s;

	for (int i = 0; (s = nni_url_default_ports[i].scheme) != NULL; i++) {
		size_t l = strlen(s);
		if (strncmp(s, scheme, strlen(s)) != 0) {
			continue;
		}
		// It can have a suffix of either "4" or "6" to restrict
		// the address family.  This is an NNG extension.
		switch (scheme[l]) {
		case '\0':
			return (nni_url_default_ports[i].port);
		case '4':
		case '6':
			if (scheme[l + 1] == '\0') {
				return (nni_url_default_ports[i].port);
			}
			break;
		}
	}
	return ("");
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
	for (size_t i = 0; i < len; i++) {
		url->u_scheme[i] = (char) tolower(s[i]);
	}
	url->u_scheme[len] = '\0';
	s += len + 3; // strlen("://")

	// For compatibility reasons, we treat ipc:// and inproc:// paths
	// specially. These names URLs have a path name (ipc) or arbitrary
	// string (inproc) and don't include anything like a host.  Note that
	// in the case of path names, it is incumbent upon the application to
	// ensure that valid and safe path names are used.  Note also that
	// path names are not canonicalized, which means that the address and
	// URL properties for relative paths won't be portable to other
	// processes unless they are in the same directory.  When in doubt,
	// we recommend using absolute paths, such as ipc:///var/run/mysocket.

	if ((strcmp(url->u_scheme, "ipc") == 0) ||
	    (strcmp(url->u_scheme, "inproc") == 0)) {
		if ((url->u_path = nni_strdup(s)) == NULL) {
			rv = NNG_ENOMEM;
			goto error;
		}
		*urlp = url;
		return (0);
	}

	// Look for host part (including colon).  Will be terminated by
	// a path, or NUL.  May also include an "@", separating a user
	// field.
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

	// If the hostname part is just '*', skip over it.  (We treat it
	// as an empty host for legacy nanomsg compatibility.  This may be
	// non-RFC compliant, but we're really only interested in parsing
	// nanomsg URLs.)
	if (((len == 1) && (s[0] == '*')) ||
	    ((len > 1) && (strncmp(s, "*:", 2) == 0))) {
		s++;
		len--;
	}

	if ((url->u_host = nni_alloc(len + 1)) == NULL) {
		rv = NNG_ENOMEM;
		goto error;
	}
	// Copy the host portion, but make it lower case (hostnames are
	// case insensitive).
	for (size_t i = 0; i < len; i++) {
		url->u_host[i] = (char) tolower(s[i]);
	}
	url->u_host[len] = '\0';
	s += len;

	if ((rv = url_canonify_uri(&url->u_requri, s)) != 0) {
		goto error;
	}

	s = url->u_requri;
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
		// If a colon was present, but no port value present, then
		// that is an error.
		if (s[1] == '\0') {
			rv = NNG_EINVAL;
			goto error;
		}
		url->u_port = nni_strdup(s + 1);
	} else {
		url->u_port = nni_strdup(nni_url_default_port(url->u_scheme));
	}
	if (url->u_port == NULL) {
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
	if (url != NULL) {
		nni_strfree(url->u_rawurl);
		nni_strfree(url->u_scheme);
		nni_strfree(url->u_userinfo);
		nni_strfree(url->u_host);
		nni_strfree(url->u_hostname);
		nni_strfree(url->u_port);
		nni_strfree(url->u_path);
		nni_strfree(url->u_query);
		nni_strfree(url->u_fragment);
		nni_strfree(url->u_requri);
		NNI_FREE_STRUCT(url);
	}
}

int
nni_url_asprintf(char **str, const nni_url *url)
{
	const char *scheme = url->u_scheme;
	const char *port   = url->u_port;
	const char *host   = url->u_hostname;
	const char *hostob = "";
	const char *hostcb = "";

	if ((strcmp(scheme, "ipc") == 0) || (strcmp(scheme, "inproc") == 0)) {
		return (nni_asprintf(str, "%s://%s", scheme, url->u_path));
	}

	if (port != NULL) {
		if ((strlen(port) == 0) ||
		    (strcmp(nni_url_default_port(scheme), port) == 0)) {
			port = NULL;
		}
	}
	if (strcmp(host, "*") == 0) {
		host = "";
	}
	if (strchr(host, ':') != 0) {
		hostob = "[";
		hostcb = "]";
	}
	return (nni_asprintf(str, "%s://%s%s%s%s%s%s", scheme, hostob, host,
	    hostcb, port != NULL ? ":" : "", port != NULL ? port : "",
	    url->u_requri != NULL ? url->u_requri : ""));
}

// nni_url_asprintf_port is like nni_url_asprintf, but includes a port
// override.  If non-zero, this port number replaces the port number
// in the port string.
int
nni_url_asprintf_port(char **str, const nni_url *url, int port)
{
	char    portstr[16];
	nni_url myurl = *url;

	if (port > 0) {
		(void) snprintf(portstr, sizeof(portstr), "%d", port);
		myurl.u_port = portstr;
	}
	return (nni_url_asprintf(str, &myurl));
}

#define URL_COPYSTR(d, s) ((s != NULL) && ((d = nni_strdup(s)) == NULL))

int
nni_url_clone(nni_url **dstp, const nni_url *src)
{
	nni_url *dst;

	if ((dst = NNI_ALLOC_STRUCT(dst)) == NULL) {
		return (NNG_ENOMEM);
	}
	if (URL_COPYSTR(dst->u_rawurl, src->u_rawurl) ||
	    URL_COPYSTR(dst->u_scheme, src->u_scheme) ||
	    URL_COPYSTR(dst->u_userinfo, src->u_userinfo) ||
	    URL_COPYSTR(dst->u_host, src->u_host) ||
	    URL_COPYSTR(dst->u_hostname, src->u_hostname) ||
	    URL_COPYSTR(dst->u_port, src->u_port) ||
	    URL_COPYSTR(dst->u_requri, src->u_requri) ||
	    URL_COPYSTR(dst->u_path, src->u_path) ||
	    URL_COPYSTR(dst->u_query, src->u_query) ||
	    URL_COPYSTR(dst->u_fragment, src->u_fragment)) {
		nni_url_free(dst);
		return (NNG_ENOMEM);
	}
	*dstp = dst;
	return (0);
}

#undef URL_COPYSTR
