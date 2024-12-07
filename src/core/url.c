//
// Copyright 2024 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "core/defs.h"
#include "core/nng_impl.h"

#include <ctype.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "core/platform.h"
#include "nng/nng.h"
#include "url.h"

static uint8_t
url_hex_val(char c)
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
		if ((s[0] & 0x80u) == 0) {
			s++;
			continue;
		}
		if ((s[0] & 0xe0u) == 0xc0) {
			// 0x80 thru 0x7ff
			v    = (s[0] & 0x1fu);
			minv = 0x80;
			nb   = 1;
		} else if ((s[0] & 0xf0u) == 0xe0) {
			v    = (s[0] & 0xfu);
			minv = 0x800;
			nb   = 2;
		} else if ((s[0] & 0xf8u) == 0xf0) {
			v    = (s[0] & 0x7u);
			minv = 0x10000;
			nb   = 3;
		} else {
			// invalid byte, either continuation, or too many
			// leading 1 bits.
			return (NNG_EINVAL);
		}
		s++;
		for (int i = 0; i < nb; i++) {
			if ((s[0] & 0xc0u) != 0x80) {
				return (NNG_EINVAL); // not continuation
			}
			s++;
			v <<= 6u;
			v += s[0] & 0x3fu;
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

size_t
nni_url_decode(uint8_t *out, const char *in, size_t max_len)
{
	size_t  len;
	uint8_t c;

	len = 0;
	while ((c = (uint8_t) *in) != '\0') {
		if (len >= max_len) {
			return ((size_t) -1);
		}
		if (c == '%') {
			in++;
			if ((!isxdigit(in[0])) || (!isxdigit(in[1]))) {
				return ((size_t) -1);
			}
			out[len] = url_hex_val(*in++);
			out[len] <<= 4u;
			out[len] += url_hex_val(*in++);
			len++;
		} else {
			out[len++] = c;
			in++;
		}
	}
	return (len);
}

static int
url_canonify_uri(char *out)
{
	size_t  src, dst;
	uint8_t c;
	int     rv;
	bool    skip;

	// First pass, convert '%xx' for safe characters to unescaped forms.
	src = dst = 0;
	while ((c = out[src]) != 0) {
		if (c == '%') {
			if ((!isxdigit(out[src + 1])) ||
			    (!isxdigit(out[src + 2]))) {
				return (NNG_EINVAL);
			}
			c = url_hex_val(out[src + 1]);
			c *= 16;
			c += url_hex_val(out[src + 2]);
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
				out[dst++] = toupper((uint8_t) out[src + 1]);
				out[dst++] = toupper((uint8_t) out[src + 2]);
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
		return (rv);
	}

	return (0);
}

static struct {
	const char *scheme;
	uint16_t    port;
} nni_url_default_ports[] = {
	// This list is not exhaustive, but likely covers the main ones we
	// care about.  Feel free to add additional ones as use cases arise.
	// Note also that we don't use "default" ports for SP protocols
	// that have no "default" port, like tcp:// or tls+tcp://.
	// clang-format off
	{ "git", 9418 },
	{ "gopher", 70 },
	{ "http", 80 },
	{ "https", 443 },
	{ "ssh", 22 },
	{ "telnet", 23 },
	{ "ws", 80 },
	{ "ws4", 80 },
	{ "ws6", 80 },
	{ "wss", 443 },
	{ "wss4", 443 },
	{ "wss6", 443 },
	{ NULL, 0 },
	// clang-format on
};

// List of schemes that we recognize.  We don't support them all.
static const char *nni_schemes[] = {
	"http",
	"https",
	"tcp",
	"tcp4",
	"tcp6",
	"tls+tcp",
	"tls+tcp4",
	"tls+tcp6",
	"socket",
	"inproc",
	"ipc",
	"unix",
	"abstract",
	"ws",
	"ws4",
	"ws6",
	"wss",
	"wss4",
	"wss6",
	"udp",
	"udp4",
	"udp6",
	// we don't support these
	"file",
	"mailto",
	"gopher",
	"ftp",
	"ssh",
	"git",
	"telnet",
	"irc",
	"imap",
	"imaps",
	NULL,
};

uint16_t
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
	return (0);
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
static int
nni_url_parse_inline_inner(nng_url *url, const char *raw)
{
	size_t      len;
	const char *s;
	char       *p;
	char        c;
	int         rv;

	// Grab the scheme.
	s = raw;
	for (len = 0; (c = s[len]) != ':'; len++) {
		if (c == 0) {
			break;
		}
	}
	if (strncmp(s + len, "://", 3) != 0) {
		return (NNG_EINVAL);
	}

	for (int i = 0; nni_schemes[i] != NULL; i++) {
		if (strncmp(s, nni_schemes[i], len) == 0) {
			url->u_scheme = nni_schemes[i];
			break;
		}
	}
	if (url->u_scheme == NULL) {
		return (NNG_ENOTSUP);
	}
	s += len;

	// A little tricky.  We copy the "://" here, even though we don't need
	// it. This affords us some space for zero bytes between URL components
	// if needed

	if (strlen(s) >= sizeof(url->u_static)) {
		url->u_buffer = nni_strdup(s);
		url->u_bufsz  = strlen(s) + 1;
	} else {
		snprintf(url->u_static, sizeof(url->u_static), "%s", s);
		url->u_buffer = url->u_static;
		url->u_bufsz  = 0;
	}

	p = url->u_buffer + strlen("://");
	s = p;

	// For compatibility reasons, we treat ipc:// and inproc:// paths
	// specially. These names URLs have a path name (ipc) or arbitrary
	// string (inproc) and don't include anything like a host.  Note that
	// in the case of path names, it is incumbent upon the application to
	// ensure that valid and safe path names are used.  Note also that
	// path names are not canonicalized, which means that the address and
	// URL properties for relative paths won't be portable to other
	// processes unless they are in the same directory.  When in doubt,
	// we recommend using absolute paths, such as ipc:///var/run/socket.

	if ((strcmp(url->u_scheme, "ipc") == 0) ||
	    (strcmp(url->u_scheme, "unix") == 0) ||
	    (strcmp(url->u_scheme, "abstract") == 0) ||
	    (strcmp(url->u_scheme, "inproc") == 0) ||
	    (strcmp(url->u_scheme, "socket") == 0)) {
		url->u_path     = p;
		url->u_hostname = NULL;
		url->u_query    = NULL;
		url->u_fragment = NULL;
		url->u_userinfo = NULL;
		return (0);
	}

	// Look for host part (including colon).  Will be terminated by
	// a path, or NUL.  May also include an "@", separating a user
	// field.
	for (;;) {
		c = *p;
		if ((c == '\0') || (c == '/') || (c == '#') || (c == '?')) {
			*p = '\0';
			memmove(url->u_buffer, s, strlen(s) + 1);
			*p = c;
			break;
		}
		p++;
	}

	s           = p;
	url->u_path = p;

	// shift the host back to the start of the buffer, which gives us
	// padding so we don't have to clobber the leading "/" in the path.
	url->u_hostname = url->u_buffer;

	char *at;
	if ((at = strchr(url->u_hostname, '@')) != NULL) {
		url->u_userinfo = url->u_hostname;
		*at++           = 0;
		url->u_hostname = at;

		// make sure only one '@' appears in the host (only one user
		// info is allowed)
		if (strchr(url->u_hostname, '@') != NULL) {
			return (NNG_EINVAL);
		}
	}

	// Copy the host portion, but make it lower case (hostnames are
	// case insensitive).
	for (int i = 0; url->u_hostname[i]; i++) {
		url->u_hostname[i] = (char) tolower(url->u_hostname[i]);
	}

	if ((rv = url_canonify_uri(p)) != 0) {
		return (rv);
	}

	while ((c = *p) != '\0') {
		if ((c == '?') || (c == '#')) {
			break;
		}
		p++;
	}

	// Look for query info portion.
	if (*p == '?') {
		*p++         = '\0';
		url->u_query = p;
		while ((c = *p) != '\0') {
			if (c == '#') {
				*p++            = '\0';
				url->u_fragment = p;
				break;
			}
			p++;
		}
	} else if (c == '#') {
		*p++            = '\0';
		url->u_fragment = p;
	}

	// Now go back to the host portion, and look for a separate
	// port We also yank off the "[" part for IPv6 addresses.
	p = url->u_hostname;
	if (*p == '[') {
		url->u_hostname++;
		p++;
		while (*p != ']') {
			if (*p++ == '\0') {
				return (NNG_EINVAL);
			}
		}
		*p++ = '\0';
		if ((*p != ':') && (*p != '\0')) {
			return (NNG_EINVAL);
		}
	} else {
		while (*p != ':' && *p != '\0') {
			p++;
		}
	}
	if ((c = *p) == ':') {
		*p++ = '\0';
	}
	// hostname length check
	if (strlen(url->u_hostname) >= 256) {
		return (NNG_EINVAL);
	}

	if (c == ':') {
		// If a colon was present, but no port value present, then
		// that is an error.
		if (*p == '\0') {
			return (NNG_EINVAL);
		}
		if (nni_get_port_by_name(p, &url->u_port) != 0) {
			return (NNG_EINVAL);
		}
	} else {
		url->u_port = nni_url_default_port(url->u_scheme);
	}

	return (0);
}

int
nni_url_parse_inline(nng_url *url, const char *raw)
{
	int rv = nni_url_parse_inline_inner(url, raw);
	if (rv != 0) {
		nni_url_fini(url);
	}
	return (rv);
}

int
nng_url_parse(nng_url **urlp, const char *raw)
{
	nng_url *url;
	int      rv;

	if ((url = NNI_ALLOC_STRUCT(url)) == NULL) {
		return (NNG_ENOMEM);
	}
	if ((rv = nni_url_parse_inline(url, raw)) != 0) {
		NNI_FREE_STRUCT(url);
		return (rv);
	}
	*urlp = url;
	return (0);
}

void
nni_url_fini(nng_url *url)
{
	if (url->u_bufsz != 0) {
		nni_free(url->u_buffer, url->u_bufsz);
		url->u_buffer = NULL;
		url->u_bufsz  = 0;
	}
}

void
nng_url_free(nng_url *url)
{
	if (url != NULL) {
		nni_url_fini(url);
		NNI_FREE_STRUCT(url);
	}
}

int
nng_url_sprintf(char *str, size_t size, const nng_url *url)
{
	const char *scheme  = url->u_scheme;
	const char *host    = url->u_hostname;
	const char *hostob  = "";
	const char *hostcb  = "";
	bool        do_port = true;

	if ((strcmp(scheme, "ipc") == 0) || (strcmp(scheme, "inproc") == 0) ||
	    (strcmp(scheme, "unix") == 0) ||
	    (strcmp(scheme, "abstract") == 0) ||
	    (strcmp(scheme, "socket") == 0)) {
		return (snprintf(str, size, "%s://%s", scheme, url->u_path));
	}

	if (url->u_port == nni_url_default_port(scheme)) {
		do_port = false;
	}
	if (strchr(host, ':') != 0) {
		hostob = "[";
		hostcb = "]";
	}
	char portstr[8];
	if (do_port) {
		snprintf(portstr, sizeof(portstr), ":%u", url->u_port);
	} else {
		portstr[0] = 0;
	}
	return (snprintf(str, size, "%s://%s%s%s%s%s%s%s%s%s", scheme, hostob,
	    host, hostcb, portstr, url->u_path,
	    url->u_query != NULL ? "?" : "",
	    url->u_query != NULL ? url->u_query : "",
	    url->u_fragment != NULL ? "#" : "",
	    url->u_fragment != NULL ? url->u_fragment : ""));
}

int
nni_url_asprintf(char **str, const nng_url *url)
{
	char  *result;
	size_t sz;

	sz = nng_url_sprintf(NULL, 0, url) + 1;
	if ((result = nni_alloc(sz)) == NULL) {
		return (NNG_ENOMEM);
	}
	nng_url_sprintf(result, sz, url);
	*str = result;
	return (0);
}

// nni_url_asprintf_port is like nni_url_asprintf, but includes a port
// override.  If non-zero, this port number replaces the port number
// in the port string.
int
nni_url_asprintf_port(char **str, const nng_url *url, int port)
{
	nng_url myurl = *url;

	if (port > 0) {
		myurl.u_port = (uint16_t) port;
	}
	return (nni_url_asprintf(str, &myurl));
}

#define URL_COPYSTR(d, s) ((s != NULL) && ((d = nni_strdup(s)) == NULL))

int
nni_url_clone_inline(nng_url *dst, const nng_url *src)
{
	if (src->u_bufsz != 0) {
		if ((dst->u_buffer = nni_alloc(dst->u_bufsz)) == NULL) {
			return (NNG_ENOMEM);
		}
		dst->u_bufsz = src->u_bufsz;
		memcpy(dst->u_buffer, src->u_buffer, src->u_bufsz);
	} else {
		memcpy(dst->u_static, src->u_static, sizeof(src->u_static));
		dst->u_buffer =
		    dst->u_static + (src->u_buffer - src->u_static);
	}

	dst->u_hostname = dst->u_buffer + (src->u_hostname - src->u_buffer);
	dst->u_path     = dst->u_buffer + (src->u_path - src->u_buffer);

	if (src->u_userinfo != NULL) {
		dst->u_userinfo =
		    dst->u_buffer + (src->u_userinfo - src->u_buffer);
	}
	if (src->u_query != NULL) {
		dst->u_query = dst->u_buffer + (src->u_query - src->u_buffer);
	}
	if (src->u_fragment != NULL) {
		dst->u_fragment =
		    dst->u_buffer + (src->u_fragment - src->u_buffer);
	}
	dst->u_scheme = src->u_scheme;
	dst->u_port   = src->u_port;
	return (0);
}

#undef URL_COPYSTR

int
nng_url_clone(nng_url **dstp, const nng_url *src)
{
	nng_url *dst;
	int      rv;
	if ((dst = NNI_ALLOC_STRUCT(dst)) == NULL) {
		return (NNG_ENOMEM);
	}
	if ((rv = nni_url_clone_inline(dst, src) != 0)) {
		NNI_FREE_STRUCT(dst);
		return (rv);
	}
	*dstp = dst;
	return (0);
}

// nni_url_to_address resolves a URL into a sockaddr, assuming the URL is for
// an IP address.
int
nni_url_to_address(nng_sockaddr *sa, const nng_url *url)
{
	int         af;
	nni_aio     aio;
	const char *h;
	int         rv;

	// This assumes the scheme is one that uses TCP/IP addresses.

	if (strchr(url->u_scheme, '4') != NULL) {
		af = NNG_AF_INET;
	} else if (strchr(url->u_scheme, '6') != NULL) {
		af = NNG_AF_INET6;
	} else {
		af = NNG_AF_UNSPEC;
	}

	nni_aio_init(&aio, NULL, NULL);

	h = url->u_hostname;
	if ((h != NULL) && (strcmp(h, "") == 0)) {
		h = NULL;
	}

	nni_resolv_ip(h, url->u_port, af, true, sa, &aio);
	nni_aio_wait(&aio);
	rv = nni_aio_result(&aio);
	nni_aio_fini(&aio);
	return (rv);
}

const char *
nng_url_scheme(const nng_url *url)
{
	return (url->u_scheme);
}

uint32_t
nng_url_port(const nng_url *url)
{
	return (url->u_port);
}

void
nng_url_resolve_port(nng_url *url, uint32_t port)
{
	if (url->u_port == 0) {
		url->u_port = port;
	}
}

const char *
nng_url_hostname(const nng_url *url)
{
	return (url->u_hostname);
}

const char *
nng_url_path(const nng_url *url)
{
	return (url->u_path);
}

const char *
nng_url_query(const nng_url *url)
{
	return (url->u_query);
}

const char *
nng_url_userinfo(const nng_url *url)
{
	return (url->u_userinfo);
}

const char *
nng_url_fragment(const nng_url *url)
{
	return (url->u_fragment);
}
