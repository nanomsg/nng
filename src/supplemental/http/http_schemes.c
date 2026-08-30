//
// Copyright 2026 Staysail Systems, Inc. <info@staysail.tech>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <ctype.h>
#include <stdbool.h>
#include <string.h>

#include "../../core/nng_impl.h"

#include "http_api.h"

static struct {
	const char *upper;
	const char *lower;
} http_schemes[] = {
	{
	    .upper = "http",
	    .lower = "tcp",
	},
	{
	    .upper = "http+unix",
	    .lower = "unix",
	},
	{
	    .upper = "ws",
	    .lower = "tcp",
	},
	{
	    .upper = "https",
	    .lower = "tls+tcp",
	},
	{
	    .upper = "wss",
	    .lower = "tls+tcp",
	},
	{
	    .upper = "http4",
	    .lower = "tcp4",
	},
	{
	    .upper = "ws4",
	    .lower = "tcp4",
	},
	{
	    .upper = "http6",
	    .lower = "tcp6",
	},
	{
	    .upper = "ws6",
	    .lower = "tcp6",
	},
	{
	    .upper = "https4",
	    .lower = "tls+tcp4",
	},
	{
	    .upper = "wss4",
	    .lower = "tls+tcp4",
	},
	{
	    .upper = "https6",
	    .lower = "tls+tcp6",
	},
	{
	    .upper = "wss6",
	    .lower = "tls+tcp6",
	},
	{
	    .upper = NULL,
	    .lower = NULL,
	},
};

const char *
nni_http_stream_scheme(const char *upper)
{
	for (int i = 0; http_schemes[i].upper != NULL; i++) {
		if (strcmp(http_schemes[i].upper, upper) == 0) {
			return (http_schemes[i].lower);
		}
	}
	return (NULL);
}

nng_err
nni_http_stream_url(
    nng_url *stream_url, const nng_url *url, char *path, size_t pathsz)
{
	const char *scheme;
	size_t      len;

	if ((scheme = nni_http_stream_scheme(url->u_scheme)) == NULL) {
		return (NNG_EADDRINVAL);
	}
	memcpy(stream_url, url, sizeof(*stream_url));
	stream_url->u_scheme = (char *) scheme;

	if (strcmp(url->u_scheme, "http+unix") != 0) {
		return (NNG_OK);
	}
	if ((url->u_port != 0) || (url->u_hostname == NULL) ||
	    (url->u_hostname[0] == '\0') ||
	    (pathsz == 0) ||
	    ((len = nni_url_decode((uint8_t *) path, url->u_hostname,
	          pathsz - 1)) == (size_t) -1) ||
	    (len == 0) || (memchr(path, '\0', len) != NULL)) {
		return (NNG_EADDRINVAL);
	}
	path[len]              = '\0';
	if ((path[0] != '/') &&
	    !((len > 2) && isalpha((uint8_t) path[0]) && (path[1] == ':') &&
	        ((path[2] == '/') || (path[2] == '\\')))) {
		return (NNG_EADDRINVAL);
	}
	stream_url->u_hostname = NULL;
	stream_url->u_path     = path;
	stream_url->u_port     = 0;
	return (NNG_OK);
}
