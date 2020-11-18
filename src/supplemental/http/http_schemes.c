//
// Copyright 2020 Staysail Systems, Inc. <info@staysail.tech>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <ctype.h>
#include <stdbool.h>
#include <string.h>

#include "core/nng_impl.h"

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