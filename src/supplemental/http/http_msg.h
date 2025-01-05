//
// Copyright 2025 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#ifndef NNG_SUPPLEMENTAL_HTTP_HTTP_MSG
#define NNG_SUPPLEMENTAL_HTTP_HTTP_MSG

#include "core/defs.h"
#include "core/list.h"

// Note that as we parse headers, the rule is that if a header is already
// present, then we can append it to the existing header, separated by
// a comma.  From experience, for example, Firefox uses a Connection:
// header with two values, "keepalive", and "upgrade".
typedef struct http_header {
	char         *name;
	char         *value;
	nni_list_node node;
} http_header;

typedef struct nni_http_entity {
	char  *data;
	size_t size; // allocated/expected size
	size_t len;  // current length
	bool   own;  // if true, data is "ours", and should be freed
} nni_http_entity;

struct nng_http_req {
	nni_list        hdrs;
	nni_http_entity data;
	char            meth[32];
	char           *uri;
	const char     *vers;
	char           *buf;
	size_t          bufsz;
	bool            parsed;
};

struct nng_http_res {
	nni_list        hdrs;
	nni_http_entity data;
	uint16_t        code;
	char           *rsn;
	const char     *vers;
	char           *buf;
	size_t          bufsz;
	bool            parsed;
	bool            iserr;
};

#endif
