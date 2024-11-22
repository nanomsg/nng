//
// Copyright 2024 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#ifndef CORE_URL_H
#define CORE_URL_H

#include "core/defs.h"

struct nng_url {
	char       *u_rawurl;   // never NULL
	const char *u_scheme;   // never NULL
	const char *u_userinfo; // will be NULL if not specified
	char       *u_hostname; // name only, will be "" if not specified
	uint32_t    u_port;  // port, may be zero for schemes that do not use
	char       *u_path;  // path, will be "" if not specified
	char       *u_query; // without '?', will be NULL if not specified
	char       *u_fragment; // without '#', will be NULL if not specified
	// these members are private
	char  *u_buffer;
	size_t u_bufsz;
	char   u_static[NNG_MAXADDRLEN]; // Most URLs fit within this
};

extern uint16_t nni_url_default_port(const char *);
extern int      nni_url_asprintf(char **, const nng_url *);
extern int      nni_url_asprintf_port(char **, const nng_url *, int);
extern size_t   nni_url_decode(uint8_t *, const char *, size_t);
extern int      nni_url_to_address(nng_sockaddr *, const nng_url *);
extern int      nni_url_parse_inline(nng_url *, const char *);
extern void     nni_url_fini(nng_url *);

#endif // CORE_URL_H
