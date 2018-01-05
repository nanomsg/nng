//
// Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#ifndef CORE_URL_H
#define CORE_URL_H

typedef struct nni_url nni_url;

struct nni_url {
	char *u_rawurl;   // never NULL
	char *u_scheme;   // never NULL
	char *u_userinfo; // will be NULL if not specified
	char *u_host;     // including colon and port
	char *u_hostname; // name only, will be "" if not specified
	char *u_port;     // port, will be "" if not specified
	char *u_path;     // path, will be "" if not specified
	char *u_query;    // without '?', will be NULL if not specified
	char *u_fragment; // without '#', will be NULL if not specified
	char *u_rawpath;  // includes query and fragment, "" if not specified
};

extern int nni_url_parse(nni_url **, const char *path);
extern void nni_url_free(nni_url *);

// nni_url_decode decodes the string, converting escaped characters to their
// proper form. The newly allocated string is returned in the first argument
// and may be freed with nni_strfree().  Note that we return EINVAL in the
// presence of an encoding of a control character.  (Most especially NUL
// would cause problems for C code, but the other control characters have
// no business inside a URL either.)
extern int nni_url_decode(char **, const char *);

// nni_url_encode works like nni_url_decode, but does the opposite transform.
// "Reserved" special characters (such as "/" and "@") are encoded, so don't
// use this to encode the entire URL.) This is most useful when encoding
// individual components, such as a value for a query parameter.  Note that
// this returns NNG_EINVAL if the input string contains control characters,
// as those have no business inside a URL.
extern int nni_url_encode(char **, const char *);

// nni_url_encode_ext works like nni_url_encode, but passes the named
// special characters.  For example, to URL encode all elements in a path
// while preserving director separators, use the string "/" for specials.
extern int nni_url_encode_ext(char **, const char *, const char *);

#endif // CORE_URL_H
