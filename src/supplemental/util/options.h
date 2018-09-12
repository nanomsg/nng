//
// Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#ifndef NNG_SUPPLEMENTAL_UTIL_OPTIONS_H
#define NNG_SUPPLEMENTAL_UTIL_OPTIONS_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// This is a relatively simple "options parsing" library, used to
// parse command line options.  We would use getopt(3), but there are
// two problems with getopt(3).  First, it isn't available on all
// platforms (especially Win32), and second, it doesn't support long
// options.  We *exclusively* support long options.  POSIX style
// short option clustering is *NOT* supported.

struct nng_optspec {
	const char *o_name;  // Long style name (may be NULL for short only)
	int         o_short; // Short option (no clustering!)
	int         o_val;   // Value stored on a good parse (>0)
	bool        o_arg;   // Option takes an argument if true
};

typedef struct nng_optspec nng_optspec;

// Call with *optidx set to 1 to start parsing for a standard program.
// The val will store the value of the matched "o_val", optarg will be
// set to match the option string, and optidx will be increment appropriately.
// Returns -1 when the end of options is reached, 0 on success, or
// NNG_EINVAL if the option parse is invalid for any reason.
NNG_DECL int nng_opts_parse(int argc, char *const *argv,
    const nng_optspec *opts, int *val, char **optarg, int *optidx);

#ifdef __cplusplus
}
#endif

#endif // NNG_SUPPLEMENTAL_UTIL_OPTIONS_H
