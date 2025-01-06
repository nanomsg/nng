//
// Copyright 2025 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#ifndef NNG_ARGS_H
#define NNG_ARGS_H

// This is a relatively simple "command line options parsing" library, used to
// parse command line options.  We would use getopt(3), but there are
// two problems with getopt(3).  First, it isn't available on all
// platforms (especially Win32), and second, it doesn't support long
// options.  We *exclusively* support long options.  POSIX style
// short option clustering is *NOT* supported.
//
// This is a header library, and it does not depend on anything else in NNG.
// This is by design, please do not add dependencies beyond what is available
// in fairly minimal standard C99 or C11.
#include <stdbool.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

// This is a relatively simple "options parsing" library, used to
// parse command line options.  We would use getopt(3), but there are
// two problems with getopt(3).  First, it isn't available on all
// platforms (especially Win32), and second, it doesn't support long
// options.  We *exclusively* support long options.  POSIX style
// short option clustering is *NOT* supported.

struct nng_arg_spec {
	const char *a_name;  // Long style name (may be NULL for short only)
	int         a_short; // Short option (no clustering!)
	int         a_val;   // Value stored on a good parse (>0)
	bool        a_arg;   // Option takes an argument if true
};

typedef struct nng_arg_spec nng_arg_spec;

#define NNG_ARG_END (-1)     // no more arguments (not an error)
#define NNG_ARG_INVAL (-2)   // an invalid argument/option was given in argv
#define NNG_ARG_AMBIG (-3)   // an arg in argv resolves to more than one spec
#define NNG_ARG_MISSING (-4) // a required option argument is missing

// Call with *optidx set to 1 to start parsing for a standard program, or with
// 0 if parsing arguments without the executable in argv[0].
//
// The val will store the value of the matched "o_val", optarg will be
// set to match the option string, and optidx will be increment appropriately.
// Returns -1 when the end of options is reached, 0 on success, or
// NNG_EINVAL if the option parse is invalid for any reason.
int
nng_args_parse(int argc, char *const *argv, const nng_arg_spec *specs,
    int *val, char **optarg, int *optidx)
{
	const nng_arg_spec *spec;
	int                 matches;
	bool                shortopt;
	size_t              l;
	char               *arg;
	int                 i;

	if ((i = *optidx) >= argc) {
		return (-1);
	}
	arg = argv[*optidx];

	if (arg[0] != '-') {
		return (-1);
	}
	if (arg[1] == '\0') {
		*optidx = i + 1;
		return (-1);
	}

	if ((arg[0] == '-') && (arg[1] == '-')) {
		arg += 2;
		shortopt = false;
		for (l = 0; arg[l] != '\0'; l++) {
			if ((arg[l] == '=') || (arg[l] == ':')) {
				break;
			}
		}
	} else {
		arg++;
		shortopt = true;
		l        = 1;
	}

	matches = 0;
	spec    = NULL;

	for (int x = 0; specs[x].a_val != 0; x++) {

		if (shortopt) {
			if (arg[0] == specs[x].a_short) {
				matches = 1;
				spec    = &specs[x];
				break;
			}
			continue;
		}

		if ((specs[x].a_name == NULL) ||
		    (strncmp(arg, specs[x].a_name, l) != 0)) {
			continue;
		}
		matches++;
		spec = &specs[x];

		if (strlen(specs[x].a_name) == l) {
			// Perfect match.
			matches = 1;
			break;
		}
	}

	switch (matches) {
	case 1:
		// Exact match
		break;
	case 0:
		// No such option
		return (NNG_ARG_INVAL);
		break;
	default:
		// Ambiguous (not match)
		return (NNG_ARG_AMBIG);
		break;
	}

	if (!spec->a_arg) {
		// No option clustering for short options yet.
		if (arg[l] != '\0') {
			return (NNG_ARG_INVAL);
		}
		*val    = spec->a_val;
		*optidx = i + 1;
		return (0);
	}

	if (arg[l] != '\0') {
		if (shortopt) {
			*optarg = arg + l;
		} else {
			*optarg = arg + l + 1;
		}
	} else {
		i++;
		if (i >= argc) {
			return (NNG_ARG_MISSING);
		}
		*optarg = argv[i];
	}
	*optidx = ++i;
	*val    = spec->a_val;

	return (0);
}

#endif // NNG_ARGS_H
