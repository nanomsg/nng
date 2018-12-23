//
// Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <stdlib.h>
#include <string.h>

#include <nng/nng.h>
#include <nng/supplemental/util/options.h>

#include "core/nng_impl.h"

// Call with optidx set to 1 to start parsing.
int
nng_opts_parse(int argc, char *const *argv, const nng_optspec *opts, int *val,
    char **optarg, int *optidx)
{
	const nng_optspec *opt;
	int                matches;
	bool               shortopt;
	size_t             l;
	char *             arg;
	int                i;

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
	opt     = NULL;

	for (int x = 0; opts[x].o_val != 0; x++) {

		if (shortopt) {
			if (arg[0] == opts[x].o_short) {
				matches = 1;
				opt     = &opts[x];
				break;
			}
			continue;
		}

		if ((opts[x].o_name == NULL) ||
		    (strncmp(arg, opts[x].o_name, l) != 0)) {
			continue;
		}
		matches++;
		opt = &opts[x];

		if (strlen(opts[x].o_name) == l) {
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
		return (NNG_EINVAL);
		break;
	default:
		// Ambiguous (not match)
		return (NNG_EAMBIGUOUS);
		break;
	}

	if (!opt->o_arg) {
		// No option clustering for short options yet.
		if (arg[l] != '\0') {
			return (NNG_EINVAL);
		}
		*val    = opt->o_val;
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
			return (NNG_ENOARG);
		}
		*optarg = argv[i];
	}
	*optidx = ++i;
	*val    = opt->o_val;

	return (0);
}
