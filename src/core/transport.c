//
// Copyright 2016 Garrett D'Amore <garrett@damore.org>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "core/nng_impl.h"

#include <string.h>

// For now the list of transports is hard-wired.  Adding new transports
// to the system dynamically is something that might be considered later.
extern nni_tran nni_inproc_tran;

static nni_tran *transports[] = {
	&nni_inproc_tran,
	NULL
};

nni_tran *
nni_tran_find(const char *addr)
{
	// address is of the form "<scheme>://blah..."
	const char *end;
	int len;
	int i;
	nni_tran *tran;

	if ((end = strstr(addr, "://")) == NULL) {
		return (NULL);
	}
	len = (int) (end - addr);
	for (i = 0; (tran = transports[i]) != NULL; i++) {
		if ((strncmp(addr, tran->tran_scheme, len) == 0) &&
		    (tran->tran_scheme[len] == '\0')) {
			return (tran);
		}
	}
	return (NULL);
}


// nni_transport_init initializes the entire transport subsystem, including
// each individual transport.
void
nni_tran_init(void)
{
	int i;
	nni_tran *tran;

	for (i = 0; (tran = transports[i]) != NULL; i++) {
		tran->tran_init();
	}
}


void
nni_tran_fini(void)
{
	int i;
	nni_tran *tran;

	for (i = 0; (tran = transports[i]) != NULL; i++) {
		if (tran->tran_fini != NULL) {
			tran->tran_fini();
		}
	}
}
