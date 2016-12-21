/*
 * Copyright 2016 Garrett D'Amore <garrett@damore.org>
 *
 * This software is supplied under the terms of the MIT License, a
 * copy of which should be located in the distribution where this
 * file was obtained (LICENSE.txt).  A copy of the license may also be
 * found online at https://opensource.org/licenses/MIT.
 */

#include <string.h>

#include "core/nng_impl.h"

/*
 * For now the list of transports is hard-wired.  Adding new transports
 * to the system dynamically is something that might be considered later.
 */
extern struct nni_transport nni_inproc_transport;

static struct nni_transport *transports[] = {
	&nni_inproc_transport,
	NULL
};

struct nni_transport *
nni_transport_find(const char *addr)
{
	/* address is of the form "<scheme>://blah..." */
	const char *end;
	int len;
	int i;
	struct nni_transport *ops;

	if ((end = strstr(addr, "://")) == NULL) {
		return (NULL);
	}
	len = (int) (end - addr);
	for (i = 0; (ops = transports[i]) != NULL; i++) {
		if (strncmp(addr, ops->tran_scheme, len) == 0) {
			return (ops);
		}
	}
	return (NULL);
}


/*
 * nni_transport_init initializes the entire transport subsystem, including
 * each individual transport.
 */
void
nni_transport_init(void)
{
	int i;
	struct nni_transport *ops;

	for (i = 0; (ops = transports[i]) != NULL; i++) {
		ops->tran_init();
	}
}


void
nni_transport_fini(void)
{
	int i;
	struct nni_transport *ops;

	for (i = 0; (ops = transports[i]) != NULL; i++) {
		if (ops->tran_fini != NULL) {
			ops->tran_fini();
		}
	}
}
