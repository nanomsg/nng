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
 * Protocol related stuff - generically.
 */

/*
 * The list of protocols is hardwired.  This is reasonably unlikely to
 * change, as adding new protocols is not something intended to be done
 * outside of the core.
 */
extern struct nni_protocol nni_pair_protocol;

static struct nni_protocol *protocols[] = {
	&nni_pair_protocol,
	NULL
};

struct nni_protocol *
nni_protocol_find(uint16_t num)
{
	int i;
	struct nni_protocol *p;

	for (i = 0; (p = protocols[i]) != NULL; i++) {
		if (p->proto_self == num) {
			break;
		}
	}
	return (p);
}


const char *
nni_protocol_name(uint16_t num)
{
	struct nni_protocol *p;

	if ((p = nni_protocol_find(num)) == NULL) {
		return (NULL);
	}
	return (p->proto_name);
}


uint16_t
nni_protocol_number(const char *name)
{
	struct nni_protocol *p;
	int i;

	for (i = 0; (p = protocols[i]) != NULL; i++) {
		if (strcmp(p->proto_name, name) == 0) {
			return (p->proto_self);
		}
	}
	return (NNG_PROTO_NONE);
}
