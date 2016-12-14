/*
 * Copyright 2016 Garrett D'Amore <garrett@damore.org>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom
 * the Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
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
extern struct nni_protocol	nni_pair_protocol;

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