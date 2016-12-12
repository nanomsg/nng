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

#include "core/nng_impl.h"

/*
 * For now the list of transports is hard-wired.  Adding new transports
 * to the system dynamically is something that might be considered later.
 */
extern struct nni_transport	nni_inproc_transport;

static struct nni_transport *transports[] = {
	&nni_inproc_transport,
	NULL
};

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
nni_transport_fork(int prefork)
{
	int i;
	struct nni_transport *ops;

	for (i = 0; (ops = transports[i]) != NULL; i++) {
		if (ops->tran_fork != NULL) {
			ops->tran_fork(prefork);
		}
	}
}
