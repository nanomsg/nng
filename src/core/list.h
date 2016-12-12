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

#ifndef CORE_LIST_H
#define CORE_LIST_H

#include "core/nng_impl.h"

/*
 * In order to make life easy, we just define the list structures
 * directly, and let consumers directly inline structures.
 */
typedef struct nni_list_node {
	struct nni_list_node	*ln_next;
	struct nni_list_node	*ln_prev;
} nni_list_node_t;

typedef struct nni_list {
	struct nni_list_node	ll_head;
	size_t			ll_offset;
} nni_list_t;

extern void nni_list_init_offset(nni_list_t *list, size_t offset);
#define	NNI_LIST_INIT(list, type, field)	\
	nni_list_init_offset(list, offsetof (type, field))
extern void *nni_list_first(nni_list_t *);
extern void *nni_list_last(nni_list_t *);
extern void nni_list_append(nni_list_t *, void *);
extern void nni_list_prepend(nni_list_t *, void *);
extern void *nni_list_next(nni_list_t *, void *);
extern void *nni_list_prev(nni_list_t *, void *);
extern void nni_list_remove(nni_list_t *, void *);
extern void nni_list_node_init(nni_list_t *, void *);
#define NNI_LIST_FOREACH(l, it)	\
	for (it = nni_list_first(l); it != NULL; it = nni_list_next(l, it))

#endif	/* CORE_LIST_H */
