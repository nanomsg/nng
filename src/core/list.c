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

#include <stdlib.h>
#include <string.h>

#include "core/nng_impl.h"

/*
 * Linked list implementation.  We implement a doubly linked list.
 * Using pointer arithmetic, we can operate as a list of "anything".
 */

#define	NODE(list, item)	\
	(nni_list_node_t)(void *)(((char *)item) + list->ll_offset)
#define	ITEM(list, node)	\
	(void *)(((char *)node) - list->ll_offset)

void
nni_list_init_offset(nni_list_t list, size_t offset)
{
	list->ll_offset = offset;
	list->ll_head.ln_next = &list->ll_head;
	list->ll_head.ln_prev = &list->ll_head;
}

void *
nni_list_first(nni_list_t list)
{
	nni_list_node_t node = list->ll_head.ln_next;
	if (node == &list->ll_head) {
		return (NULL);
	}
	return (ITEM(list, node));
}

void *
nni_list_last(nni_list_t list)
{
	nni_list_node_t node = list->ll_head.ln_prev;
	if (node == &list->ll_head) {
		return (NULL);
	}
	return (ITEM(list, node));
}

void
nni_list_append(nni_list_t list, void *item)
{
	nni_list_node_t node = NODE(list, item);

	node->ln_prev = list->ll_head.ln_prev;
	node->ln_next = &list->ll_head;
	node->ln_next->ln_prev = node;
	node->ln_prev->ln_next = node;
}
void
nni_list_prepend(nni_list_t list, void *item)
{
	nni_list_node_t node = NODE(list, item);

	node->ln_next = list->ll_head.ln_next;
	node->ln_prev = &list->ll_head;
	node->ln_next->ln_prev = node;
	node->ln_prev->ln_next = node;
}

void *
nni_list_next(nni_list_t list, void *item)
{
	nni_list_node_t node = NODE(list, item);

	if ((node = node->ln_next) == &list->ll_head) {
		return (NULL);
	}
	return (ITEM(list, node));
}

void *
nni_list_prev(nni_list_t list, void *item)
{
	nni_list_node_t node = NODE(list, item);

	if ((node = node->ln_prev) == &list->ll_head) {
		return (NULL);
	}
	return (ITEM(list, node));
}

void
nni_list_remove(nni_list_t list, void *item)
{
	nni_list_node_t node = NODE(list, item);
	node->ln_prev->ln_next = node->ln_next;
	node->ln_next->ln_prev = node->ln_prev;
}

void
nni_list_node_init(nni_list_t list, void *item)
{
	nni_list_node_t	node = NODE(list, item);
	node->ln_prev = node->ln_next = NULL;
}
