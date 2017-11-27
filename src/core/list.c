//
// Copyright 2017 Garrett D'Amore <garrett@damore.org>
// Copyright 2017 Capitar IT Group BV <info@capitar.com>
// Copyright 2017 Staysail Systems, Inc. <info@staysail.tech>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <stdlib.h>
#include <string.h>

#include "core/nng_impl.h"

// Linked list implementation.  We implement a doubly linked list.
// Using pointer arithmetic, we can operate as a list of "anything".

#define NODE(list, item) \
	(nni_list_node *) (void *)(((char *) item) + list->ll_offset)
#define ITEM(list, node) (void *) (((char *) node) - list->ll_offset)

void
nni_list_init_offset(nni_list *list, size_t offset)
{
	list->ll_offset       = offset;
	list->ll_head.ln_next = &list->ll_head;
	list->ll_head.ln_prev = &list->ll_head;
}

void *
nni_list_first(const nni_list *list)
{
	nni_list_node *node = list->ll_head.ln_next;

	if (node == &list->ll_head) {
		return (NULL);
	}
	return (ITEM(list, node));
}

void *
nni_list_last(const nni_list *list)
{
	nni_list_node *node = list->ll_head.ln_prev;

	if (node == &list->ll_head) {
		return (NULL);
	}
	return (ITEM(list, node));
}

void
nni_list_append(nni_list *list, void *item)
{
	nni_list_node *node = NODE(list, item);

	if ((node->ln_next != NULL) || (node->ln_prev != NULL)) {
		nni_panic("appending node already on a list or not inited");
	}
	node->ln_prev          = list->ll_head.ln_prev;
	node->ln_next          = &list->ll_head;
	node->ln_next->ln_prev = node;
	node->ln_prev->ln_next = node;
}

void
nni_list_prepend(nni_list *list, void *item)
{
	nni_list_node *node = NODE(list, item);

	if ((node->ln_next != NULL) || (node->ln_prev != NULL)) {
		nni_panic("prepending node already on a list or not inited");
	}
	node->ln_next          = list->ll_head.ln_next;
	node->ln_prev          = &list->ll_head;
	node->ln_next->ln_prev = node;
	node->ln_prev->ln_next = node;
}

void
nni_list_insert_before(nni_list *list, void *item, void *before)
{
	nni_list_node *node  = NODE(list, item);
	nni_list_node *where = NODE(list, before);

	if ((node->ln_next != NULL) || (node->ln_prev != NULL)) {
		nni_panic("inserting node already on a list or not inited");
	}
	node->ln_next          = where;
	node->ln_prev          = where->ln_prev;
	node->ln_next->ln_prev = node;
	node->ln_prev->ln_next = node;
}

void
nni_list_insert_after(nni_list *list, void *item, void *after)
{
	nni_list_node *node  = NODE(list, item);
	nni_list_node *where = NODE(list, after);

	if ((node->ln_next != NULL) || (node->ln_prev != NULL)) {
		nni_panic("inserting node already on a list or not inited");
	}
	node->ln_prev          = where;
	node->ln_next          = where->ln_next;
	node->ln_next->ln_prev = node;
	node->ln_prev->ln_next = node;
}

void *
nni_list_next(const nni_list *list, void *item)
{
	nni_list_node *node = NODE(list, item);

	if ((node = node->ln_next) == &list->ll_head) {
		return (NULL);
	}
	return (ITEM(list, node));
}

void *
nni_list_prev(const nni_list *list, void *item)
{
	nni_list_node *node = NODE(list, item);

	if ((node = node->ln_prev) == &list->ll_head) {
		return (NULL);
	}
	return (ITEM(list, node));
}

void
nni_list_remove(nni_list *list, void *item)
{
	nni_list_node *node = NODE(list, item);

	node->ln_prev->ln_next = node->ln_next;
	node->ln_next->ln_prev = node->ln_prev;
	node->ln_next          = NULL;
	node->ln_prev          = NULL;
}

int
nni_list_active(nni_list *list, void *item)
{
	nni_list_node *node = NODE(list, item);

	return (node->ln_next == NULL ? 0 : 1);
}

int
nni_list_empty(nni_list *list)
{
	// The first check ensures that we treat an uninitialized list
	// as empty.  This use useful for statically initialized lists.
	return ((list->ll_head.ln_next == NULL) ||
	    (list->ll_head.ln_next == &list->ll_head));
}

int
nni_list_node_active(nni_list_node *node)
{
	return (node->ln_next == NULL ? 0 : 1);
}

void
nni_list_node_remove(nni_list_node *node)
{
	if (node->ln_next != NULL) {
		node->ln_prev->ln_next = node->ln_next;
		node->ln_next->ln_prev = node->ln_prev;
		node->ln_next          = NULL;
		node->ln_prev          = NULL;
	}
}
