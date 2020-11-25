//
// Copyright 2020 Staysail Systems, Inc. <info@staysail.tech>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "nng_impl.h"
#include "stubs.h"
#include <nuts.h>

typedef struct {
	int           pad[2];
	nni_list_node node_a;
	nni_list_node node_b;
} my_struct;

static void
test_list_init_empty(void)
{
	nni_list a;
	nni_list b;

	NNI_LIST_INIT(&a, my_struct, node_a);
	NNI_LIST_INIT(&b, my_struct, node_b);

	NUTS_TRUE(nni_list_first(&a) == NULL);
	NUTS_TRUE(nni_list_last(&b) == NULL);

	NUTS_TRUE(a.ll_offset == 8);
	NUTS_TRUE(b.ll_offset == (8 + sizeof(nni_list_node)));
}

static void
test_list_add_item(void)
{
	nni_list  a;
	nni_list  b;
	my_struct item;

	NNI_LIST_INIT(&a, my_struct, node_a);
	NNI_LIST_INIT(&b, my_struct, node_b);

	NUTS_TRUE(nni_list_first(&a) == NULL);
	NUTS_TRUE(nni_list_last(&b) == NULL);

	NNI_LIST_NODE_INIT(&item.node_a);
	NNI_LIST_NODE_INIT(&item.node_b);

	nni_list_append(&a, &item);

	// it's the first item.
	NUTS_TRUE(nni_list_first(&a) == &item);

	// it's also the last item.
	NUTS_TRUE(nni_list_last(&a) == &item);

	// and there are no other items.
	NUTS_TRUE(nni_list_next(&a, &item) == NULL);
	NUTS_TRUE(nni_list_prev(&a, &item) == NULL);

	// not on the other list.
	NUTS_TRUE(nni_list_first(&b) == NULL);
	NUTS_TRUE(nni_list_last(&b) == NULL);

	// removing it works
	nni_list_remove(&a, &item);

	// And that leaves the list empty.
	NUTS_TRUE(nni_list_first(&a) == NULL);
	NUTS_TRUE(nni_list_last(&a) == NULL);
}

static void
test_list_two_items(void)
{
	nni_list  a;
	nni_list  b;
	my_struct item1;
	my_struct item2;

	NNI_LIST_INIT(&a, my_struct, node_a);
	NNI_LIST_INIT(&b, my_struct, node_b);

	NNI_LIST_NODE_INIT(&item1.node_a);
	NNI_LIST_NODE_INIT(&item1.node_b);
	NNI_LIST_NODE_INIT(&item2.node_a);
	NNI_LIST_NODE_INIT(&item2.node_b);

	nni_list_append(&a, &item1);
	nni_list_append(&a, &item2);

	NUTS_TRUE(nni_list_first(&a) == &item1);
	NUTS_TRUE(nni_list_last(&a) == &item2);
	NUTS_TRUE(nni_list_next(&a, &item1) == &item2);
	NUTS_TRUE(nni_list_prev(&a, &item2) == &item1);

	NUTS_TRUE(nni_list_next(&a, &item2) == NULL);
	NUTS_TRUE(nni_list_prev(&a, &item1) == NULL);

	// remove the first
	nni_list_remove(&a, &item1);
	NUTS_TRUE(nni_list_first(&a) == &item2);
	NUTS_TRUE(nni_list_last(&a) == &item2);
	NUTS_TRUE(nni_list_next(&a, &item2) == NULL);
	NUTS_TRUE(nni_list_prev(&a, &item2) == NULL);

	// remove the second
	nni_list_remove(&a, &item2);
	NUTS_TRUE(nni_list_first(&a) == NULL);
	NUTS_TRUE(nni_list_last(&a) == NULL);
	NUTS_TRUE(nni_list_next(&a, &item2) == NULL);
	NUTS_TRUE(nni_list_prev(&a, &item2) == NULL);
}

NUTS_TESTS = {
    { "list empty", test_list_init_empty },
    { "list add one", test_list_add_item },
    { "list add two", test_list_two_items },
    { NULL, NULL },
};