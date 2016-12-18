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

#include "core/list.c"
#include "test.h"

typedef struct {
	int pad[2];
	nni_list_node_t nodea;
	nni_list_node_t nodeb;
} mystruct;

test_main("Linked Lists", {
	test_convey("Given a couple lists", {
		nni_list_t alist;
		nni_list_t blist;

		NNI_LIST_INIT(&alist, mystruct, nodea);
		NNI_LIST_INIT(&blist, mystruct, nodeb);

		test_so(alist.ll_offset == 8);
		test_so(blist.ll_offset == (8 + sizeof (nni_list_node_t)));

		test_convey("The list starts empty", {
			test_so(nni_list_first(&alist) == NULL);
			test_so(nni_list_last(&blist) == NULL);
		});

		test_convey("And we can add an item", {
			mystruct item;
			nni_list_append(&alist, &item);

			test_convey("It is the first item", {
				test_so(nni_list_first(&alist) == &item);
			});
			test_convey("It is the last item", {
				test_so(nni_list_last(&alist) == &item);
			});
			test_convey("It is the only item", {
				test_so(nni_list_next(&alist, &item) == NULL);
				test_so(nni_list_prev(&alist, &item) == NULL);
			});
			test_convey("It isn't on the other list", {
				test_so(nni_list_first(&blist) == NULL);
				test_so(nni_list_last(&blist) == NULL);
			});
			test_convey("We can remove it", {
				nni_list_remove(&alist, &item);
				test_so(nni_list_first(&alist) == NULL);
				test_so(nni_list_last(&alist) == NULL);
			});
		});

		test_convey("We can add two items", {
			mystruct item1;
			mystruct item2;

			nni_list_append(&alist, &item1);
			nni_list_append(&alist, &item2);

			test_so(nni_list_first(&alist) == &item1);
			test_so(nni_list_last(&alist) == &item2);
			test_so(nni_list_next(&alist, &item1) == &item2);
			test_so(nni_list_prev(&alist, &item2) == &item1);

			test_so(nni_list_next(&alist, &item2) == NULL);
			test_so(nni_list_prev(&alist, &item1) == NULL);

			test_convey("Removing the first works", {
				nni_list_remove(&alist, &item1);
				test_so(nni_list_first(&alist) == &item2);
				test_so(nni_list_last(&alist) == &item2);
				test_so(nni_list_next(&alist, &item2) == NULL);
				test_so(nni_list_prev(&alist, &item2) == NULL);
			});

			test_convey("Removing the second works", {
				nni_list_remove(&alist, &item2);
				test_so(nni_list_first(&alist) == &item1);
				test_so(nni_list_last(&alist) == &item1);
				test_so(nni_list_next(&alist, &item1) == NULL);
				test_so(nni_list_prev(&alist, &item1) == NULL);
			});
		});
	});
})