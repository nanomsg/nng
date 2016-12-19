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
#include "convey.h"

typedef struct {
	int pad[2];
	nni_list_node_t nodea;
	nni_list_node_t nodeb;
} mystruct;

TestMain("Linked Lists", {
	Convey("Given a couple lists", {
		nni_list_t alist;
		nni_list_t blist;

		NNI_LIST_INIT(&alist, mystruct, nodea);
		NNI_LIST_INIT(&blist, mystruct, nodeb);

		So(alist.ll_offset == 8);
		So(blist.ll_offset == (8 + sizeof (nni_list_node_t)));

		Convey("The list starts empty", {
			So(nni_list_first(&alist) == NULL);
			So(nni_list_last(&blist) == NULL);
		});

		Convey("And we can add an item", {
			mystruct item;
			nni_list_append(&alist, &item);

			Convey("It is the first item", {
				So(nni_list_first(&alist) == &item);
			});
			Convey("It is the last item", {
				So(nni_list_last(&alist) == &item);
			});
			Convey("It is the only item", {
				So(nni_list_next(&alist, &item) == NULL);
				So(nni_list_prev(&alist, &item) == NULL);
			});
			Convey("It isn't on the other list", {
				So(nni_list_first(&blist) == NULL);
				So(nni_list_last(&blist) == NULL);
			});
			Convey("We can remove it", {
				nni_list_remove(&alist, &item);
				So(nni_list_first(&alist) == NULL);
				So(nni_list_last(&alist) == NULL);
			});
		});

		Convey("We can add two items", {
			mystruct item1;
			mystruct item2;

			nni_list_append(&alist, &item1);
			nni_list_append(&alist, &item2);

			So(nni_list_first(&alist) == &item1);
			So(nni_list_last(&alist) == &item2);
			So(nni_list_next(&alist, &item1) == &item2);
			So(nni_list_prev(&alist, &item2) == &item1);

			So(nni_list_next(&alist, &item2) == NULL);
			So(nni_list_prev(&alist, &item1) == NULL);

			Convey("Removing the first works", {
				nni_list_remove(&alist, &item1);
				So(nni_list_first(&alist) == &item2);
				So(nni_list_last(&alist) == &item2);
				So(nni_list_next(&alist, &item2) == NULL);
				So(nni_list_prev(&alist, &item2) == NULL);
			});

			Convey("Removing the second works", {
				nni_list_remove(&alist, &item2);
				So(nni_list_first(&alist) == &item1);
				So(nni_list_last(&alist) == &item1);
				So(nni_list_next(&alist, &item1) == NULL);
				So(nni_list_prev(&alist, &item1) == NULL);
			});
		});
	});
})