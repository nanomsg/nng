//
// Copyright 2016 Garrett D'Amore <garrett@damore.org>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "core/list.c"
#include "convey.h"
#include "stubs.h"

typedef struct {
	int pad[2];
	nni_list_node nodea;
	nni_list_node nodeb;
} mystruct;

TestMain("Linked Lists", {
	Convey("Given a couple lists", {
		nni_list alist;
		nni_list blist;

		NNI_LIST_INIT(&alist, mystruct, nodea);
		NNI_LIST_INIT(&blist, mystruct, nodeb);

		So(alist.ll_offset == 8);
		So(blist.ll_offset == (8 + sizeof (nni_list_node)));

		Convey("The list starts empty", {
			So(nni_list_first(&alist) == NULL);
			So(nni_list_last(&blist) == NULL);
		});

		Convey("And we can add an item", {
			mystruct item;

			NNI_LIST_NODE_INIT(&item.nodea);
			NNI_LIST_NODE_INIT(&item.nodeb);

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

			NNI_LIST_NODE_INIT(&item1.nodea);
			NNI_LIST_NODE_INIT(&item1.nodeb);
			NNI_LIST_NODE_INIT(&item2.nodea);
			NNI_LIST_NODE_INIT(&item2.nodeb);

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
