//
// Copyright 2016 Garrett D'Amore <garrett@damore.org>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "core/idhash.c"
#include "convey.h"

Main({
	Test("General ID Hash", {
		int rv;

		Convey("Given an id hash", {
			nni_idhash *h;

			rv = nni_idhash_create(&h);
			So(rv == 0);
			So(h->ih_cap == 8);
			So(h->ih_entries != NULL);
			So(h->ih_count == 0);

			Reset({
				nni_idhash_destroy(h);
			})

			Convey("We can insert an element", {
				char *five = "five";
				char *four = "four";
				rv = nni_idhash_insert(h, 5, five);
				So(rv == 0);
				So(h->ih_load == 1);
				So(h->ih_count == 1);

				Convey("And we can find it", {
					void *ptr;
					rv = nni_idhash_find(h, 5, &ptr);
					So(rv == 0);
					So(ptr == five);
				})
				Convey("We can delete it", {
					void *ptr;
					rv = nni_idhash_remove(h, 5);
					So(rv == 0);
					rv = nni_idhash_find(h, 5, &ptr);
					So(rv == NNG_ENOENT);
				})
				Convey("We can change the value", {
					void *ptr;
					rv = nni_idhash_insert(h, 5, four);
					So(rv == 0);
					So(h->ih_count == 1);
					rv = nni_idhash_find(h, 5, &ptr);
					So(rv == 0);
					So(ptr == four);
				})
				Convey("We can insert a hash collision", {
					void *ptr;
					rv = nni_idhash_insert(h, 13, four);
					So(rv == 0);
					So(h->ih_load == 2);
					So(h->ih_count == 2);
					rv = nni_idhash_find(h, 5, &ptr);
					So(rv == 0);
					So(ptr == five);
					rv = nni_idhash_find(h, 13, &ptr);
					So(rv == 0);
					So(ptr == four);
					So(h->ih_entries[5].ihe_skips == 1);
					Convey("And delete the intermediate", {
						rv = nni_idhash_remove(h, 5);
						So(rv == 0);
						ptr = NULL;
						rv = nni_idhash_find(h, 13, &ptr);
						So(rv == 0);
						So(ptr == four);
						So(h->ih_load == 2);
					})
				})

			})
			Convey("We cannot find bogus values", {
				void *ptr = NULL;
				rv = nni_idhash_find(h, 42, &ptr);
				So(rv == NNG_ENOENT);
				So(ptr == NULL);
			})
		})
	})

	Test("Resize ID Hash", {
		int expect[1024];
		int actual[1024];
		int rv;
		int i;

		for (i = 0; i < 1024; i++) {
			expect[i] = i;
		}
		Convey("Given an id hash", {
			nni_idhash *h;

			rv = nni_idhash_create(&h);
			So(rv == 0);
			So(h->ih_cap == 8);
			So(h->ih_entries != NULL);
			So(h->ih_count == 0);

			Reset({
				nni_idhash_destroy(h);
			})

			Convey("We can insert 1024 items", {
				uint32_t count;
				for (i = 0; i < 1024; i++) {
					nni_idhash_insert(h, i, &expect[i]);
				}
				So(nni_idhash_count(h, &count) == 0);
				So(count == 1024);
				So(h->ih_cap = 2048);
				So(h->ih_count == 1024);

				Convey("We can remove them", {
					for (i = 0; i < 1024; i++) {
						nni_idhash_remove(h, i);
					}
					So(h->ih_count == 0);
					So(h->ih_cap == 8);
				})
			})
		})
	})
})
