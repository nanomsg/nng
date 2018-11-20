//
// Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "core/idhash.c"
#include "core/nng_impl.h"

#include "convey.h"

#define STRESSLOAD 50000
#define NVALUES 1000

int
stress(nni_idhash *h, void **values, size_t nvalues, int iter)
{
	for (int i = 0; i < iter; i++) {
		void *x;
		int   v = rand() % nvalues; // Keep it constrained

		switch (rand() & 3) {
		case 0:
			x         = &values[rand() % nvalues];
			values[v] = x;
			if (nni_idhash_insert(h, v, x) != 0) {
				return (-1);
			}
			break;

		case 1:
			if (values[v] == NULL) {
				if (nni_idhash_remove(h, v) != NNG_ENOENT) {
					return (-1);
				} else {
					break;
				}
			} else {
				if (nni_idhash_remove(h, v) != 0) {
					return (-1);
				}
				values[v] = NULL;
			}
			break;
		case 2:
			if (values[v] == NULL) {
				if (nni_idhash_find(h, v, &x) != NNG_ENOENT) {
					return (-1);
				}

			} else {
				if ((nni_idhash_find(h, v, &x) != 0) ||
				    (x != values[v])) {
					return (-1);
				}
			}
			break;
		}
	}
	return (0);
}

int
poststress(nni_idhash *h, void **values, size_t nvalues)
{
	for (size_t i = 0; i < nvalues; i++) {
		void *x;
		if (values[i] == NULL) {
			if ((nni_idhash_find(h, i, &x) != NNG_ENOENT) ||
			    (nni_idhash_remove(h, i) != NNG_ENOENT)) {
				return (-1);
			}
			continue;
		}
		if (((nni_idhash_find(h, i, &x) != 0) || (x != values[i])) ||
		    (nni_idhash_remove(h, i) != 0)) {
			return (-1);
		}
	}
	return (0);
}

Main({
	nni_init();
	atexit(nni_fini);
	Test("General ID Hash", {
		int rv;

		Convey("Given an id hash", {
			nni_idhash *h = NULL;

			So(nni_idhash_init(&h) == 0);
			So(h != NULL);

			Reset({ nni_idhash_fini(h); });

			Convey("We can insert an element", {
				char *five = "five";
				char *four = "four";
				rv         = nni_idhash_insert(h, 5, five);
				So(rv == 0);

				Convey("And we can find it", {
					void *ptr;
					rv = nni_idhash_find(h, 5, &ptr);
					So(rv == 0);
					So(ptr == five);
				});
				Convey("We can delete it", {
					void *ptr;
					rv = nni_idhash_remove(h, 5);
					So(rv == 0);
					rv = nni_idhash_find(h, 5, &ptr);
					So(rv == NNG_ENOENT);
				});
				Convey("We can change the value", {
					void *ptr;
					So(nni_idhash_insert(h, 5, four) == 0);
					So(nni_idhash_find(h, 5, &ptr) == 0);
					So(ptr == four);
				});
				Convey("We can insert a hash collision", {
					void *ptr;
					So(nni_idhash_insert(h, 13, four) ==
					    0);
					So(nni_idhash_find(h, 5, &ptr) == 0);
					So(ptr == five);
					So(nni_idhash_find(h, 13, &ptr) == 0);
					So(ptr == four);
					Convey("And delete intermediate", {
						So(nni_idhash_remove(h, 5) ==
						    0);
						ptr = NULL;
						So(nni_idhash_find(
						       h, 13, &ptr) == 0);
						So(ptr == four);
					});
				});
			});
			Convey("We cannot find bogus values", {
				void *ptr;
				ptr = NULL;
				rv  = nni_idhash_find(h, 42, &ptr);
				So(rv == NNG_ENOENT);
				So(ptr == NULL);
			});

			Convey("64-bit hash values work", {
				char *   huge    = "huge";
				void *   ptr     = NULL;
				uint64_t hugenum = 0x1234567890ULL;

				nni_idhash_set_limits(h, 1, 1ULL << 63, 1);
				So(nni_idhash_insert(h, hugenum, huge) == 0);
				So(nni_idhash_find(h, hugenum, &ptr) == 0);
				So((char *) ptr == huge);
			});

			Convey("64-bit dynvals work", {
				char *   huge = "dynhuge";
				void *   ptr  = NULL;
				uint64_t id;

				nni_idhash_set_limits(
				    h, 1ULL << 32, 1ULL << 63, 1);
				So(nni_idhash_alloc(h, &id, huge) == 0);
				So(id > 0xffffffff);
				So(nni_idhash_find(h, id, &ptr) == 0);
				So((char *) ptr == huge);
			});
		});
	});

	Test("Resize ID Hash", {
		int expect[1024];
		int i;

		for (i = 0; i < 1024; i++) {
			expect[i] = i;
		}
		Convey("Given an id hash", {
			nni_idhash *h;

			So(nni_idhash_init(&h) == 0);

			Reset({ nni_idhash_fini(h); });

			Convey("We can insert 1024 items", {
				for (i = 0; i < 1024; i++) {
					nni_idhash_insert(h, i, &expect[i]);
				}

				Convey("We can remove them", {
					for (i = 0; i < 1024; i++) {
						nni_idhash_remove(h, i);
					}
				});
			});
		});
	});

	Test("Dynamic ID generation", {
		Convey("Given a small ID hash", {
			nni_idhash *h;
			int         expect[5];
			uint64_t    id;
			So(nni_idhash_init(&h) == 0);
			Reset({ nni_idhash_fini(h); });
			nni_idhash_set_limits(h, 10, 13, 10);
			So(1);
			Convey("We can fill the table", {
				for (uint64_t i = 0; i < 4; i++) {
					So(nni_idhash_alloc(
					       h, &id, &expect[i]) == 0);
					So(id == (i + 10));
				}
				Convey("Adding another fails", {
					So(nni_idhash_alloc(h, &id,
					       &expect[5]) == NNG_ENOMEM);
				});
				Convey("Deleting one lets us reinsert", {
					nni_idhash_remove(h, 11);
					So(nni_idhash_alloc(
					       h, &id, &expect[5]) == 0);
					So(id == 11);
				});
			});
			Convey("We can insert outside range forcibly", {
				So(nni_idhash_insert(h, 1, &expect[0]) == 0);
				So(nni_idhash_insert(h, 100, &expect[0]) == 0);
				So(nni_idhash_alloc(h, &id, &expect[1]) == 0);
				So(id >= 10);
				So(id <= 13);
			});
		});
	});

	Test("Stress it", {
		void *values[NVALUES];

		Convey("Given a hash", {
			nni_idhash *h;
			So(nni_idhash_init(&h) == 0);
			Reset({ nni_idhash_fini(h); });
			memset(values, 0, sizeof(values));

			Convey("A stress run works", {
				So(stress(h, values, NVALUES, STRESSLOAD) ==
				    0);
				So(poststress(h, values, NVALUES) == 0);
				So(nni_idhash_count(h) == 0);
			});
		});
	});
})
