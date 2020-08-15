//
// Copyright 2020 Staysail Systems, Inc. <info@staysail.tech>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "acutest.h"
#include "testutil.h"

#include "core/idhash.h"

void
test_basic(void)
{
	nni_id_map m;
	char *     five = "five";
	char *     four = "four";

	nni_id_map_init(&m, 0, 0, false);

	// insert it
	TEST_NNG_PASS(nni_id_set(&m, 5, five));
	// retrieve it
	TEST_CHECK(nni_id_get(&m, 5) == five);

	// change it
	TEST_NNG_PASS(nni_id_set(&m, 5, four));
	TEST_CHECK(nni_id_get(&m, 5) == four);

	// delete
	TEST_NNG_PASS(nni_id_remove(&m, 5));

	nni_id_map_fini(&m);
}

void
test_random(void)
{
	int      i;
	uint32_t id;
	for (i = 0; i < 2; i++) {
		nni_id_map m;
		nni_id_map_init(&m, 0, 0, true);
		TEST_NNG_PASS(nni_id_alloc(&m, &id, &id));
		nni_id_map_fini(&m);
		TEST_CHECK(id != 0);
		if (id != 1) {
			break;
		}
		// one chance in 4 billion, but try again
	}

	TEST_CHECK(id != 1);
	TEST_CHECK(i < 2);
}

void
test_collision(void)
{
	nni_id_map m;
	char *     five = "five";
	char *     four = "four";

	nni_id_map_init(&m, 0, 0, false);

	// Carefully crafted -- 13 % 8 == 5.
	TEST_NNG_PASS(nni_id_set(&m, 5, five));
	TEST_NNG_PASS(nni_id_set(&m, 13, four));
	TEST_CHECK(nni_id_get(&m, 5) == five);
	TEST_CHECK(nni_id_get(&m, 13) == four);

	// Delete the intermediate
	TEST_NNG_PASS(nni_id_remove(&m, 5));
	TEST_CHECK(nni_id_get(&m, 13) == four);

	nni_id_map_fini(&m);
}

void
test_empty(void)
{
	nni_id_map m;
	nni_id_map_init(&m, 0, 0, false);

	TEST_CHECK(nni_id_get(&m, 42) == NULL);
	TEST_NNG_FAIL(nni_id_remove(&m, 42), NNG_ENOENT);
	TEST_NNG_FAIL(nni_id_remove(&m, 1), NNG_ENOENT);
	nni_id_map_fini(&m);
}

void
test_not_found(void)
{
	nni_id_map m;
	uint32_t   id;
	nni_id_map_init(&m, 0, 0, false);

	TEST_NNG_PASS(nni_id_alloc(&m, &id, &id));
	TEST_NNG_FAIL(nni_id_remove(&m, 42), NNG_ENOENT);
	TEST_NNG_FAIL(nni_id_remove(&m, 2), NNG_ENOENT);
	TEST_NNG_PASS(nni_id_remove(&m, id));
	nni_id_map_fini(&m);
}

void
test_resize(void)
{
	nni_id_map m;
	int        rv;
	int        i;
	int        expect[1024];

	for (i = 0; i < 1024; i++) {
		expect[i] = i;
	}

	nni_id_map_init(&m, 0, 0, false);

	for (i = 0; i < 1024; i++) {
		if ((rv = nni_id_set(&m, i, &expect[i])) != 0) {
			TEST_NNG_PASS(rv);
		}
	}

	for (i = 0; i < 1024; i++) {
		if ((rv = nni_id_remove(&m, i)) != 0) {
			TEST_NNG_PASS(rv);
		}
	}
	nni_id_map_fini(&m);
}

void
test_dynamic(void)
{
	nni_id_map m;
	int        expect[5];
	uint32_t   id;

	nni_id_map_init(&m, 10, 13, false);

        // We can fill the table.
	TEST_NNG_PASS(nni_id_alloc(&m, &id, &expect[0]));
	TEST_CHECK(id == 10);
	TEST_NNG_PASS(nni_id_alloc(&m, &id, &expect[1]));
	TEST_CHECK(id == 11);
	TEST_NNG_PASS(nni_id_alloc(&m, &id, &expect[2]));
	TEST_CHECK(id == 12);
	TEST_NNG_PASS(nni_id_alloc(&m, &id, &expect[3]));
	TEST_CHECK(id == 13);

	// Adding another fails.
	TEST_NNG_FAIL(nni_id_alloc(&m, &id, &expect[4]), NNG_ENOMEM);

	// Delete one.
	TEST_NNG_PASS(nni_id_remove(&m, 11));

	// And now we can allocate one.
	TEST_NNG_PASS(nni_id_alloc(&m, &id, &expect[4]));
	TEST_CHECK(id == 11);
	nni_id_map_fini(&m);
}

void
test_set_out_of_range(void)
{
	nni_id_map m;
	int        x;
	uint32_t   id;

	nni_id_map_init(&m, 10, 13, false);

	// We can insert outside the range forcibly.
	TEST_NNG_PASS(nni_id_set(&m, 1, &x));
	TEST_NNG_PASS(nni_id_set(&m, 100, &x));
	TEST_NNG_PASS(nni_id_alloc(&m, &id, &x));
	TEST_CHECK(id == 10);
	nni_id_map_fini(&m);
}

#define STRESS_LOAD 50000
#define NUM_VALUES 1000

void
test_stress(void)
{
	void *     values[NUM_VALUES];
	nni_id_map m;
	size_t     i;
	int        rv;
	void *     x;
	int        v;

	nni_id_map_init(&m, 0, 0, false);
	for (i = 0; i < NUM_VALUES; i++) {
		values[i] = NULL;
	}

	for (i = 0; i < STRESS_LOAD; i++) {
		v = rand() % NUM_VALUES; // Keep it constrained

		switch (rand() & 3) {
		case 0:
			x         = &values[rand() % NUM_VALUES];
			values[v] = x;
			if ((rv = nni_id_set(&m, v, x)) != 0) {
				TEST_NNG_PASS(rv);
				goto out;
			}
			break;

		case 1:
			rv = nni_id_remove(&m, v);
			if (values[v] == NULL) {
				if (rv != NNG_ENOENT) {
					TEST_NNG_FAIL(rv, NNG_ENOENT);
					goto out;
				}
			} else {
				values[v] = NULL;
				if (rv != 0) {
					TEST_NNG_PASS(rv);
					goto out;
				}
			}
			break;
		case 2:
			x = nni_id_get(&m, v);
			if (x != values[v]) {
				TEST_CHECK(x == values[v]);
				goto out;
			}
			break;
		}
	}
out:
	TEST_CHECK(i == STRESS_LOAD);

	// Post stress check.
	for (i = 0; i < NUM_VALUES; i++) {
		x = nni_id_get(&m, i);
		if (x != values[i]) {
			TEST_CHECK(x == values[i]);
			break;
		}

		// We only use the test macros if we know they are going
		// to fail.  Otherwise there will be too many errors reported.
		rv = nni_id_remove(&m, i);
		if ((x == NULL) && (rv != NNG_ENOENT)) {
			TEST_NNG_FAIL(rv, NNG_ENOENT);
		} else if ((x != NULL) && (rv != 0)) {
			TEST_NNG_PASS(rv);
		}
	}
	TEST_CHECK(i == NUM_VALUES);

	nni_id_map_fini(&m);
}

TEST_LIST = {
	{ "basic", test_basic },
	{ "random", test_random },
	{ "collision", test_collision },
	{ "empty", test_empty },
	{ "not found", test_not_found },
	{ "resize", test_resize },
	{ "dynamic", test_dynamic },
	{ "set out of range", test_set_out_of_range },
	{ "stress", test_stress },
	{ NULL, NULL },
};
