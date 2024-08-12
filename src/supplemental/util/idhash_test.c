//
// Copyright 2024 Staysail Systems, Inc. <info@staysail.tech>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <nuts.h>

#include <nng/supplemental/util/idhash.h>

void
test_id_basic(void)
{
	nng_id_map *m;
	char       *five = "five";
	char       *four = "four";

	NUTS_PASS(nng_id_map_alloc(&m, 0, 0, 0));

	// insert it
	NUTS_PASS(nng_id_set(m, 5, five));
	// retrieve it
	NUTS_TRUE(nng_id_get(m, 5) == five);

	// change it
	NUTS_PASS(nng_id_set(m, 5, four));
	NUTS_TRUE(nng_id_get(m, 5) == four);

	// delete
	NUTS_PASS(nng_id_remove(m, 5));

	nng_id_map_free(m);
}

void
test_id_random(void)
{
	int      i;
	uint64_t id;
	for (i = 0; i < 2; i++) {
		nng_id_map *m;
		NUTS_PASS(nng_id_map_alloc(&m, 0, 0, NNG_MAP_RANDOM));
		NUTS_PASS(nng_id_alloc(m, &id, &id));
		nng_id_map_free(m);
		NUTS_TRUE(id != 0);
		if (id != 1) {
			break;
		}
		// one chance in 4 billion, but try again
	}

	NUTS_TRUE(id != 1);
	NUTS_TRUE(i < 2);
}

void
test_id_collision(void)
{
	nng_id_map *m;
	char       *five = "five";
	char       *four = "four";

	NUTS_PASS(nng_id_map_alloc(&m, 0, 0, 0));

	// Carefully crafted -- 13 % 8 == 5.
	NUTS_PASS(nng_id_set(m, 5, five));
	NUTS_PASS(nng_id_set(m, 13, four));
	NUTS_TRUE(nng_id_get(m, 5) == five);
	NUTS_TRUE(nng_id_get(m, 13) == four);

	// Delete the intermediate
	NUTS_PASS(nng_id_remove(m, 5));
	NUTS_TRUE(nng_id_get(m, 13) == four);

	nng_id_map_free(m);
}

void
test_id_empty(void)
{
	nng_id_map *m;

	NUTS_PASS(nng_id_map_alloc(&m, 0, 0, 0));

	NUTS_TRUE(nng_id_get(m, 42) == NULL);
	NUTS_FAIL(nng_id_remove(m, 42), NNG_ENOENT);
	NUTS_FAIL(nng_id_remove(m, 1), NNG_ENOENT);
	nng_id_map_free(m);
}

void
test_id_not_found(void)
{
	nng_id_map *m;
	uint64_t    id;

	NUTS_PASS(nng_id_map_alloc(&m, 0, 0, 0));

	NUTS_PASS(nng_id_alloc(m, &id, &id));
	NUTS_FAIL(nng_id_remove(m, 42), NNG_ENOENT);
	NUTS_FAIL(nng_id_remove(m, 2), NNG_ENOENT);
	NUTS_PASS(nng_id_remove(m, id));
	nng_id_map_free(m);
}

void
test_id_resize(void)
{
	nng_id_map *m;
	int         rv;
	int         i;
	int         expect[1024];

	for (i = 0; i < 1024; i++) {
		expect[i] = i;
	}

	NUTS_PASS(nng_id_map_alloc(&m, 0, 0, 0));

	for (i = 0; i < 1024; i++) {
		if ((rv = nng_id_set(m, i, &expect[i])) != 0) {
			NUTS_PASS(rv);
		}
	}

	for (i = 0; i < 1024; i++) {
		if ((rv = nng_id_remove(m, i)) != 0) {
			NUTS_PASS(rv);
		}
	}
	nng_id_map_free(m);
}

void
test_id_dynamic(void)
{
	nng_id_map *m;
	int         expect[5];
	uint64_t    id;

	NUTS_PASS(nng_id_map_alloc(&m, 10, 13, 0));

	// We can fill the table.
	NUTS_PASS(nng_id_alloc(m, &id, &expect[0]));
	NUTS_TRUE(id == 10);
	NUTS_PASS(nng_id_alloc(m, &id, &expect[1]));
	NUTS_TRUE(id == 11);
	NUTS_PASS(nng_id_alloc(m, &id, &expect[2]));
	NUTS_TRUE(id == 12);
	NUTS_PASS(nng_id_alloc(m, &id, &expect[3]));
	NUTS_TRUE(id == 13);

	// Adding another fails.
	NUTS_FAIL(nng_id_alloc(m, &id, &expect[4]), NNG_ENOMEM);

	// Delete one.
	NUTS_PASS(nng_id_remove(m, 11));

	// And now we can allocate one.
	NUTS_PASS(nng_id_alloc(m, &id, &expect[4]));
	NUTS_TRUE(id == 11);
	nng_id_map_free(m);
}

void
test_id_set_out_of_range(void)
{
	nng_id_map *m;
	int         x;
	uint64_t    id;

	NUTS_PASS(nng_id_map_alloc(&m, 10, 13, 0));

	// We can insert outside the range forcibly.
	NUTS_PASS(nng_id_set(m, 1, &x));
	NUTS_PASS(nng_id_set(m, 100, &x));
	NUTS_PASS(nng_id_alloc(m, &id, &x));
	NUTS_TRUE(id == 10);
	nng_id_map_free(m);
}

void
test_id_visit(void)
{
	nng_id_map *m;
	int         x, y;
	uint64_t    id1;
	uint64_t    id2;
	int        *v1;
	int        *v2;
	uint32_t    cursor = 0;

	NUTS_PASS(nng_id_map_alloc(&m, 10, 13, 0));

	// We can insert outside the range forcibly.
	NUTS_PASS(nng_id_set(m, 1, &x));
	NUTS_PASS(nng_id_set(m, 100, &y));
	NUTS_TRUE(nng_id_visit(m, &id1, (void **) &v1, &cursor));
	NUTS_ASSERT(id1 == 1 || id1 == 100);
	NUTS_ASSERT(v1 == &x || v1 == &y);
	NUTS_TRUE(nng_id_visit(m, &id2, (void **) &v2, &cursor));
	NUTS_ASSERT(id2 == 1 || id2 == 100);
	NUTS_ASSERT(v2 == &x || v2 == &y);
	NUTS_ASSERT(id1 != id2);
	NUTS_ASSERT(v1 != v2);
	NUTS_TRUE(!nng_id_visit(m, &id2, (void **) &v2, &cursor));
	nng_id_map_free(m);
}

void
test_id_visit_out_of_range(void)
{
	nng_id_map *m;
	int         x, y;
	uint64_t    id1;
	int        *v1;
	uint32_t    cursor = 1000;

	NUTS_PASS(nng_id_map_alloc(&m, 10, 13, 0));

	// We can insert outside the range forcibly.
	NUTS_PASS(nng_id_set(m, 1, &x));
	NUTS_PASS(nng_id_set(m, 100, &y));
	NUTS_TRUE(!nng_id_visit(m, &id1, (void **) &v1, &cursor));
	nng_id_map_free(m);
}

#define STRESS_LOAD 50000
#define NUM_VALUES 1000

void
test_id_stress(void)
{
	void       *values[NUM_VALUES];
	nng_id_map *m;
	size_t      i;
	int         rv;
	void       *x;
	int         v;

	NUTS_PASS(nng_id_map_alloc(&m, 0, 0, 0));
	for (i = 0; i < NUM_VALUES; i++) {
		values[i] = NULL;
	}

	for (i = 0; i < STRESS_LOAD; i++) {
		v = rand() % NUM_VALUES; // Keep it constrained

		switch (rand() & 3) {
		case 0:
			x         = &values[rand() % NUM_VALUES];
			values[v] = x;
			if ((rv = nng_id_set(m, v, x)) != 0) {
				NUTS_PASS(rv);
				goto out;
			}
			break;

		case 1:
			rv = nng_id_remove(m, v);
			if (values[v] == NULL) {
				if (rv != NNG_ENOENT) {
					NUTS_FAIL(rv, NNG_ENOENT);
					goto out;
				}
			} else {
				values[v] = NULL;
				if (rv != 0) {
					NUTS_PASS(rv);
					goto out;
				}
			}
			break;
		case 2:
			x = nng_id_get(m, v);
			if (x != values[v]) {
				NUTS_TRUE(x == values[v]);
				goto out;
			}
			break;
		}
	}
out:
	NUTS_TRUE(i == STRESS_LOAD);

	// Post stress check.
	for (i = 0; i < NUM_VALUES; i++) {
		x = nng_id_get(m, (uint32_t) i);
		if (x != values[i]) {
			NUTS_TRUE(x == values[i]);
			break;
		}

		// We only use the test macros if we know they are going
		// to fail.  Otherwise, there will be too many errors reported.
		rv = nng_id_remove(m, (uint32_t) i);
		if ((x == NULL) && (rv != NNG_ENOENT)) {
			NUTS_FAIL(rv, NNG_ENOENT);
		} else if ((x != NULL) && (rv != 0)) {
			NUTS_PASS(rv);
		}
	}
	NUTS_TRUE(i == NUM_VALUES);

	nng_id_map_free(m);
}

void
test_id_alloc_long_long(void)
{
#define TEST_IDS 100
	nng_id_map *m;
	int         x;
	uint64_t    ids[TEST_IDS];

	NUTS_PASS(nng_id_map_alloc(&m, 1ULL << 32, (int64_t) -1, 0));

	// We can insert outside the range forcibly - making sure we are
	// choosing numbers above 64 bits.
	for (int i = 0; i < TEST_IDS; i++) {
		NUTS_PASS(nng_id_alloc(m, &ids[i], &x));
		NUTS_ASSERT(ids[i] > 0xFFFFFFFFULL);
	}
	for (int i = 0; i < TEST_IDS; i++) {
		bool matched = false;
		for (int j = 0; j < i; j++) {
			// only dump the assertion on failure
			// otherwise it is too noisy
			if (ids[i] == ids[j]) {
				matched = true;
				break;
			}
		}
		NUTS_ASSERT(!matched);
	}
	nng_id_map_free(m);
#undef TEST_IDS
}

NUTS_TESTS = {
	{ "id basic", test_id_basic },
	{ "id random", test_id_random },
	{ "id collision", test_id_collision },
	{ "id empty", test_id_empty },
	{ "not found", test_id_not_found },
	{ "id resize", test_id_resize },
	{ "id dynamic", test_id_dynamic },
	{ "id set out of range", test_id_set_out_of_range },
	{ "id visit", test_id_visit },
	{ "id visit out of range", test_id_visit_out_of_range },
	{ "id stress", test_id_stress },
	{ "id alloc long long", test_id_alloc_long_long },
	{ NULL, NULL },
};
