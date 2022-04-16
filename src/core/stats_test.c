//
// Copyright 2022 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <nuts.h>

#define SECONDS(x) ((x) *1000)

void
test_stats_socket(void)
{
#ifdef NNG_ENABLE_STATS
	nng_socket s1;
	nng_socket s2;
	nng_stat  *st1;
	nng_stat  *st2;
	nng_stat *item;
	nng_stat  *stats;

	NUTS_OPEN(s1);
	NUTS_OPEN(s2);
	nng_socket_set_string(s2, NNG_OPT_SOCKNAME, "second");
	NUTS_MARRY(s1, s2);
	NUTS_SEND(s1, "ping");
	NUTS_RECV(s2, "ping");

	nng_stats_get(&stats);
	NUTS_ASSERT(stats != NULL);
	st1 = nng_stat_find_socket(stats, s1);
	st2 = nng_stat_find_socket(stats, s2);
	NUTS_ASSERT(st1 != NULL);
	NUTS_ASSERT(st2 != NULL);
	NUTS_ASSERT(st1 != st2);
	item = nng_stat_find(st1, "name");
	NUTS_ASSERT(item != NULL);
	NUTS_ASSERT(nng_stat_string(item) != NULL);
	NUTS_MATCH(nng_stat_string(item), "1");
	item = nng_stat_find(st2, "name");
	NUTS_ASSERT(item != NULL);
	NUTS_ASSERT(nng_stat_string(item) != NULL);
	NUTS_MATCH(nng_stat_string(item), "second");
	item = nng_stat_find(st1, "tx_msgs");
	NUTS_ASSERT(item != NULL);
	NUTS_ASSERT(nng_stat_value(item) == 1);
	NUTS_ASSERT(nng_stat_unit(item) == NNG_UNIT_MESSAGES);
	item = nng_stat_find(st2, "rx_msgs");
	NUTS_ASSERT(item != NULL);
	NUTS_ASSERT(nng_stat_value(item) == 1);
	NUTS_ASSERT(nng_stat_unit(item) == NNG_UNIT_MESSAGES);
	NUTS_CLOSE(s1);
	NUTS_CLOSE(s2);
	nng_stats_free(stats);
#endif
}

void
test_stats_dump(void)
{
#ifdef NNG_ENABLE_STATS
	nng_socket s1;
	nng_socket s2;
	nng_stat  *st1;
	nng_stat  *st2;
	nng_stat  *stats;

	NUTS_OPEN(s1);
	NUTS_OPEN(s2);
	nng_socket_set_string(s2, NNG_OPT_SOCKNAME, "second");
	NUTS_MARRY(s1, s2);
	NUTS_SEND(s1, "ping");
	NUTS_RECV(s2, "ping");
	nng_stats_get(&stats);
	NUTS_ASSERT(stats != NULL);
	st1 = nng_stat_find_socket(stats, s1);
	st2 = nng_stat_find_socket(stats, s2);
	NUTS_ASSERT(st1 != NULL);
	NUTS_ASSERT(st2 != NULL);
	NUTS_ASSERT(st1 != st2);
	nng_stats_dump(stats);
	nng_stats_free(stats);
	NUTS_CLOSE(s1);
	NUTS_CLOSE(s2);
#endif
}

NUTS_TESTS = {
	{ "socket stats", test_stats_socket },
	{ "dump stats", test_stats_dump },
	{ NULL, NULL },
};
