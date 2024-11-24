//
// Copyright 2024 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "nng/nng.h"
#include <nuts.h>

#include <nng/supplemental/util/options.h>

static nng_optspec case1[] = {
	// clang-format off
	{ "flag", 'f', 1, false },
	{ "longflag", 0, 2, false },
	{ "value", 'v', 3, true },
	{ NULL, 'b', 4, false },
	{ NULL, 0, 0, false },
	// clang-format on
};

void
test_simple_options(void)
{
	int   opti = 1;
	char *av[6];
	int   ac = 5;
	int   v;
	char *a = NULL;

	av[0] = "program";
	av[1] = "-f";
	av[2] = "-v";
	av[3] = "123";
	av[4] = "456";
	NUTS_PASS(nng_opts_parse(ac, av, case1, &v, &a, &opti));
	NUTS_TRUE(v == 1);
	NUTS_NULL(a);
	NUTS_TRUE(opti == 2);
	NUTS_PASS(nng_opts_parse(ac, av, case1, &v, &a, &opti));
	NUTS_TRUE(opti == 4);
	NUTS_TRUE(v == 3);
	NUTS_MATCH(a, "123");
	NUTS_TRUE(nng_opts_parse(ac, av, case1, &v, &a, &opti) == -1);
	NUTS_TRUE(opti == 4);
	NUTS_MATCH(av[opti], "456");
}

void
test_long_options(void)
{
	int   opti = 1;
	char *av[6];
	int   ac = 5;
	int   v;
	char *a = NULL;

	av[0] = "program";
	av[1] = "--flag";
	av[2] = "--value";
	av[3] = "123";
	av[4] = "456";
	NUTS_PASS(nng_opts_parse(ac, av, case1, &v, &a, &opti));
	NUTS_TRUE(v == 1);
	NUTS_NULL(a);
	NUTS_TRUE(opti == 2);
	NUTS_PASS(nng_opts_parse(ac, av, case1, &v, &a, &opti));
	NUTS_TRUE(opti == 4);
	NUTS_TRUE(v == 3);
	NUTS_MATCH(a, "123");
	NUTS_TRUE(nng_opts_parse(ac, av, case1, &v, &a, &opti) == -1);
	NUTS_TRUE(opti == 4);
	NUTS_MATCH(av[opti], "456");
}

void
test_attached_short(void)
{
	int   opti = 1;
	char *av[3];
	int   ac = 3;
	int   v;
	char *a = NULL;

	av[0] = "program";
	av[1] = "-v123";
	av[2] = "456";
	NUTS_PASS(nng_opts_parse(ac, av, case1, &v, &a, &opti));
	NUTS_TRUE(opti == 2);
	NUTS_TRUE(v == 3);
	NUTS_MATCH(a, "123");
	NUTS_TRUE(nng_opts_parse(ac, av, case1, &v, &a, &opti) == -1);
	NUTS_TRUE(opti == 2);
	NUTS_MATCH(av[opti], "456");
}

void
test_attached_long_equals(void)
{
	int   opti = 1;
	char *av[3];
	int   ac = 3;
	int   v;
	char *a = NULL;

	av[0] = "program";
	av[1] = "--value=123";
	av[2] = "456";
	NUTS_PASS(nng_opts_parse(ac, av, case1, &v, &a, &opti));
	NUTS_TRUE(opti == 2);
	NUTS_TRUE(v == 3);
	NUTS_MATCH(a, "123");
	NUTS_TRUE(nng_opts_parse(ac, av, case1, &v, &a, &opti) == -1);
	NUTS_TRUE(opti == 2);
	NUTS_MATCH(av[opti], "456");
}

void
test_attached_long_colon(void)
{
	int   opti = 1;
	char *av[3];
	int   ac = 3;
	int   v;
	char *a = NULL;

	av[0] = "program";
	av[1] = "--value:123";
	av[2] = "456";
	NUTS_PASS(nng_opts_parse(ac, av, case1, &v, &a, &opti));
	NUTS_TRUE(opti == 2);
	NUTS_TRUE(v == 3);
	NUTS_MATCH(a, "123");
	NUTS_TRUE(nng_opts_parse(ac, av, case1, &v, &a, &opti) == -1);
	NUTS_TRUE(opti == 2);
	NUTS_MATCH(av[opti], "456");
}

void
test_negative_bad_short(void)
{
	int   opti = 1;
	char *av[3];
	int   ac = 3;
	int   v;
	char *a = NULL;

	av[0] = "program";
	av[1] = "-Z";
	av[2] = "456";
	NUTS_FAIL(nng_opts_parse(ac, av, case1, &v, &a, &opti), NNG_EINVAL);
	NUTS_TRUE(opti == 1);
}

void
test_negative_bad_long(void)
{
	int   opti = 1;
	char *av[3];
	int   ac = 3;
	int   v;
	char *a = NULL;

	av[0] = "program";
	av[1] = "--something";
	av[2] = "456";
	NUTS_FAIL(nng_opts_parse(ac, av, case1, &v, &a, &opti), NNG_EINVAL);
	NUTS_TRUE(opti == 1);
}

void
test_option_separator_flag(void)
{
	int   opti = 1;
	char *av[5];
	int   ac = 5;
	int   v;
	char *a = NULL;

	av[0] = "program";
	av[1] = "-f";
	av[2] = "-";
	av[3] = "-v";
	av[4] = "456";
	NUTS_PASS(nng_opts_parse(ac, av, case1, &v, &a, &opti));
	NUTS_TRUE(v == 1);
	NUTS_TRUE(opti == 2);
	NUTS_TRUE(nng_opts_parse(ac, av, case1, &v, &a, &opti) == -1);
	NUTS_TRUE(opti == 3);
}

void
test_no_options(void)
{
	int   opti = 1;
	char *av[1];
	int   ac = 1;
	int   v;
	char *a = NULL;

	av[0] = "program";
	NUTS_TRUE(nng_opts_parse(ac, av, case1, &v, &a, &opti) == -1);
}

void
test_arg_only(void)
{
	int   opti = 1;
	char *av[2];
	int   ac = 2;
	int   v;
	char *a = NULL;

	av[0] = "program";
	av[1] = "123";
	NUTS_TRUE(nng_opts_parse(ac, av, case1, &v, &a, &opti) == -1);
	NUTS_TRUE(opti == 1);
}

void
test_mixed_long_short(void)
{
	int   opti = 1;
	char *av[7];
	int   ac = 7;
	int   v;
	char *a = NULL;

	av[0] = "program";
	av[1] = "--value=123";
	av[2] = "-f";
	av[3] = "--longflag";
	av[4] = "-b";
	av[5] = "-vxyz";
	av[6] = "456";
	NUTS_PASS(nng_opts_parse(ac, av, case1, &v, &a, &opti));
	NUTS_TRUE(opti == 2);
	NUTS_TRUE(v == 3);
	NUTS_MATCH(a, "123");
	NUTS_PASS(nng_opts_parse(ac, av, case1, &v, &a, &opti));
	NUTS_TRUE(opti == 3);
	NUTS_TRUE(v == 1);
	NUTS_PASS(nng_opts_parse(ac, av, case1, &v, &a, &opti));
	NUTS_TRUE(opti == 4);
	NUTS_TRUE(v == 2);
	NUTS_PASS(nng_opts_parse(ac, av, case1, &v, &a, &opti));
	NUTS_TRUE(opti == 5);
	NUTS_TRUE(v == 4);
	NUTS_PASS(nng_opts_parse(ac, av, case1, &v, &a, &opti));
	NUTS_TRUE(opti == 6);
	NUTS_TRUE(v == 3);
	NUTS_MATCH(a, "xyz");
	NUTS_MATCH(av[opti], "456");
	NUTS_TRUE(nng_opts_parse(ac, av, case1, &v, &a, &opti) == -1);
	NUTS_TRUE(opti == 6);
}

void
test_ambiguous(void)
{
	int   opti = 1;
	char *av[2];
	int   ac = 2;
	int   v;
	char *a = NULL;

	nng_optspec spec[] = {
		{ "flag", 'f', 1, false },
		{ "fluid", 0, 2, false },
		{ NULL, 0, 0, false },
	};

	av[0] = "program";
	av[1] = "--fl";
	NUTS_FAIL(nng_opts_parse(ac, av, spec, &v, &a, &opti), NNG_EAMBIGUOUS);
}

void
test_missing_arg(void)
{
	int   opti = 1;
	char *av[2];
	int   ac = 2;
	int   v;
	char *a = NULL;

	nng_optspec spec[] = {
		{ "flag", 'f', 1, true },
		{ NULL, 0, 0, false },
	};

	av[0] = "program";
	av[1] = "--fl";
	NUTS_FAIL(nng_opts_parse(ac, av, spec, &v, &a, &opti), NNG_ENOARG);
	av[0] = "program";
	av[1] = "-f";
	opti  = 1;
	NUTS_FAIL(nng_opts_parse(ac, av, spec, &v, &a, &opti), NNG_ENOARG);
}

void
test_no_clustering(void)
{
	int   opti = 1;
	char *av[2];
	int   ac = 2;
	int   v;
	char *a = NULL;

	nng_optspec spec[] = {
		{ "flag", 'f', 1, false },
		{ "verbose", 'v', 2, false },
		{ NULL, 0, 0, false },
	};

	av[0] = "program";
	av[1] = "-fv";
	NUTS_FAIL(nng_opts_parse(ac, av, spec, &v, &a, &opti), NNG_EINVAL);
}

NUTS_TESTS = {
	{ "simple options", test_simple_options },
	{ "long options", test_long_options },
	{ "separator flag", test_option_separator_flag },
	{ "no options", test_no_options },
	{ "attached short", test_attached_long_equals },
	{ "attached long equals", test_attached_long_equals },
	{ "attached long colon", test_attached_long_colon },
	{ "bad short", test_negative_bad_short },
	{ "bad long", test_negative_bad_long },
	{ "arg only", test_arg_only },
	{ "options mixed long short", test_mixed_long_short },
	{ "ambiguous options", test_ambiguous },
	{ "missing argument", test_missing_arg },
	{ "no clustering", test_no_clustering },
	{ NULL, NULL },
};
