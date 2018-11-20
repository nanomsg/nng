//
// Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <string.h>

#include <nng/nng.h>
#include <nng/supplemental/util/options.h>

#include "convey.h"

static nng_optspec case1[] = {
	// clang-format off
	{ "flag", 'f', 1, false },
	{ "longflag", 0, 2, false },
	{ "value", 'v', 3, true },
	{ NULL, 'b', 4, false },
	{ NULL, 0, 0, false },
	// clang-format on
};

TestMain("Option Parsing", {
	Convey("Simple works", {
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
		So(nng_opts_parse(ac, av, case1, &v, &a, &opti) == 0);
		So(v == 1);
		So(a == NULL);
		So(opti == 2);
		So(nng_opts_parse(ac, av, case1, &v, &a, &opti) == 0);
		So(opti == 4);
		So(v == 3);
		So(strcmp(a, "123") == 0);
		So(nng_opts_parse(ac, av, case1, &v, &a, &opti) == -1);
		So(opti == 4);
		So(strcmp(av[opti], "456") == 0);
	});

	Convey("Long works", {
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
		So(nng_opts_parse(ac, av, case1, &v, &a, &opti) == 0);
		So(v == 1);
		So(a == NULL);
		So(opti == 2);
		So(nng_opts_parse(ac, av, case1, &v, &a, &opti) == 0);
		So(opti == 4);
		So(v == 3);
		So(strcmp(a, "123") == 0);
		So(nng_opts_parse(ac, av, case1, &v, &a, &opti) == -1);
		So(opti == 4);
		So(strcmp(av[opti], "456") == 0);
	});

	Convey("Attached short works", {
		int   opti = 1;
		char *av[3];
		int   ac = 3;
		int   v;
		char *a = NULL;

		av[0] = "program";
		av[1] = "-v123";
		av[2] = "456";
		So(nng_opts_parse(ac, av, case1, &v, &a, &opti) == 0);
		So(opti == 2);
		So(v == 3);
		So(strcmp(a, "123") == 0);
		So(nng_opts_parse(ac, av, case1, &v, &a, &opti) == -1);
		So(opti == 2);
		So(strcmp(av[opti], "456") == 0);
	});

	Convey("Attached long (=) works", {
		int   opti = 1;
		char *av[3];
		int   ac = 3;
		int   v;
		char *a = NULL;

		av[0] = "program";
		av[1] = "--value=123";
		av[2] = "456";
		So(nng_opts_parse(ac, av, case1, &v, &a, &opti) == 0);
		So(opti == 2);
		So(v == 3);
		So(strcmp(a, "123") == 0);
		So(nng_opts_parse(ac, av, case1, &v, &a, &opti) == -1);
		So(opti == 2);
		So(strcmp(av[opti], "456") == 0);
	});

	Convey("Attached long (:) works", {
		int   opti = 1;
		char *av[3];
		int   ac = 3;
		int   v;
		char *a = NULL;

		av[0] = "program";
		av[1] = "--value:123";
		av[2] = "456";
		So(nng_opts_parse(ac, av, case1, &v, &a, &opti) == 0);
		So(opti == 2);
		So(v == 3);
		So(strcmp(a, "123") == 0);
		So(nng_opts_parse(ac, av, case1, &v, &a, &opti) == -1);
		So(opti == 2);
		So(strcmp(av[opti], "456") == 0);
	});

	Convey("Negative bad short works", {
		int   opti = 1;
		char *av[3];
		int   ac = 3;
		int   v;
		char *a = NULL;

		av[0] = "program";
		av[1] = "-Z";
		av[2] = "456";
		So(nng_opts_parse(ac, av, case1, &v, &a, &opti) == NNG_EINVAL);
		So(opti == 1);
	});

	Convey("Negative bad long works", {
		int   opti = 1;
		char *av[3];
		int   ac = 3;
		int   v;
		char *a = NULL;

		av[0] = "program";
		av[1] = "--something";
		av[2] = "456";
		So(nng_opts_parse(ac, av, case1, &v, &a, &opti) == NNG_EINVAL);
		So(opti == 1);
	});

	Convey("Separator flag works", {
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
		So(nng_opts_parse(ac, av, case1, &v, &a, &opti) == 0);
		So(v == 1);
		So(opti == 2);
		So(nng_opts_parse(ac, av, case1, &v, &a, &opti) == -1);
		So(opti == 3);
	});

	Convey("No options works", {
		int   opti = 1;
		char *av[1];
		int   ac = 1;
		int   v;
		char *a = NULL;

		av[0] = "program";
		So(nng_opts_parse(ac, av, case1, &v, &a, &opti) == -1);
	});

	Convey("No options (but arguments) works", {
		int   opti = 1;
		char *av[2];
		int   ac = 2;
		int   v;
		char *a = NULL;

		av[0] = "program";
		av[1] = "123";
		So(nng_opts_parse(ac, av, case1, &v, &a, &opti) == -1);
		So(opti == 1);
	});
	Convey("Mixed long and short works", {
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
		So(nng_opts_parse(ac, av, case1, &v, &a, &opti) == 0);
		So(opti == 2);
		So(v == 3);
		So(strcmp(a, "123") == 0);
		So(nng_opts_parse(ac, av, case1, &v, &a, &opti) == 0);
		So(opti == 3);
		So(v == 1);
		So(nng_opts_parse(ac, av, case1, &v, &a, &opti) == 0);
		So(opti == 4);
		So(v == 2);
		So(nng_opts_parse(ac, av, case1, &v, &a, &opti) == 0);
		So(opti == 5);
		So(v == 4);
		So(nng_opts_parse(ac, av, case1, &v, &a, &opti) == 0);
		So(opti == 6);
		So(v == 3);
		So(strcmp(a, "xyz") == 0);
		So(strcmp(av[opti], "456") == 0);
		So(nng_opts_parse(ac, av, case1, &v, &a, &opti) == -1);
		So(opti == 6);
	});
})
