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

#include "convey.h"
#include "supplemental/base64/base64.h"

typedef struct testcase {
	char *decoded;
	char *encoded;
} testcase;

static struct testcase cases[] = {
	// clang-format off
	{ "", "" },
	{ "f", "Zg==" },
	{ "fo", "Zm8=" },
	{ "foo", "Zm9v" },
	{ "foob", "Zm9vYg==" },
	{ "fooba", "Zm9vYmE=" },
	{ "foobar", "Zm9vYmFy" },
	{ NULL, NULL }
	// clang-format on
};

TestMain("Base64 Verification", {

	Convey("Encode Works", {
		int   rv;
		char  buf[1024];
		int   i;
		void *dec;

		for (i = 0; (dec = cases[i].decoded) != NULL; i++) {
			rv = nni_base64_encode(dec, strlen(dec), buf, 1024);
			So(rv >= 0);
			So(rv == (int) strlen(cases[i].encoded));
			buf[rv] = 0;
			So(strcmp(buf, cases[i].encoded) == 0);
		}
	});

	Convey("Decode Works", {
		int   rv;
		char  buf[1024];
		int   i;
		void *enc;

		for (i = 0; (enc = cases[i].encoded) != NULL; i++) {
			rv = nni_base64_decode(
			    enc, strlen(enc), (void *) buf, 1024);
			So(rv >= 0);
			So(rv == (int) strlen(cases[i].decoded));
			buf[rv] = 0;
			So(strcmp(buf, cases[i].decoded) == 0);
		}
	});

	Convey("Overflow Works", {
		char tmp[1024];
		for (int i = 1; cases[i].decoded != NULL; i++) {
			void *enc = cases[i].encoded;
			void *dec = cases[i].decoded;
			void *buf = tmp;

			So(nni_base64_encode(
			       dec, strlen(dec), buf, strlen(enc) - 1) == -1);
			So(nni_base64_encode(dec, strlen(dec), buf, 0) == -1);

			So(nni_base64_decode(
			       enc, strlen(enc), buf, strlen(dec) - 1) == -1);
			So(nni_base64_encode(enc, strlen(enc), buf, 0) == -1);
		}
	})
})
