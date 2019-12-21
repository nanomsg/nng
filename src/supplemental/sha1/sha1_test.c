//
// Copyright 2019 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <stdint.h>
#include <string.h>

#include <nng/nng.h>

#include <acutest.h>

#include "sha1.h"


// The following test vectors are from RFC 3174.
#define TEST1 "abc"
#define TEST2a "abcdbcdecdefdefgefghfghighijhi"
#define TEST2b "jkijkljklmklmnlmnomnopnopq"
#define TEST2 TEST2a TEST2b
#define TEST3 "a"
#define TEST4a "01234567012345670123456701234567"
#define TEST4b "01234567012345670123456701234567"
/* an exact multiple of 512 bits */
#define TEST4 TEST4a TEST4b

char *testarray[4]   = { TEST1, TEST2, TEST3, TEST4 };
int   repeatcount[4] = { 1, 1, 1000000, 10 };
char *resultarray[4] = {
	"A9 99 3E 36 47 06 81 6A BA 3E 25 71 78 50 C2 6C 9C D0 D8 9D",
	"84 98 3E 44 1C 3B D2 6E BA AE 4A A1 F9 51 29 E5 E5 46 70 F1",
	"34 AA 97 3C D4 C4 DA A4 F6 1E EB 2B DB AD 27 31 65 34 01 6F",
	"DE A3 56 A2 CD DD 90 C7 A7 EC ED C5 EB B5 63 93 4F 46 04 52"
};

void
test_sha1(void)
{

	for (int i = 0; i < 4; i++) {
		nni_sha1_ctx ctx;
		size_t       slen = strlen(testarray[i]);
		uint8_t      digest[20];
		char         strout[20 * 3 + 1];
		char         name[8];

		snprintf(name, sizeof(name), "%d", i);
		TEST_CASE(name);

		memset(digest, 0, sizeof(digest));
		nni_sha1_init(&ctx);
		for (int j = 0; j < repeatcount[i]; j++) {
			nni_sha1_update(&ctx, (uint8_t *) testarray[i], slen);
		}
		nni_sha1_final(&ctx, digest);
		for (int j = 0; j < 20; j++) {
			snprintf(strout + j * 3, 4, "%02X ", digest[j]);
		}
		strout[20 * 3 - 1] = '\0';
		TEST_CHECK(strcmp(strout, resultarray[i]) == 0);
	}
}

TEST_LIST = {
	{ "sha1", test_sha1 },
	{ NULL, NULL },
};
