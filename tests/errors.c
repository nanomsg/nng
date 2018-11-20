//
// Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <errno.h>
#include <string.h>

#include <nng/nng.h>

#include "convey.h"

TestMain("Error messages work", {
	Convey("Known errors work", {
		So(strcmp(nng_strerror(NNG_ECLOSED), "Object closed") == 0);
		So(strcmp(nng_strerror(NNG_ETIMEDOUT), "Timed out") == 0);
	});
	Convey("We always get a valid error", {
		for (unsigned i = 1; i < 0x1000000; i = i * 2 + 100) {
			So(nng_strerror(i) != NULL);
		}
	});
	Convey("System errors work", {
		So(strcmp(nng_strerror(NNG_ESYSERR + ENOENT),
		       strerror(ENOENT)) == 0);
		So(strcmp(nng_strerror(NNG_ESYSERR + EINVAL),
		       strerror(EINVAL)) == 0);
	});
})
