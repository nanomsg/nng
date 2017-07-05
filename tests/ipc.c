//
// Copyright 2017 Garrett D'Amore <garrett@damore.org>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "convey.h"
#include "trantest.h"


// Inproc tests.

TestMain("IPC Transport", {
	trantest_test_all("ipc:///tmp/nng_ipc_test");

	nng_fini();
})
