//
// Copyright 2016 Garrett D'Amore <garrett@damore.org>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "convey.h"
#include "trantest.h"


// Inproc tests.

TestMain("Inproc Transport", {
	nni_init();
	trantest_test_all("inproc://TEST");
	nni_fini();
})
