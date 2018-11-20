//
// Copyright 2017 Garrett D'Amore <garrett@damore.org>
// Copyright 2017 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "convey.h"
#include "trantest.h"

#include "core/nng_impl.h"

// Inproc tests.

TestMain("Inproc Transport", {
	trantest_test_all("inproc://TEST_%u");
	nng_fini();
})
