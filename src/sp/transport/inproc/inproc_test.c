//
// Copyright 2024 Staysail Systems, Inc. <info@staysail.tech>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <nuts.h>

NUTS_DECLARE_TRAN_TESTS(inproc)

NUTS_TESTS = {
	NUTS_INSERT_TRAN_TESTS(inproc),
	{ NULL, NULL },
};
