// Copyright 2026 - OFI/libfabric transport tests for NNG (EXPERIMENTAL)
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).

#include "../../../testing/nuts.h"

// Placeholder - real tests are added in subsequent tasks.
void
test_ofi_placeholder(void)
{
	// Nothing to test yet; this just ensures the test binary links.
	NUTS_PASS(0);
}

TEST_LIST = {
	{ "ofi-placeholder", test_ofi_placeholder },
	{ NULL, NULL },
};
