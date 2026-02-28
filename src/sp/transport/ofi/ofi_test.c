// Copyright 2026 - OFI/libfabric transport tests for NNG (EXPERIMENTAL)
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).

#include "../../../testing/nuts.h"
#include "../../../sp/transport.h"

void
test_ofi_scheme_recognized(void)
{
	// nni_sp_tran_find is internal API exposed via nng_testing.
	// A non-NULL result means the "ofi" scheme was registered.
	NUTS_TRUE(nni_sp_tran_find("ofi") != NULL);
}

TEST_LIST = {
	{ "ofi-scheme-recognized", test_ofi_scheme_recognized },
	{ NULL, NULL },
};
