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
	NUTS_TRUE(nni_sp_tran_find("ofi") != NULL);
}

void
test_ofi_listen(void)
{
	nng_socket s;
	char       addr[64];

	nuts_scratch_addr("ofi", sizeof(addr), addr);
	NUTS_OPEN(s);
	NUTS_PASS(nng_listen(s, addr, NULL, 0));
	NUTS_CLOSE(s);
}

void
test_ofi_connect(void)
{
	nng_socket s1;
	nng_socket s2;
	char       addr[64];

	nuts_scratch_addr("ofi", sizeof(addr), addr);
	NUTS_OPEN(s1);
	NUTS_OPEN(s2);
	NUTS_PASS(nng_listen(s1, addr, NULL, 0));
	NUTS_PASS(nng_dial(s2, addr, NULL, 0));
	nng_msleep(100);
	NUTS_CLOSE(s1);
	NUTS_CLOSE(s2);
}

TEST_LIST = {
	{ "ofi-scheme-recognized", test_ofi_scheme_recognized },
	{ "ofi-listen", test_ofi_listen },
	{ "ofi-connect", test_ofi_connect },
	{ NULL, NULL },
};
