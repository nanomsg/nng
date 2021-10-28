//
// Copyright 2021 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <nng/nng.h>
#include <nuts.h>

// Microsoft prefers CamelCase header names, but relies on case-insensitive
// file systems to make that work.  The rest of the world (min-gw64 included)
// uses case-sensitive names and lowercase.

#include <accctrl.h>
#include <aclapi.h>

SECURITY_DESCRIPTOR *
sdescAuthUsers(PSID sid, PACL *aclp)
{
	SECURITY_DESCRIPTOR *sdesc;
	EXPLICIT_ACCESS      xa;
	ACL                 *acl;

	sdesc = calloc(SECURITY_DESCRIPTOR_MIN_LENGTH, 1);
	NUTS_ASSERT(sdesc != NULL);

	InitializeSecurityDescriptor(sdesc, SECURITY_DESCRIPTOR_REVISION);

	xa.grfAccessPermissions = GENERIC_READ | GENERIC_WRITE;
	xa.grfAccessMode        = SET_ACCESS;
	xa.grfInheritance       = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
	xa.Trustee.TrusteeForm  = TRUSTEE_IS_SID;
	xa.Trustee.TrusteeType  = TRUSTEE_IS_WELL_KNOWN_GROUP;
	xa.Trustee.ptstrName    = (LPSTR) sid;

	SetEntriesInAcl(1, &xa, NULL, &acl);
	*aclp = acl;

	SetSecurityDescriptorDacl(sdesc, TRUE, acl, FALSE);
	return (sdesc);
}

void
test_ipc_security_descriptor(void)
{
	nng_stream_listener *l;
	char                 address[64];
	char                 pipe[64];
	SECURITY_DESCRIPTOR *sd;
	SID                  users;
	DWORD                size;
	PACL                 acl = NULL;
	PACL                 dacl;
	PSECURITY_DESCRIPTOR psd;
	PACE_HEADER          ace;
	PSID                 psid;
	PACCESS_ALLOWED_ACE  allowed;
	nng_aio             *aio;

	nuts_scratch_addr("ipc", sizeof(address), address);

	NUTS_PASS(nng_stream_listener_alloc(&l, address));
	size = sizeof(users);
	CreateWellKnownSid(WinAuthenticatedUserSid, NULL, &users, &size);
	sd = sdescAuthUsers(&users, &acl);

	NUTS_ASSERT(sd != NULL);
	NUTS_ASSERT(acl != NULL);
	NUTS_PASS(nng_aio_alloc(&aio, NULL, NULL));

	NUTS_PASS(nng_stream_listener_set_ptr(
	    l, NNG_OPT_IPC_SECURITY_DESCRIPTOR, sd));
	NUTS_PASS(nng_stream_listener_listen(l));
	nng_stream_listener_accept(l, aio);

	(void) snprintf(pipe, sizeof(pipe), "\\\\.\\pipe\\%s", address+strlen("ipc://"));
	HANDLE ph = CreateFileA(pipe, READ_CONTROL, 0, NULL, OPEN_EXISTING,
	    FILE_FLAG_OVERLAPPED, NULL);

	nng_aio_wait(aio);
	NUTS_PASS(nng_aio_result(aio));
	HANDLE pd = (HANDLE) nng_aio_get_output(aio, 0);

	NUTS_ASSERT(ph != INVALID_HANDLE_VALUE);
	NUTS_ASSERT(pd != INVALID_HANDLE_VALUE);

	NUTS_ASSERT(
	    GetSecurityInfo(ph, SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION,
	        NULL, NULL, &dacl, NULL, &psd) == ERROR_SUCCESS);

	NUTS_ASSERT(dacl->AceCount == 1);
	NUTS_ASSERT(GetAce(dacl, 0, (void **) &ace) == TRUE);
	allowed = (PACCESS_ALLOWED_ACE) ace;
	psid    = (PSID) &allowed->SidStart;
	NUTS_ASSERT(IsValidSid(psid));
	NUTS_ASSERT(EqualSid(psid, &users) == TRUE);

	CloseHandle(pd);
	CloseHandle(ph);
	free(sd);
	LocalFree(acl);
	LocalFree(psd);
	nng_stream_listener_close(l);
	nng_stream_listener_free(l);
}

void
test_ipc_security_descriptor_busy(void)
{
	// This test ensures that the descriptor can only be set before
	// the listener is started.
	nng_stream_listener *l;
	char                 address[64];
	SECURITY_DESCRIPTOR *sd;
	SID                  users;
	DWORD                size;
	PACL                 acl = NULL;

	nuts_scratch_addr("ipc", sizeof(address), address);

	NUTS_PASS(nng_stream_listener_alloc(&l, address));
	size = sizeof(users);
	CreateWellKnownSid(WinAuthenticatedUserSid, NULL, &users, &size);
	sd = sdescAuthUsers(&users, &acl);

	NUTS_ASSERT(sd != NULL);
	NUTS_ASSERT(acl != NULL);

	NUTS_PASS(nng_stream_listener_listen(l));

	NUTS_FAIL(nng_stream_listener_set_ptr(
	              l, NNG_OPT_IPC_SECURITY_DESCRIPTOR, sd),
	    NNG_EBUSY);

	free(sd);
	nng_stream_listener_close(l);
	nng_stream_listener_free(l);
}

void
test_ipc_security_descriptor_bogus(void)
{
	nng_stream_listener *l;
	char                 address[64];

	nuts_scratch_addr("ipc", sizeof(address), address);

	NUTS_PASS(nng_stream_listener_alloc(&l, address));

	NUTS_FAIL(nng_stream_listener_set_ptr(
	              l, NNG_OPT_IPC_SECURITY_DESCRIPTOR, NULL),
	    NNG_EINVAL);

	nng_stream_listener_close(l);
	nng_stream_listener_free(l);
}

void
test_ipc_security_descriptor_dialer(void)
{
	nng_stream_dialer   *d;
	char                 address[64];
	SECURITY_DESCRIPTOR *sdesc;

	nuts_scratch_addr("ipc", sizeof(address), address);
	NUTS_PASS(nng_stream_dialer_alloc(&d, address));

	sdesc = calloc(SECURITY_DESCRIPTOR_MIN_LENGTH, 1);
	NUTS_ASSERT(sdesc != NULL);
	InitializeSecurityDescriptor(sdesc, SECURITY_DESCRIPTOR_REVISION);
	NUTS_FAIL(nng_stream_dialer_set_ptr(
	              d, NNG_OPT_IPC_SECURITY_DESCRIPTOR, sdesc),
	    NNG_ENOTSUP);
	free(sdesc);
	nng_stream_dialer_free(d);
}

NUTS_TESTS = {
	{ "ipc security descriptor", test_ipc_security_descriptor },
	{ "ipc security descriptor busy", test_ipc_security_descriptor_busy },
	{ "ipc security descriptor bogus",
	    test_ipc_security_descriptor_bogus },
	{ "ipc security descriptor dialer",
	    test_ipc_security_descriptor_dialer },
	{ NULL, NULL },
};
