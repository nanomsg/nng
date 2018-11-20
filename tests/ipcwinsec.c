//
// Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <nng/nng.h>
#include <nng/protocol/reqrep0/rep.h>
#include <nng/protocol/reqrep0/req.h>
#include <nng/transport/ipc/ipc.h>

#include "convey.h"
#include "stubs.h"
#include "trantest.h"

#define ADDR "/tmp/ipc_winsec_test"

// Inproc tests.

#ifndef _WIN32
TestMain("IPC Security Descriptor", {
	atexit(nng_fini);
	Convey("Given a socket and an IPC listener", {
		nng_socket   s;
		nng_listener l;
		int          x;

		So(nng_rep0_open(&s) == 0);
		Reset({ nng_close(s); });
		So(nng_listener_create(&l, s, "ipc://" ADDR) == 0);
		Convey("We cannot set Windows SECURITY_DESCRIPTOR on POSIX", {
			So(nng_listener_setopt_ptr(l,
			       NNG_OPT_IPC_SECURITY_DESCRIPTOR,
			       &x) == NNG_ENOTSUP);
		});
	});
})
#else

#include <assert.h>

// Microsoft prefers CamelCase header names, but relies on case insensitive
// file systems to make that work.  The rest of the world (min-gw64 included)
// uses case sensitive names and lowercase.

#include <accctrl.h>

#include <sddl.h>

#include <aclapi.h>

SECURITY_DESCRIPTOR *
sdescAuthUsers(PSID sid, PACL *aclp)
{
	SECURITY_DESCRIPTOR *sdesc;
	EXPLICIT_ACCESS      xa;
	ACL *                acl;

	sdesc = calloc(SECURITY_DESCRIPTOR_MIN_LENGTH, 1);
	assert(sdesc != NULL);

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

TestMain("IPC Security Descriptor", {
	atexit(nng_fini);

	Convey("Given a socket and an IPC listener", {
		nng_socket   s;
		nng_listener l;

		So(nng_rep0_open(&s) == 0);
		Reset({ nng_close(s); });

		So(nng_listener_create(&l, s, "ipc://" ADDR) == 0);
		Convey("We can set security descriptor on Windows", {
			SECURITY_DESCRIPTOR *sdesc;
			SID                  users;
			DWORD                size;
			PACL                 acl = NULL;

			size = sizeof(users);
			CreateWellKnownSid(
			    WinAuthenticatedUserSid, NULL, &users, &size);

			sdesc = sdescAuthUsers(&users, &acl);
			assert(sdesc != NULL);
			assert(acl != NULL);
			Reset({
				free(sdesc);
				LocalFree(acl);
			});

			So(nng_listener_setopt_ptr(l,
			       NNG_OPT_IPC_SECURITY_DESCRIPTOR, sdesc) == 0);
			So(nng_listener_start(l, 0) == 0);

			Convey("And they are effective", {
				PACL                 dacl;
				PSECURITY_DESCRIPTOR sd;
				PACE_HEADER          ace;
				PSID                 asid;
				PACCESS_ALLOWED_ACE  allowed;

				HANDLE ph = CreateFileA("\\\\.\\\\pipe\\" ADDR,
				    READ_CONTROL, 0, NULL, OPEN_EXISTING,
				    FILE_FLAG_OVERLAPPED, NULL);

				So(ph != INVALID_HANDLE_VALUE);
				Reset({ CloseHandle(ph); });

				So(GetSecurityInfo(ph, SE_KERNEL_OBJECT,
				       DACL_SECURITY_INFORMATION, NULL, NULL,
				       &dacl, NULL, &sd) == ERROR_SUCCESS);
				Reset({ LocalFree(sd); });

				So(dacl->AceCount == 1);
				So(GetAce(dacl, 0, (void **) &ace) == TRUE);
				allowed = (PACCESS_ALLOWED_ACE) ace;
				asid    = (PSID) &allowed->SidStart;
				So(IsValidSid(asid));
				So(EqualSid(asid, &users) == TRUE);
			});
		});

		Convey("We cannot set security descriptor after started", {
			SECURITY_DESCRIPTOR *sdesc;
			SID                  users;
			DWORD                size;
			PACL                 acl = NULL;

			size = sizeof(users);
			CreateWellKnownSid(
			    WinAuthenticatedUserSid, NULL, &users, &size);

			sdesc = sdescAuthUsers(&users, &acl);
			assert(sdesc != NULL);
			assert(acl != NULL);
			Reset({
				free(sdesc);
				LocalFree(acl);
			});

			So(nng_listener_start(l, 0) == 0);
			So(nng_listener_setopt_ptr(l,
			       NNG_OPT_IPC_SECURITY_DESCRIPTOR,
			       sdesc) == NNG_EBUSY);
		});

		Convey("We cannot set bogus security", {
			So(nng_listener_setopt_ptr(l,
			       NNG_OPT_IPC_SECURITY_DESCRIPTOR,
			       NULL) == NNG_EINVAL);
		});
	});

	Convey("We cannot set security descriptor on an IPC dialer", {
		nng_socket           s;
		nng_dialer           d;
		SECURITY_DESCRIPTOR *sdesc;

		sdesc = calloc(SECURITY_DESCRIPTOR_MIN_LENGTH, 1);
		assert(sdesc != NULL);
		InitializeSecurityDescriptor(
		    sdesc, SECURITY_DESCRIPTOR_REVISION);

		So(nng_rep0_open(&s) == 0);
		Reset({
			nng_close(s);
			free(sdesc);
		});

		So(nng_dialer_create(&d, s, "ipc://" ADDR) == 0);
		So(nng_dialer_setopt_ptr(d, NNG_OPT_IPC_SECURITY_DESCRIPTOR,
		       sdesc) == NNG_ENOTSUP);
	});
})
#endif
