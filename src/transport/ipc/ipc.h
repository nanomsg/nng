//
// Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#ifndef NNG_TRANSPORT_IPC_IPC_H
#define NNG_TRANSPORT_IPC_IPC_H

// ipc transport.  This is used for inter-process communication on
// the same host computer.

NNG_DECL int nng_ipc_register(void);

// Security Descriptor.  This option may only be set on listeners
// on the Windows platform, where the object is a pointer to a
// a Windows SECURITY_DESCRIPTOR.
#define NNG_OPT_IPC_SECURITY_DESCRIPTOR "ipc:security-descriptor"

// Permissions bits.  This option is only valid for listeners on
// POSIX platforms and others that honor UNIX style permission bits.
// Note that some platforms may not honor the permissions here, although
// at least Linux and macOS seem to do so.  Check before you rely on
// this for security.
#define NNG_OPT_IPC_PERMISSIONS "ipc:permissions"

#endif // NNG_TRANSPORT_IPC_IPC_H
