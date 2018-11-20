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

// Peer UID.  This is only available on POSIX style systems.
#define NNG_OPT_IPC_PEER_UID "ipc:peer-uid"

// Peer GID (primary group).  This is only available on POSIX style systems.
#define NNG_OPT_IPC_PEER_GID "ipc:peer-gid"

// Peer process ID.  Available on Windows, Linux, and SunOS.
// In theory we could obtain this with the first message sent,
// but we have elected not to do this for now. (Nice RFE for a FreeBSD
// guru though.)
#define NNG_OPT_IPC_PEER_PID "ipc:peer-pid"

// Peer Zone ID.  Only on SunOS systems.  (Linux containers have no
// definable kernel identity; they are a user-land fabrication made up
// from various pieces of different namespaces. FreeBSD does have
// something called JailIDs, but it isn't obvious how to determine this,
// or even if processes can use IPC across jail boundaries.)
#define NNG_OPT_IPC_PEER_ZONEID "ipc:peer-zoneid"

#endif // NNG_TRANSPORT_IPC_IPC_H
