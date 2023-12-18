//
// Copyright 2023 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
// Copyright 2019 Devolutions <info@devolutions.net>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "core/nng_impl.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdbool.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/un.h>

#if defined(NNG_HAVE_GETPEERUCRED)
#include <ucred.h>
#elif defined(NNG_HAVE_LOCALPEERCRED) || defined(NNG_HAVE_SOCKPEERCRED)
#include <sys/ucred.h>
#endif
#if defined(NNG_HAVE_GETPEEREID)
#include <sys/types.h>
#include <unistd.h>
#endif

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

#ifndef SOL_LOCAL
#define SOL_LOCAL 0
#endif


int
nni_posix_peerid(int fd, uint64_t *euid, uint64_t *egid, uint64_t *prid,
    uint64_t *znid)
{
#if defined(NNG_HAVE_GETPEEREID) && !defined(NNG_HAVE_LOCALPEERCRED)
	uid_t uid;
	gid_t gid;

	if (getpeereid(fd, &uid, &gid) != 0) {
		return (nni_plat_errno(errno));
	}
	*euid = uid;
	*egid = gid;
	*prid = (uint64_t) -1;
	*znid = (uint64_t) -1;
	return (0);
#elif defined(NNG_HAVE_GETPEERUCRED)
	ucred_t *ucp = NULL;
	if (getpeerucred(fd, &ucp) != 0) {
		return (nni_plat_errno(errno));
	}
	*euid = ucred_geteuid(ucp);
	*egid = ucred_getegid(ucp);
	*prid = ucred_getpid(ucp);
	*znid = ucred_getzoneid(ucp);
	ucred_free(ucp);
	return (0);
#elif defined(NNG_HAVE_SOCKPEERCRED)
	struct sockpeercred uc;
	socklen_t           len = sizeof(uc);
	if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &uc, &len) != 0) {
		return (nni_plat_errno(errno));
	}
	*euid = uc.uid;
	*egid = uc.gid;
	*prid = uc.pid;
	*znid = (uint64_t) -1;
	return (0);
#elif defined(NNG_HAVE_SOPEERCRED)
	struct ucred uc;
	socklen_t    len = sizeof(uc);
	if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &uc, &len) != 0) {
		return (nni_plat_errno(errno));
	}
	*euid = uc.uid;
	*egid = uc.gid;
	*prid = uc.pid;
	*znid = (uint64_t) -1;
	return (0);
#elif defined(NNG_HAVE_LOCALPEERCRED)
	struct xucred xu;
	socklen_t     len = sizeof(xu);
	if (getsockopt(fd, SOL_LOCAL, LOCAL_PEERCRED, &xu, &len) != 0) {
		return (nni_plat_errno(errno));
	}
	*euid = xu.cr_uid;
	*egid = xu.cr_gid;
	*prid = (uint64_t) -1;
	*znid = (uint64_t) -1;
#if defined(NNG_HAVE_LOCALPEERPID) // documented on macOS since 10.8
	{
		pid_t pid;
		if (getsockopt(fd, SOL_LOCAL, LOCAL_PEERPID, &pid, &len) ==
		    0) {
			*prid = (uint64_t) pid;
		}
	}
#endif // NNG_HAVE_LOCALPEERPID
	return (0);
#else
	if (fd < 0) {
		return (NNG_ECLOSED);
	}
	NNI_ARG_UNUSED(euid);
	NNI_ARG_UNUSED(egid);
	NNI_ARG_UNUSED(prid);
	NNI_ARG_UNUSED(znid);
	return (NNG_ENOTSUP);
#endif
}

