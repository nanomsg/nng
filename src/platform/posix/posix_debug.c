//
// Copyright 2017 Garrett D'Amore <garrett@damore.org>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "core/nng_impl.h"

#ifdef PLATFORM_POSIX_DEBUG

#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

void
nni_plat_abort(void)
{
	abort();
}


void
nni_plat_println(const char *message)
{
	(void) fprintf(stderr, "%s\n", message);
}


const char *
nni_plat_strerror(int errnum)
{
	if (errnum > NNG_ESYSERR) {
		errnum -= NNG_ESYSERR;
	}
	return (strerror(errnum));
}


#define NNI_ERR(x, y)    { x, y },

// There are of course other errors than these, but these are the ones
// that we might reasonably expect and want to handle "cleanly".  Most of
// the others should be handled by the system error code.  Note that EFAULT
// is very special, because if the error code is *that*, then we should panic
// because an invalid system call has been made.  (That would be a sign
// of a serious software bug, in other words.)  POSIX says that all these
// error codes should exist, and be distinct positive numbers. (EWOULDBLOCK
// and EAGAIN are permitted to have the same value.)
static struct {
	int	posix_err;
	int	nng_err;
}
nni_plat_errnos[] = {
	NNI_ERR(EINTR,		 NNG_EINTR)
	NNI_ERR(EINVAL,		 NNG_EINVAL)
	NNI_ERR(ENOMEM,		 NNG_ENOMEM)
	NNI_ERR(EACCES,		 NNG_EPERM)
	NNI_ERR(EADDRINUSE,	 NNG_EADDRINUSE)
	NNI_ERR(EADDRNOTAVAIL,	 NNG_EADDRINVAL)
	NNI_ERR(EAFNOSUPPORT,	 NNG_ENOTSUP)
	NNI_ERR(EAGAIN,		 NNG_EAGAIN)
	NNI_ERR(EBADF,		 NNG_ECLOSED)
	NNI_ERR(EBUSY,		 NNG_EBUSY)
	NNI_ERR(ECONNABORTED,	 NNG_ECLOSED)
	NNI_ERR(ECONNREFUSED,	 NNG_ECONNREFUSED)
	NNI_ERR(ECONNRESET,	 NNG_ECLOSED)
	NNI_ERR(EHOSTUNREACH,	 NNG_EUNREACHABLE)
	NNI_ERR(ENETUNREACH,	 NNG_EUNREACHABLE)
	NNI_ERR(ENAMETOOLONG,	 NNG_EINVAL)
	NNI_ERR(ENOENT,		 NNG_ENOENT)
	NNI_ERR(ENOBUFS,	 NNG_ENOMEM)
	NNI_ERR(ENOPROTOOPT,	 NNG_ENOTSUP)
	NNI_ERR(ENOSYS,		 NNG_ENOTSUP)
	NNI_ERR(ENOTSUP,	 NNG_ENOTSUP)
	NNI_ERR(EPERM,		 NNG_EPERM)
	NNI_ERR(EPIPE,		 NNG_ECLOSED)
	NNI_ERR(EPROTO,		 NNG_EPROTO)
	NNI_ERR(EPROTONOSUPPORT, NNG_ENOTSUP)
	NNI_ERR(ETIME,		 NNG_ETIMEDOUT)
	NNI_ERR(ETIMEDOUT,	 NNG_ETIMEDOUT)
	NNI_ERR(EWOULDBLOCK,	 NNG_EAGAIN)
	NNI_ERR(0,		 0)     // must be last
};

int
nni_plat_errno(int errnum)
{
	int i;

	if (errnum == 0) {
		return (0);
	}
	if (errnum == EFAULT) {
		nni_panic("System EFAULT encountered!");
	}
	for (i = 0; nni_plat_errnos[i].nng_err != 0; i++) {
		if (errnum == nni_plat_errnos[i].posix_err) {
			return (nni_plat_errnos[i].nng_err);
		}
	}
	// Other system errno.
	return (NNG_ESYSERR + errnum);
}


#endif // PLATFORM_POSIX_DEBUG
