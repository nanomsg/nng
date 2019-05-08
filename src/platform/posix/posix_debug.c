//
// Copyright 2019 Staysail Systems, Inc. <info@staysail.tech>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "core/nng_impl.h"

#ifdef NNG_PLATFORM_POSIX

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void
nni_plat_abort(void)
{
	abort();
}

void
nni_plat_printf(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	(void) vprintf(fmt, ap);
	va_end(ap);
}

void
nni_plat_println(const char *message)
{
	fputs(message, stderr);
	fputc('\n', stderr);
}

const char *
nni_plat_strerror(int errnum)
{
	if (errnum > NNG_ESYSERR) {
		errnum -= NNG_ESYSERR;
	}
	return (strerror(errnum));
}

// There are of course other errors than these, but these are the ones
// that we might reasonably expect and want to handle "cleanly".  Most of
// the others should be handled by the system error code.  Note that EFAULT
// is very special, because if the error code is *that*, then we should panic
// because an invalid system call has been made.  (That would be a sign
// of a serious software bug, in other words.)  POSIX says that all these
// error codes should exist, and be distinct positive numbers. (EWOULDBLOCK
// and EAGAIN are permitted to have the same value.)
static struct {
	int posix_err;
	int nng_err;
} nni_plat_errnos[] = {
	// clang-format off
	{ EINTR,	   NNG_EINTR	    },
	{ EINVAL,	   NNG_EINVAL	    },
	{ ENOMEM,	   NNG_ENOMEM	    },
	{ EACCES,	   NNG_EPERM	    },
	{ EADDRINUSE,	   NNG_EADDRINUSE   },
	{ EADDRNOTAVAIL,   NNG_EADDRINVAL   },
	{ EAFNOSUPPORT,	   NNG_ENOTSUP	    },
	{ EAGAIN,	   NNG_EAGAIN	    },
	{ EBADF,	   NNG_ECLOSED	    },
	{ EBUSY,	   NNG_EBUSY	    },
	{ ECONNABORTED,	   NNG_ECONNABORTED },
	{ ECONNREFUSED,	   NNG_ECONNREFUSED },
	{ ECONNRESET,	   NNG_ECONNRESET   },
	{ EHOSTUNREACH,	   NNG_EUNREACHABLE },
	{ ENETUNREACH,	   NNG_EUNREACHABLE },
	{ ENAMETOOLONG,	   NNG_EINVAL	    },
	{ ENOENT,	   NNG_ENOENT	    },
	{ ENOBUFS,	   NNG_ENOMEM	    },
	{ ENOPROTOOPT,	   NNG_ENOTSUP	    },
	{ ENOSYS,	   NNG_ENOTSUP	    },
	{ ENOTSUP,	   NNG_ENOTSUP	    },
	{ EPERM,	   NNG_EPERM	    },
	{ EPIPE,	   NNG_ECLOSED	    },
	{ EPROTO,	   NNG_EPROTO	    },
	{ EPROTONOSUPPORT, NNG_ENOTSUP	    },
#ifdef  ETIME   // Found in STREAMs, not present on all systems.
	{ ETIME,	   NNG_ETIMEDOUT    },
#endif
	{ ETIMEDOUT,	   NNG_ETIMEDOUT    },
	{ EWOULDBLOCK,	   NNG_EAGAIN	    },
	{ ENOSPC,	   NNG_ENOSPC	    },
	{ EFBIG,	   NNG_ENOSPC	    },
	{ EDQUOT,	   NNG_ENOSPC	    },
	{ ENFILE,	   NNG_ENOFILES	    },
	{ EMFILE,	   NNG_ENOFILES	    },
	{ EEXIST,	   NNG_EEXIST	    },
	// must be last
	{		0,		  0 },
	// clang-format on
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

#endif // NNG_PLATFORM_POSIX
