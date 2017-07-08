//
// Copyright 2017 Garrett D'Amore <garrett@damore.org>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "core/nng_impl.h"

#ifdef PLATFORM_WINDOWS

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


// Win32 has its own error codes, but these ones it shares with POSIX.
static struct {
	int	sys_err;
	int	nng_err;
}
nni_plat_errnos[] = {
	{ ENOENT,	NNG_ENOENT  },
	{ EINTR,	NNG_EINTR   },
	{ EINVAL,	NNG_EINVAL  },
	{ ENOMEM,	NNG_ENOMEM  },
	{ EACCES,	NNG_EPERM   },
	{ EAGAIN,	NNG_EAGAIN  },
	{ EBADF,	NNG_ECLOSED },
	{ EBUSY,	NNG_EBUSY   },
	{ ENAMETOOLONG, NNG_EINVAL  },
	{ EPERM,	NNG_EPERM   },
	{ EPIPE,	NNG_ECLOSED },
	{	     0,		  0 } // must be last
};

int
nni_plat_errno(int errnum)
{
	int i;

	if (errnum == 0) {
		return (0);
	}
	for (i = 0; nni_plat_errnos[i].nng_err != 0; i++) {
		if (errnum == nni_plat_errnos[i].sys_err) {
			return (nni_plat_errnos[i].nng_err);
		}
	}
	// Other system errno.
	return (NNG_ESYSERR + errnum);
}

// Windows has infinite numbers of error codes it seems.  We only bother
// with the ones that are relevant to us (we think).  Note that there is
// no overlap between errnos and GetLastError values.
static struct {
	int	win_err;
	int	nng_err;
}
nni_win_errnos[] = {
	{ ERROR_FILE_NOT_FOUND,	    NNG_ENOENT	     },
	{ ERROR_ACCESS_DENIED,	    NNG_EPERM	     },
	{ ERROR_INVALID_HANDLE,	    NNG_ECLOSED	     },
	{ ERROR_NOT_ENOUGH_MEMORY,  NNG_ENOMEM	     },
	{ ERROR_INVALID_ACCESS,	    NNG_EPERM	     },
	{ ERROR_INVALID_DATA,	    NNG_EINVAL	     },
	{ ERROR_OUTOFMEMORY,	    NNG_ENOMEM	     },
	{ ERROR_HANDLE_EOF,	    NNG_ECLOSED	     },
	{ ERROR_NOT_SUPPORTED,	    NNG_ENOTSUP	     },
	{ ERROR_OUT_OF_STRUCTURES,  NNG_ENOMEM	     },
	{ ERROR_INVALID_PARAMETER,  NNG_EINVAL	     },
	{ ERROR_CONNECTION_REFUSED, NNG_ECONNREFUSED },
	{ ERROR_BROKEN_PIPE,	    NNG_ECLOSED	     },
	{ ERROR_BAD_PIPE,	    NNG_ECLOSED	     },
	{ ERROR_NO_DATA,	    NNG_ECLOSED	     },
	{ ERROR_PIPE_NOT_CONNECTED, NNG_ECLOSED	     },
	{ ERROR_OPERATION_ABORTED,  NNG_ECLOSED	     },
	{ WAIT_TIMEOUT,		    NNG_ETIMEDOUT    },
	// Must be Last!!
	{			 0,		   0 },
};

// This converts a Windows API error (from GetLastError()) to an
// nng standard error code.
int
nni_win_error(int errnum)
{
	int i;

	if (errnum == 0) {
		return (0);
	}
	for (i = 0; nni_win_errnos[i].nng_err != 0; i++) {
		if (errnum == nni_win_errnos[i].win_err) {
			return (nni_win_errnos[i].nng_err);
		}
	}
	// Other system errno.
	return (NNG_ESYSERR + errnum);
}


#else

// Suppress empty symbols warnings in ranlib.
int nni_win_debug_not_used = 0;

#endif // PLATFORM_WINDOWS
