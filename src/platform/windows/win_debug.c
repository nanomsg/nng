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


#define NNI_ERR(x, y)    { x, y },

// Win32 has its own error codes, but these ones it shares with POSIX.
static struct {
	int	sys_err;
	int	nng_err;
}
nni_plat_errnos[] = {
	NNI_ERR(ENOENT, NNG_ENOENT)
	NNI_ERR(EINTR, NNG_EINTR)
	NNI_ERR(EINVAL, NNG_EINVAL)
	NNI_ERR(ENOMEM, NNG_ENOMEM)
	NNI_ERR(EACCES, NNG_EPERM)
	NNI_ERR(EAGAIN, NNG_EAGAIN)
	NNI_ERR(EBADF, NNG_ECLOSED)
	NNI_ERR(EBUSY, NNG_EBUSY)
	NNI_ERR(ENAMETOOLONG, NNG_EINVAL)
	NNI_ERR(EPERM, NNG_EPERM)
	NNI_ERR(EPIPE, NNG_ECLOSED)
	NNI_ERR(0, 0)                   // must be last
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


#endif // PLATFORM_WINDOWS
