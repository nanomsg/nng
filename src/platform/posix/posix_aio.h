//
// Copyright 2017 Garrett D'Amore <garrett@damore.org>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#ifndef PLATFORM_POSIX_AIO_H
#define PLATFORM_POSIX_AIO_H

// This file defines structures we will use for emulating asynchronous I/O
// on POSIX.  POSIX lacks the support for callback based asynchronous I/O
// that we have on Windows, although it has a non-widely support aio layer
// that is not very performant on many systems.   So we emulate this using
// one of several possible different backends.

#include "core/nng_impl.h"

typedef struct nni_posix_aioq		nni_posix_aioq;
typedef struct nni_posix_aiof		nni_posix_aiof;
typedef struct nni_posix_aio_pipe	nni_posix_aio_pipe;
typedef struct nni_posix_aio_ep		nni_posix_aio_ep;

// Head structure representing file operations for read/write.  We process
// the list of aios serially, and each file has its own thread for now.
struct nni_posix_aioq {
	nni_list	aq_aios;
	int		aq_fd;
	nni_mtx		aq_lk;
	nni_cv		aq_cv;
#ifdef NNG_USE_POSIX_AIOTHR
	nni_thr		aq_thr;
#endif
};

struct nni_posix_aio_pipe {
	int		ap_fd;
	nni_posix_aioq	ap_readq;
	nni_posix_aioq	ap_writeq;
};

struct nni_posix_aio_ep {
	int		ap_fd;
	nni_posix_aioq	ap_q;
};

extern int nni_posix_aio_pipe_init(nni_posix_aio_pipe *, int);
extern void nni_posix_aio_pipe_fini(nni_posix_aio_pipe *);

// extern int nni_posix_aio_ep_init(nni_posix_aio_ep *, int);
// extern void nni_posix_aio_ep_fini(nni_posix_aio_ep *);
extern int nni_posix_aio_read(nni_posix_aio_pipe *, nni_aio *);
extern int nni_posix_aio_write(nni_posix_aio_pipe *, nni_aio *);

// extern int nni_posix_aio_connect();
// extern int nni_posix_aio_accept();

#endif // PLATFORM_POSIX_AIO_H
