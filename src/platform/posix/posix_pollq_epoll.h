//
// Copyright 2024 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#ifndef PLATFORM_POSIX_POLLQ_EPOLL_H
#define PLATFORM_POSIX_POLLQ_EPOLL_H

#include <poll.h>

#include "../../core/list.h"
#include "../../core/platform.h"

typedef struct nni_posix_pfd nni_posix_pfd;
typedef void (*nni_posix_pfd_cb)(void *, unsigned);

// nni_posix_pfd is the handle used by the poller.  It's internals are private
// to the poller.
struct nni_posix_pfd {
	nni_list_node           node;
	struct nni_posix_pollq *pq;
	int                     fd;
	nni_posix_pfd_cb        cb;
	void                   *arg;
	nni_atomic_int          events;
	bool                    added;
	nni_atomic_flag         stopped;
	nni_atomic_flag         closing;
};

#define NNI_POLL_IN ((unsigned) POLLIN)
#define NNI_POLL_OUT ((unsigned) POLLOUT)
#define NNI_POLL_HUP ((unsigned) POLLHUP)
#define NNI_POLL_ERR ((unsigned) POLLERR)
#define NNI_POLL_INVAL ((unsigned) POLLNVAL)

#endif // PLATFORM_POSIX_POLLQ_EPOLL_H
