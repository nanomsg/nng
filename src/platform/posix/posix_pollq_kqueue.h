//
// Copyright 2024 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#ifndef PLATFORM_POSIX_POLLQ_KQUEUE_H
#define PLATFORM_POSIX_POLLQ_KQUEUE_H

// nni_posix_pfd is the handle used by the poller.  It's internals are private
// to the poller.
struct nni_posix_pfd {
	nni_list_node           node; // linkage into the reap list
	struct nni_posix_pollq *pq;   // associated pollq
	int                     fd;   // file descriptor to poll
	void                   *arg;  // user data
	nni_posix_pfd_cb        cb;   // user callback on event
	bool                    closed;
	unsigned                events;
	nni_cv                  cv; // signaled when poller has unregistered
	nni_mtx                 mtx;
};

#define NNI_POLL_IN (0x0001)
#define NNI_POLL_OUT (0x0010)
#define NNI_POLL_HUP (0x0004)
#define NNI_POLL_ERR (0x0008)
#define NNI_POLL_INVAL (0x0020)

#endif // PLATFORM_POSIX_POLLQ_KQUEUE_H
