//
// Copyright 2017 Garrett D'Amore <garrett@damore.org>
// Copyright 2017 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "core/nng_impl.h"

#include <stdio.h>
#include <string.h>

int
nni_chkopt_usec(const void *v, size_t sz)
{
	nni_duration val;
	if (sz != sizeof(val)) {
		return (NNG_EINVAL);
	}
	memcpy(&val, v, sz);
	if (val < -1) {
		return (NNG_EINVAL);
	}
	return (0);
}

int
nni_chkopt_int(const void *v, size_t sz, int minv, int maxv)
{
	int val;
	if (sz != sizeof(val)) {
		return (NNG_EINVAL);
	}
	memcpy(&val, v, sz);
	if ((val < minv) || (val > maxv)) {
		return (NNG_EINVAL);
	}
	return (0);
}

int
nni_chkopt_size(const void *v, size_t sz, size_t minv, size_t maxv)
{
	size_t val;
	if (sz != sizeof(val)) {
		return (NNG_EINVAL);
	}
	memcpy(&val, v, sz);
	if ((val < minv) || (val > maxv)) {
		return (NNG_EINVAL);
	}
	return (0);
}

int
nni_setopt_usec(nni_duration *dp, const void *v, size_t sz)
{
	nni_duration dur;

	if (sz != sizeof(*dp)) {
		return (NNG_EINVAL);
	}
	memcpy(&dur, v, sizeof(dur));
	if (dur < -1) {
		return (NNG_EINVAL);
	}
	*dp = dur;
	return (0);
}

int
nni_setopt_int(int *ip, const void *v, size_t sz, int minv, int maxv)
{
	int i;

	if (sz != sizeof(i)) {
		return (NNG_EINVAL);
	}
	memcpy(&i, v, sizeof(i));
	if (i > maxv) {
		return (NNG_EINVAL);
	}
	if (i < minv) {
		return (NNG_EINVAL);
	}
	*ip = i;
	return (0);
}

int
nni_setopt_size(size_t *sp, const void *v, size_t sz, size_t minv, size_t maxv)
{
	size_t val;

	if (sz != sizeof(val)) {
		return (NNG_EINVAL);
	}
	memcpy(&val, v, sizeof(val));
	if (val > maxv) {
		return (NNG_EINVAL);
	}
	if (val < minv) {
		return (NNG_EINVAL);
	}
	*sp = val;
	return (0);
}

int
nni_getopt_usec(nni_duration u, void *val, size_t *sizep)
{
	size_t sz = sizeof(u);

	if (sz > *sizep) {
		sz = *sizep;
	}
	*sizep = sizeof(u);
	memcpy(val, &u, sz);
	return (0);
}

int
nni_getopt_sockaddr(const nng_sockaddr *sa, void *val, size_t *sizep)
{
	size_t sz = sizeof(*sa);

	if (sz > *sizep) {
		sz = *sizep;
	}
	*sizep = sizeof(*sa);
	memcpy(val, sa, sz);
	return (0);
}

int
nni_getopt_int(int i, void *val, size_t *sizep)
{
	size_t sz = sizeof(i);

	if (sz > *sizep) {
		sz = *sizep;
	}
	*sizep = sizeof(i);
	memcpy(val, &i, sz);
	return (0);
}

int
nni_getopt_u64(const uint64_t u, void *val, size_t *sizep)
{
	size_t sz = sizeof(u);

	if (sz > *sizep) {
		sz = *sizep;
	}
	*sizep = sizeof(u);
	memcpy(val, &u, sz);
	return (0);
}

int
nni_getopt_str(const char *ptr, void *val, size_t *sizep)
{
	size_t len = strlen(ptr) + 1;
	size_t sz;

	sz     = (len > *sizep) ? *sizep : len;
	*sizep = len;
	memcpy(val, ptr, sz);
	return (0);
}

int
nni_getopt_size(size_t u, void *val, size_t *sizep)
{
	size_t sz = sizeof(u);

	if (sz > *sizep) {
		sz = *sizep;
	}
	*sizep = sizeof(u);
	memcpy(val, &u, sz);
	return (0);
}

int
nni_setopt_buf(nni_msgq *mq, const void *val, size_t sz)
{
	int len;

	if (sz < sizeof(len)) {
		return (NNG_EINVAL);
	}
	memcpy(&len, val, sizeof(len));
	if (len < 0) {
		return (NNG_EINVAL);
	}
	if (len > 8192) {
		// put a reasonable uppper limit on queue depth.
		// This is a count in messages, so the total queue
		// size could be quite large indeed in this case.
		return (NNG_EINVAL);
	}
	return (nni_msgq_resize(mq, len));
}

int
nni_getopt_buf(nni_msgq *mq, void *val, size_t *sizep)
{
	int len = nni_msgq_cap(mq);

	size_t sz = *sizep;

	if (sz > sizeof(len)) {
		sz = sizeof(len);
	}
	memcpy(val, &len, sz);
	*sizep = sizeof(len);
	return (0);
}

static void
nni_notifyfd_push(struct nng_event *ev, void *arg)
{
	nni_notifyfd *fd = arg;

	NNI_ARG_UNUSED(ev);

	nni_plat_pipe_raise(fd->sn_wfd);
}

int
nni_getopt_fd(nni_sock *s, nni_notifyfd *fd, int mask, void *val, size_t *szp)
{
	int      rv;
	uint32_t flags;

	if ((*szp < sizeof(int))) {
		return (NNG_EINVAL);
	}

	flags = nni_sock_flags(s);

	switch (mask) {
	case NNG_EV_CAN_SND:
		if ((flags & NNI_PROTO_FLAG_SND) == 0) {
			return (NNG_ENOTSUP);
		}
		break;
	case NNG_EV_CAN_RCV:
		if ((flags & NNI_PROTO_FLAG_RCV) == 0) {
			return (NNG_ENOTSUP);
		}
		break;
	default:
		return (NNG_ENOTSUP);
	}

	// If we already inited this, just give back the same file descriptor.
	if (fd->sn_init) {
		memcpy(val, &fd->sn_rfd, sizeof(int));
		*szp = sizeof(int);
		return (0);
	}

	if ((rv = nni_plat_pipe_open(&fd->sn_wfd, &fd->sn_rfd)) != 0) {
		return (rv);
	}

	if (nni_sock_notify(s, mask, nni_notifyfd_push, fd) == NULL) {
		nni_plat_pipe_close(fd->sn_wfd, fd->sn_rfd);
		return (NNG_ENOMEM);
	}

	fd->sn_init = 1;
	*szp        = sizeof(int);
	memcpy(val, &fd->sn_rfd, sizeof(int));
	return (0);
}
