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

#include <string.h>

int
nni_setopt_duration(nni_duration *ptr, const void *val, size_t size)
{
	nni_duration dur;

	if (size != sizeof(*ptr)) {
		return (NNG_EINVAL);
	}
	memcpy(&dur, val, sizeof(dur));
	if (dur < -1) {
		return (NNG_EINVAL);
	}
	*ptr = dur;
	return (0);
}

int
nni_setopt_int(int *ptr, const void *val, size_t size, int minval, int maxval)
{
	int v;

	if (size != sizeof(v)) {
		return (NNG_EINVAL);
	}
	memcpy(&v, val, sizeof(v));
	if (v > maxval) {
		return (NNG_EINVAL);
	}
	if (v < minval) {
		return (NNG_EINVAL);
	}
	*ptr = v;
	return (0);
}

int
nni_setopt_size(
    size_t *ptr, const void *val, size_t size, size_t minval, size_t maxval)
{
	size_t v;

	if (size != sizeof(v)) {
		return (NNG_EINVAL);
	}
	memcpy(&v, val, sizeof(v));
	if (v > maxval) {
		return (NNG_EINVAL);
	}
	if (v < minval) {
		return (NNG_EINVAL);
	}
	*ptr = v;
	return (0);
}

int
nni_getopt_duration(nni_duration *ptr, void *val, size_t *sizep)
{
	size_t sz = sizeof(*ptr);

	if (sz > *sizep) {
		sz = *sizep;
	}
	*sizep = sizeof(*ptr);
	memcpy(val, ptr, sz);
	return (0);
}

int
nni_getopt_int(int *ptr, void *val, size_t *sizep)
{
	size_t sz = sizeof(*ptr);

	if (sz > *sizep) {
		sz = *sizep;
	}
	*sizep = sizeof(*ptr);
	memcpy(val, ptr, sz);
	return (0);
}

int
nni_getopt_size(size_t *ptr, void *val, size_t *sizep)
{
	size_t sz = sizeof(*ptr);

	if (sz > *sizep) {
		sz = *sizep;
	}
	*sizep = sizeof(*ptr);
	memcpy(val, ptr, sz);
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
	int rv;

	if ((*szp < sizeof(int))) {
		return (NNG_EINVAL);
	}

	switch (mask) {
	case NNG_EV_CAN_SND:
		if ((s->s_flags & NNI_PROTO_FLAG_SND) == 0) {
			return (NNG_ENOTSUP);
		}
		break;
	case NNG_EV_CAN_RCV:
		if ((s->s_flags & NNI_PROTO_FLAG_RCV) == 0) {
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
