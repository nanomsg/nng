//
// Copyright 2024 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
// Copyright 2018 Devolutions <info@devolutions.net>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "core/defs.h"
#include "core/nng_impl.h"
#include "nng/nng.h"

#include <stdio.h>
#include <string.h>

int
nni_copyin_ms(nni_duration *dp, const void *v, size_t sz, nni_type t)
{
	nni_duration dur;
	NNI_ARG_UNUSED(sz);

	if (t != NNI_TYPE_DURATION) {
		return (NNG_EBADTYPE);
	}
	dur = *(nng_duration *) v;

	if (dur < -1) {
		return (NNG_EINVAL);
	}
	if (dp != NULL) {
		*dp = dur;
	}
	return (0);
}

int
nni_copyin_bool(bool *bp, const void *v, size_t sz, nni_type t)
{
	NNI_ARG_UNUSED(sz);

	if (t != NNI_TYPE_BOOL) {
		return (NNG_EBADTYPE);
	}
	*bp = *(bool *) v;
	return (0);
}

int
nni_copyin_int(
    int *ip, const void *v, size_t sz, int minv, int maxv, nni_type t)
{
	int i;
	NNI_ARG_UNUSED(sz);

	if (t != NNI_TYPE_INT32) {
		return (NNG_EBADTYPE);
	}
	i = *(int *) v;
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
nni_copyin_size(
    size_t *sp, const void *v, size_t sz, size_t minv, size_t maxv, nni_type t)
{
	size_t val;
	NNI_ARG_UNUSED(sz);

	if (t != NNI_TYPE_SIZE) {
		return (NNG_EBADTYPE);
	}

	val = *(size_t *) v;
	if ((val > maxv) || (val < minv)) {
		return (NNG_EINVAL);
	}
	*sp = val;
	return (0);
}

int
nni_copyin_ptr(void **pp, const void *v, size_t sz, nni_type t)
{
	NNI_ARG_UNUSED(sz);

	if (t != NNI_TYPE_POINTER) {
		return (NNG_EBADTYPE);
	}

	*pp = *(void **) v;
	return (0);
}

int
nni_copyin_str(char *s, const void *v, size_t maxsz, nni_type t)
{
	size_t z;

	if (t != NNI_TYPE_STRING) {
		return (NNG_EBADTYPE);
	}
	z = nni_strnlen(v, maxsz);
	if (z == maxsz && ((char *) v)[maxsz - 1] != 0) {
		return (NNG_EINVAL); // too long
	}
	memcpy(s, v, z);
	s[z] = 0;
	return (0);
}

int
nni_copyin_u64(uint64_t *up, const void *v, size_t sz, nni_type t)
{
	NNI_ARG_UNUSED(sz);

	if (t != NNI_TYPE_UINT64) {
		return (NNG_EBADTYPE);
	}
	*up = *(uint64_t *) v;
	return (0);
}

int
nni_copyin_sockaddr(nng_sockaddr *ap, const void *v, nni_type t)
{
	if (t != NNI_TYPE_SOCKADDR) {
		return (NNG_EBADTYPE);
	}
	*ap = *(nng_sockaddr *) v;
	return (0);
}

int
nni_copyout_bool(bool b, void *dst, size_t *szp, nni_type t)
{
	NNI_ARG_UNUSED(szp);
	if (t != NNI_TYPE_BOOL) {
		return (NNG_EBADTYPE);
	}
	*(bool *) dst = b;
	return (0);
}

int
nni_copyout_int(int i, void *dst, size_t *szp, nni_type t)
{
	NNI_ARG_UNUSED(szp);
	if (t != NNI_TYPE_INT32) {
		return (NNG_EBADTYPE);
	}
	*(int *) dst = i;
	return (0);
}

int
nni_copyout_ms(nng_duration d, void *dst, size_t *szp, nni_type t)
{
	NNI_ARG_UNUSED(szp);
	if (t != NNI_TYPE_DURATION) {
		return (NNG_EBADTYPE);
	}
	*(nng_duration *) dst = d;
	return (0);
}

int
nni_copyout_ptr(void *p, void *dst, size_t *szp, nni_type t)
{
	NNI_ARG_UNUSED(szp);
	if (t != NNI_TYPE_POINTER) {
		return (NNG_EBADTYPE);
	}
	*(void **) dst = p;
	return (0);
}

int
nni_copyout_size(size_t s, void *dst, size_t *szp, nni_type t)
{
	NNI_ARG_UNUSED(szp);
	if (t != NNI_TYPE_SIZE) {
		return (NNG_EBADTYPE);
	}
	*(size_t *) dst = s;
	return (0);
}

int
nni_copyout_sockaddr(
    const nng_sockaddr *sap, void *dst, size_t *szp, nni_type t)
{
	NNI_ARG_UNUSED(szp);
	if (t != NNI_TYPE_SOCKADDR) {
		return (NNG_EBADTYPE);
	}
	*(nng_sockaddr *) dst = *sap;
	return (0);
}

int
nni_copyout_u64(uint64_t u, void *dst, size_t *szp, nni_type t)
{
	NNI_ARG_UNUSED(szp);
	if (t != NNI_TYPE_UINT64) {
		return (NNG_EBADTYPE);
	}
	*(uint64_t *) dst = u;
	return (0);
}

int
nni_copyout_str(const char *str, void *dst, size_t *szp, nni_type t)
{
	char *s;
	NNI_ARG_UNUSED(szp);
	if (t != NNI_TYPE_STRING) {
		return (NNG_EBADTYPE);
	}

	if ((s = nni_strdup(str)) == NULL) {
		return (NNG_ENOMEM);
	}
	*(char **) dst = s;
	return (0);
}

int
nni_getopt(const nni_option *opts, const char *nm, void *arg, void *buf,
    size_t *szp, nni_type otype)
{
	while (opts->o_name != NULL) {
		if (strcmp(opts->o_name, nm) == 0) {
			if (opts->o_get == NULL) {
				return (NNG_EWRITEONLY);
			}
			return (opts->o_get(arg, buf, szp, otype));
		}
		opts++;
	}
	return (NNG_ENOTSUP);
}

int
nni_setopt(const nni_option *opts, const char *nm, void *arg, const void *buf,
    size_t sz, nni_type otype)
{
	while (opts->o_name != NULL) {
		if (strcmp(opts->o_name, nm) == 0) {
			if (opts->o_set == NULL) {
				return (NNG_EREADONLY);
			}
			return (opts->o_set(arg, buf, sz, otype));
		}
		opts++;
	}
	return (NNG_ENOTSUP);
}
