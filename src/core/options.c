//
// Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
// Copyright 2018 Devolutions <info@devolutions.net>
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
nni_copyin_ms(nni_duration *dp, const void *v, size_t sz, nni_type t)
{
	nni_duration dur;

	switch (t) {
	case NNI_TYPE_DURATION:
		dur = *(nng_duration *) v;
		break;
	case NNI_TYPE_OPAQUE:
		if (sz != sizeof(dur)) {
			return (NNG_EINVAL);
		}
		memcpy(&dur, v, sz);
		break;
	default:
		return (NNG_EBADTYPE);
	}

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
	switch (t) {
	case NNI_TYPE_BOOL:
		if (bp != NULL) {
			*bp = *(bool *) v;
		}
		break;
	case NNI_TYPE_OPAQUE:
		if (sz != sizeof(bool)) {
			return (NNG_EINVAL);
		}
		if (bp != NULL) {
			memcpy(bp, v, sz);
		}
		break;
	default:
		return (NNG_EBADTYPE);
	}

	return (0);
}

int
nni_copyin_int(
    int *ip, const void *v, size_t sz, int minv, int maxv, nni_type t)
{
	int i;

	switch (t) {
	case NNI_TYPE_INT32:
		i = *(int *) v;
		break;
	case NNI_TYPE_OPAQUE:
		if (sz != sizeof(i)) {
			return (NNG_EINVAL);
		}
		memcpy(&i, v, sz);
		break;
	default:
		return (NNG_EBADTYPE);
	}
	if (i > maxv) {
		return (NNG_EINVAL);
	}
	if (i < minv) {
		return (NNG_EINVAL);
	}
	if (ip != NULL) {
		*ip = i;
	}
	return (0);
}

int
nni_copyin_size(
    size_t *sp, const void *v, size_t sz, size_t minv, size_t maxv, nni_type t)
{
	size_t val;

	switch (t) {
	case NNI_TYPE_SIZE:
		val = *(size_t *) v;
		break;
	case NNI_TYPE_OPAQUE:
		if (sz != sizeof(val)) {
			return (NNG_EINVAL);
		}
		memcpy(&val, v, sz);
		break;
	default:
		return (NNG_EBADTYPE);
	}

	val = *(size_t *) v;
	if ((val > maxv) || (val < minv)) {
		return (NNG_EINVAL);
	}
	if (sp != NULL) {
		*sp = val;
	}
	return (0);
}

int
nni_copyin_ptr(void **pp, const void *v, size_t sz, nni_type t)
{
	void *p;

	switch (t) {
	case NNI_TYPE_POINTER:
		p = *(void **) v;
		break;
	case NNI_TYPE_OPAQUE:
		if (sz != sizeof(p)) {
			return (NNG_EINVAL);
		}
		memcpy(&p, v, sz);
		break;
	default:
		return (NNG_EBADTYPE);
	}
	if (pp != NULL) {
		*pp = p;
	}
	return (0);
}

int
nni_copyin_str(char *s, const void *v, size_t sz, size_t maxsz, nni_type t)
{
	size_t z;

	switch (t) {
	case NNI_TYPE_STRING:
	case NNI_TYPE_OPAQUE:
		if ((z = nni_strnlen(v, sz)) >= sz) {
			return (NNG_EINVAL); // missing terminator
		}
		break;
	default:
		return (NNG_EBADTYPE);
	}
	if (z > maxsz) {
		return (NNG_EINVAL); // too long
	}
	if (s != NULL) {
		memcpy(s, v, z);
	}
	return (0);
}

int
nni_copyin_u64(uint64_t *up, const void *v, size_t sz, nni_type t)
{
	uint64_t u;

	switch (t) {
	case NNI_TYPE_UINT64:
		u = *(uint64_t *) v;
		break;
	case NNI_TYPE_OPAQUE:
		if (sz != sizeof(u)) {
			return (NNG_EINVAL);
		}
		memcpy(&u, v, sz);
		break;
	default:
		return (NNG_EBADTYPE);
	}
	if (up != NULL) {
		*up = u;
	}
	return (0);
}

int
nni_copyin_sockaddr(nng_sockaddr *ap, const void *v, size_t sz, nni_type t)
{
	nng_sockaddr a;

	switch (t) {
	case NNI_TYPE_SOCKADDR:
		a = *(nng_sockaddr *) v;
		break;
	case NNI_TYPE_OPAQUE:
		if (sz != sizeof(nng_sockaddr)) {
			return (NNG_EINVAL);
		}
		memcpy(&a, v, sz);
		break;
	default:
		return (NNG_EBADTYPE);
	}
	if (ap != NULL) {
		*ap = a;
	}
	return (0);
}

int
nni_copyout(const void *src, size_t srcsz, void *dst, size_t *dstszp)
{
	int    rv     = 0;
	size_t copysz = *dstszp;
	// Assumption is that this is type NNI_TYPE_OPAQUE.
	if (copysz > srcsz) {
		copysz = srcsz;
	} else if (srcsz > copysz) {
		// destination too small.
		rv = NNG_EINVAL;
	}
	*dstszp = srcsz;
	memcpy(dst, src, copysz);
	return (rv);
}

int
nni_copyout_bool(bool b, void *dst, size_t *szp, nni_type t)
{
	switch (t) {
	case NNI_TYPE_BOOL:
		NNI_ASSERT(*szp == sizeof(b));
		*(bool *) dst = b;
		return (0);
	case NNI_TYPE_OPAQUE:
		return (nni_copyout(&b, sizeof(b), dst, szp));
	default:
		return (NNG_EBADTYPE);
	}
}

int
nni_copyout_int(int i, void *dst, size_t *szp, nni_type t)
{
	switch (t) {
	case NNI_TYPE_INT32:
		NNI_ASSERT(*szp == sizeof(i));
		*(int *) dst = i;
		return (0);
	case NNI_TYPE_OPAQUE:
		return (nni_copyout(&i, sizeof(i), dst, szp));
	default:
		return (NNG_EBADTYPE);
	}
}

int
nni_copyout_ms(nng_duration d, void *dst, size_t *szp, nni_type t)
{
	switch (t) {
	case NNI_TYPE_DURATION:
		NNI_ASSERT(*szp == sizeof(d));
		*(nng_duration *) dst = d;
		return (0);
	case NNI_TYPE_OPAQUE:
		return (nni_copyout(&d, sizeof(d), dst, szp));
	default:
		return (NNG_EBADTYPE);
	}
}

int
nni_copyout_ptr(void *p, void *dst, size_t *szp, nni_type t)
{
	switch (t) {
	case NNI_TYPE_POINTER:
		NNI_ASSERT(*szp == sizeof(p));
		*(void **) dst = p;
		return (0);
	case NNI_TYPE_OPAQUE:
		return (nni_copyout(&p, sizeof(p), dst, szp));
	default:
		return (NNG_EBADTYPE);
	}
}

int
nni_copyout_size(size_t s, void *dst, size_t *szp, nni_type t)
{
	switch (t) {
	case NNI_TYPE_SIZE:
		NNI_ASSERT(*szp == sizeof(s));
		*(size_t *) dst = s;
		return (0);
	case NNI_TYPE_OPAQUE:
		return (nni_copyout(&s, sizeof(s), dst, szp));
	default:
		return (NNG_EBADTYPE);
	}
}

int
nni_copyout_sockaddr(
    const nng_sockaddr *sap, void *dst, size_t *szp, nni_type t)
{
	switch (t) {
	case NNI_TYPE_SOCKADDR:
		NNI_ASSERT(*szp == sizeof(*sap));
		*(nng_sockaddr *) dst = *sap;
		return (0);
	case NNI_TYPE_OPAQUE:
		return (nni_copyout(sap, sizeof(*sap), dst, szp));
	default:
		return (NNG_EBADTYPE);
	}
}

int
nni_copyout_u64(uint64_t u, void *dst, size_t *szp, nni_type t)
{
	switch (t) {
	case NNI_TYPE_UINT64:
		NNI_ASSERT(*szp == sizeof(u));
		*(uint64_t *) dst = u;
		return (0);
	case NNI_TYPE_OPAQUE:
		return (nni_copyout(&u, sizeof(u), dst, szp));
	default:
		return (NNG_EBADTYPE);
	}
}

int
nni_copyout_str(const char *str, void *dst, size_t *szp, nni_type t)
{
	char *s;

	switch (t) {
	case NNI_TYPE_STRING:
		NNI_ASSERT(*szp == sizeof(char *));
		if ((s = nni_strdup(str)) == NULL) {
			return (NNG_ENOMEM);
		}
		*(char **) dst = s;
		return (0);

	case NNI_TYPE_OPAQUE:
		return (nni_copyout(str, strlen(str) + 1, dst, szp));

	default:
		return (NNG_EBADTYPE);
	}
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

int
nni_chkopt(const nni_chkoption *opts, const char *nm, const void *buf,
    size_t sz, nni_type t)
{
	while (opts->o_name != NULL) {
		if (strcmp(opts->o_name, nm) == 0) {
			if (opts->o_check == NULL) {
				return (NNG_EREADONLY);
			}
			return (opts->o_check(buf, sz, t));
		}
		opts++;
	}
	return (NNG_ENOTSUP);
}