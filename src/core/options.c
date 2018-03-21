//
// Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
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
nni_chkopt_ms(const void *v, size_t sz)
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
nni_chkopt_bool(size_t sz)
{
	if (sz != sizeof(bool)) {
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
nni_setopt_ms(nni_duration *dp, const void *v, size_t sz)
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
nni_setopt_bool(bool *bp, const void *v, size_t sz)
{
	if (sz != sizeof(*bp)) {
		return (NNG_EINVAL);
	}
	memcpy(bp, v, sizeof(*bp));
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
nni_copyout_bool(bool b, void *dst, size_t *szp, int typ)
{
	switch (typ) {
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
nni_copyout_int(int i, void *dst, size_t *szp, int typ)
{
	switch (typ) {
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
nni_copyout_ms(nng_duration d, void *dst, size_t *szp, int typ)
{
	switch (typ) {
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
nni_copyout_ptr(void *p, void *dst, size_t *szp, int typ)
{
	switch (typ) {
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
nni_copyout_size(size_t s, void *dst, size_t *szp, int typ)
{
	switch (typ) {
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
nni_copyout_sockaddr(const nng_sockaddr *sap, void *dst, size_t *szp, int typ)
{
	switch (typ) {
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
nni_copyout_u64(uint64_t u, void *dst, size_t *szp, int typ)
{
	switch (typ) {
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
nni_copyout_str(const char *str, void *dst, size_t *szp, int typ)
{
	char *s;

	switch (typ) {
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
