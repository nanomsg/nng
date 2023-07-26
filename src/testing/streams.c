//
// Copyright 2020 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#define TEST_NO_MAIN

#include <nng/nng.h>
#include <nng/supplemental/util/platform.h>

typedef struct {
	uint8_t *   base;
	size_t      rem;
	nng_iov     iov;
	nng_aio *   upper_aio;
	nng_aio *   lower_aio;
	nng_stream *s;
	void (*submit)(nng_stream *, nng_aio *);
} stream_xfr_t;

static void
stream_xfr_free(stream_xfr_t *x)
{
	if (x == NULL) {
		return;
	}
	if (x->upper_aio != NULL) {
		nng_aio_free(x->upper_aio);
	}
	if (x->lower_aio != NULL) {
		nng_aio_free(x->lower_aio);
	}
	nng_free(x, sizeof(*x));
}

static void
stream_xfr_start(stream_xfr_t *x)
{
	nng_iov iov;
	iov.iov_buf = x->base;
	iov.iov_len = x->rem;

	nng_aio_set_iov(x->lower_aio, 1, &iov);
	x->submit(x->s, x->lower_aio);
}

static void
stream_xfr_cb(void *arg)
{
	stream_xfr_t *x = arg;
	int           rv;
	size_t        n;

	rv = nng_aio_result(x->lower_aio);
	if (rv != 0) {
		nng_aio_finish(x->upper_aio, rv);
		return;
	}
	n = nng_aio_count(x->lower_aio);

	x->rem -= n;
	x->base += n;

	if (x->rem == 0) {
		nng_aio_finish(x->upper_aio, 0);
		return;
	}

	stream_xfr_start(x);
}

static stream_xfr_t *
stream_xfr_alloc(nng_stream *s, void (*submit)(nng_stream *, nng_aio *),
    void *buf, size_t size)
{
	stream_xfr_t *x;

	if ((x = nng_alloc(sizeof(*x))) == NULL) {
		return (NULL);
	}
	if (nng_aio_alloc(&x->upper_aio, NULL, NULL) != 0) {
		stream_xfr_free(x);
		return (NULL);
	}
	if (nng_aio_alloc(&x->lower_aio, stream_xfr_cb, x) != 0) {
		stream_xfr_free(x);
		return (NULL);
	}

	// Upper should not take more than 30 seconds, lower not more than 5.
	nng_aio_set_timeout(x->upper_aio, 30000);
	nng_aio_set_timeout(x->lower_aio, 5000);

	nng_aio_begin(x->upper_aio);

	x->s      = s;
	x->rem    = size;
	x->base   = buf;
	x->submit = submit;

	return (x);
}

int
nuts_stream_wait(stream_xfr_t *x)
{
	int rv;
	if (x == NULL) {
		return (NNG_ENOMEM);
	}
	nng_aio_wait(x->upper_aio);
	rv = nng_aio_result(x->upper_aio);
	stream_xfr_free(x);
	return (rv);
}

void *
nuts_stream_recv_start(nng_stream *s, void *buf, size_t size)
{
	stream_xfr_t *x;

	x = stream_xfr_alloc(s, nng_stream_recv, buf, size);
	if (x == NULL) {
		return (x);
	}
	stream_xfr_start(x);
	return (x);
}

void *
nuts_stream_send_start(nng_stream *s, void *buf, size_t size)
{
	stream_xfr_t *x;

	x = stream_xfr_alloc(s, nng_stream_send, buf, size);
	if (x == NULL) {
		return (x);
	}
	stream_xfr_start(x);
	return (x);
}
