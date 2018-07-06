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
#include "sockimpl.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Functionality related to dialers.
static void dialer_connect_start(nni_dialer *);
static void dialer_connect_cb(void *);
static void dialer_timer_cb(void *);

static nni_idhash *dialers;
static nni_mtx     dialers_lk;

int
nni_dialer_sys_init(void)
{
	int rv;

	if ((rv = nni_idhash_init(&dialers)) != 0) {
		return (rv);
	}
	nni_mtx_init(&dialers_lk);
	nni_idhash_set_limits(
	    dialers, 1, 0x7fffffff, nni_random() & 0x7fffffff);

	return (0);
}

void
nni_dialer_sys_fini(void)
{
	nni_reap_drain();
	nni_mtx_fini(&dialers_lk);
	nni_idhash_fini(dialers);
	dialers = NULL;
}

uint32_t
nni_dialer_id(nni_dialer *d)
{
	return (d->d_id);
}

void
nni_dialer_destroy(nni_dialer *d)
{
	nni_aio_stop(d->d_con_aio);
	nni_aio_stop(d->d_tmo_aio);

	nni_aio_fini(d->d_con_aio);
	nni_aio_fini(d->d_tmo_aio);

	if (d->d_data != NULL) {
		d->d_ops.d_fini(d->d_data);
	}
	nni_cv_fini(&d->d_cv);
	nni_mtx_fini(&d->d_mtx);
	nni_url_free(d->d_url);
	NNI_FREE_STRUCT(d);
}

int
nni_dialer_create(nni_dialer **dp, nni_sock *s, const char *urlstr)
{
	nni_tran *  tran;
	nni_dialer *d;
	int         rv;
	nni_url *   url;

	if ((rv = nni_url_parse(&url, urlstr)) != 0) {
		return (rv);
	}
	if (((tran = nni_tran_find(url)) == NULL) ||
	    (tran->tran_dialer == NULL)) {
		nni_url_free(url);
		return (NNG_ENOTSUP);
	}

	if ((d = NNI_ALLOC_STRUCT(d)) == NULL) {
		nni_url_free(url);
		return (NNG_ENOMEM);
	}
	d->d_url    = url;
	d->d_closed = false;
	d->d_data   = NULL;
	d->d_refcnt = 1;
	d->d_sock   = s;
	d->d_tran   = tran;
	nni_atomic_flag_reset(&d->d_started);
	nni_atomic_flag_reset(&d->d_closing);

	// Make a copy of the endpoint operations.  This allows us to
	// modify them (to override NULLs for example), and avoids an extra
	// dereference on hot paths.
	d->d_ops = *tran->tran_dialer;

	NNI_LIST_NODE_INIT(&d->d_node);
	NNI_LIST_INIT(&d->d_pipes, nni_pipe, p_ep_node);

	nni_mtx_init(&d->d_mtx);
	nni_cv_init(&d->d_cv, &d->d_mtx);

	if (((rv = nni_aio_init(&d->d_con_aio, dialer_connect_cb, d)) != 0) ||
	    ((rv = nni_aio_init(&d->d_tmo_aio, dialer_timer_cb, d)) != 0) ||
	    ((rv = d->d_ops.d_init(&d->d_data, url, s)) != 0) ||
	    ((rv = nni_idhash_alloc32(dialers, &d->d_id, d)) != 0) ||
	    ((rv = nni_sock_add_dialer(s, d)) != 0)) {
		nni_dialer_destroy(d);
		return (rv);
	}

	*dp = d;
	return (0);
}

int
nni_dialer_find(nni_dialer **dp, uint32_t id)
{
	int         rv;
	nni_dialer *d;

	if ((rv = nni_init()) != 0) {
		return (rv);
	}

	nni_mtx_lock(&dialers_lk);
	if ((rv = nni_idhash_find(dialers, id, (void **) &d)) == 0) {
		if (d->d_closed) {
			rv = NNG_ECLOSED;
		} else {
			d->d_refcnt++;
			*dp = d;
		}
	}
	nni_mtx_unlock(&dialers_lk);
	return (rv);
}

int
nni_dialer_hold(nni_dialer *d)
{
	int rv;
	nni_mtx_lock(&dialers_lk);
	if (d->d_closed) {
		rv = NNG_ECLOSED;
	} else {
		d->d_refcnt++;
		rv = 0;
	}
	nni_mtx_unlock(&dialers_lk);
	return (rv);
}

void
nni_dialer_rele(nni_dialer *d)
{
	nni_mtx_lock(&dialers_lk);
	d->d_refcnt--;
	if ((d->d_refcnt == 0) && (d->d_closed)) {
		nni_reap(&d->d_reap, (nni_cb) nni_dialer_reap, d);
	}
	nni_mtx_unlock(&dialers_lk);
}

void
nni_dialer_close(nni_dialer *d)
{
	nni_mtx_lock(&dialers_lk);
	if (d->d_closed) {
		nni_mtx_unlock(&dialers_lk);
		nni_dialer_rele(d);
		return;
	}
	d->d_closed = true;
	nni_mtx_unlock(&dialers_lk);

	// Remove us from the table so we cannot be found.
	// This is done fairly early in the teardown process.
	// If we're here, either the socket or the listener has been
	// closed at the user request, so there would be a race anyway.
	nni_idhash_remove(dialers, d->d_id);

	nni_dialer_shutdown(d);

	nni_dialer_rele(d);
}

static void
dialer_timer_cb(void *arg)
{
	nni_dialer *d   = arg;
	nni_aio *   aio = d->d_tmo_aio;

	if (nni_aio_result(aio) == 0) {
		dialer_connect_start(d);
	}
}

static void
dialer_connect_cb(void *arg)
{
	nni_dialer *d = arg;
	nni_pipe *  p;
	nni_aio *   aio = d->d_con_aio;
	int         rv;
	bool        synch;

	if ((rv = nni_aio_result(aio)) == 0) {
		void *data = nni_aio_get_output(aio, 0);
		NNI_ASSERT(data != NULL);
		rv = nni_pipe_create(&p, d->d_sock, d->d_tran, data);
	}
	nni_mtx_lock(&d->d_mtx);
	synch = d->d_synch;
	nni_mtx_unlock(&d->d_mtx);

	switch (rv) {
	case 0:
		nni_dialer_add_pipe(d, p);
		break;
	case NNG_ECLOSED:   // No further action.
	case NNG_ECANCELED: // No further action.
		break;
	default:
		if (!synch) {
			nni_dialer_timer_start(d);
		}
		break;
	}
	if (synch) {
		nni_mtx_lock(&d->d_mtx);
		d->d_synch  = false;
		d->d_lastrv = rv;
		nni_cv_wake(&d->d_cv);
		nni_mtx_unlock(&d->d_mtx);
	}
}

static void
dialer_connect_start(nni_dialer *d)
{
	nni_aio *aio = d->d_con_aio;

	// Call with the Endpoint lock held.
	d->d_ops.d_connect(d->d_data, aio);
}

int
nni_dialer_start(nni_dialer *d, int flags)
{
	int rv = 0;

	if (nni_atomic_flag_test_and_set(&d->d_started)) {
		return (NNG_ESTATE);
	}

	if ((flags & NNG_FLAG_NONBLOCK) != 0) {
		nni_mtx_lock(&d->d_mtx);
		d->d_currtime = d->d_inirtime;
		nni_mtx_unlock(&d->d_mtx);
		dialer_connect_start(d);
		return (0);
	}

	nni_mtx_lock(&d->d_mtx);
	d->d_synch = true;
	nni_mtx_unlock(&d->d_mtx);

	dialer_connect_start(d);

	nni_mtx_lock(&d->d_mtx);
	while (d->d_synch) {
		nni_cv_wait(&d->d_cv);
	}
	rv = d->d_lastrv;
	nni_mtx_unlock(&d->d_mtx);

	if (rv != 0) {
		nni_atomic_flag_reset(&d->d_started);
	}
	return (rv);
}

int
nni_dialer_setopt(nni_dialer *d, const char *name, const void *val, size_t sz,
    nni_opt_type t)
{
	nni_tran_option *o;

	if (strcmp(name, NNG_OPT_URL) == 0) {
		return (NNG_EREADONLY);
	}
	if (strcmp(name, NNG_OPT_RECONNMAXT) == 0) {
		int rv;
		nni_mtx_lock(&d->d_mtx);
		rv = nni_copyin_ms(&d->d_maxrtime, val, sz, t);
		nni_mtx_unlock(&d->d_mtx);
		return (rv);
	}
	if (strcmp(name, NNG_OPT_RECONNMINT) == 0) {
		int rv;
		nni_mtx_lock(&d->d_mtx);
		rv = nni_copyin_ms(&d->d_inirtime, val, sz, t);
		nni_mtx_unlock(&d->d_mtx);
		return (rv);
	}

	for (o = d->d_ops.d_options; o && o->o_name; o++) {
		if (strcmp(o->o_name, name) != 0) {
			continue;
		}
		if (o->o_set == NULL) {
			return (NNG_EREADONLY);
		}

		return (o->o_set(d->d_data, val, sz, t));
	}

	return (NNG_ENOTSUP);
}

int
nni_dialer_getopt(
    nni_dialer *d, const char *name, void *valp, size_t *szp, nni_opt_type t)
{
	nni_tran_option *o;

	if (strcmp(name, NNG_OPT_RECONNMAXT) == 0) {
		int rv;
		nni_mtx_lock(&d->d_mtx);
		rv = nni_copyout_ms(d->d_maxrtime, valp, szp, t);
		nni_mtx_unlock(&d->d_mtx);
		return (rv);
	}
	if (strcmp(name, NNG_OPT_RECONNMINT) == 0) {
		int rv;
		nni_mtx_lock(&d->d_mtx);
		rv = nni_copyout_ms(d->d_inirtime, valp, szp, t);
		nni_mtx_unlock(&d->d_mtx);
		return (rv);
	}

	for (o = d->d_ops.d_options; o && o->o_name; o++) {
		if (strcmp(o->o_name, name) != 0) {
			continue;
		}
		if (o->o_get == NULL) {
			return (NNG_EWRITEONLY);
		}
		return (o->o_get(d->d_data, valp, szp, t));
	}

	// We provide a fallback on the URL, but let the implementation
	// override.  This allows the URL to be created with wildcards,
	// that are resolved later.
	if (strcmp(name, NNG_OPT_URL) == 0) {
		return (nni_copyout_str(d->d_url->u_rawurl, valp, szp, t));
	}

	return (nni_sock_getopt(d->d_sock, name, valp, szp, t));
}
