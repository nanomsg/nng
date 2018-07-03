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
#include <stdlib.h>
#include <string.h>

struct nni_dialer {
	nni_tran_dialer_ops d_ops;  // transport ops
	nni_tran *          d_tran; // transport pointer
	void *              d_data; // transport private
	uint64_t            d_id;   // endpoint id
	nni_list_node       d_node; // per socket list
	nni_sock *          d_sock;
	nni_url *           d_url;
	int                 d_refcnt;
	int                 d_lastrv; // last result from synchronous
	bool                d_synch;  // synchronous connect in progress?
	bool                d_started;
	bool                d_closed;  // full shutdown
	nni_atomic_flag     d_closing; // close pending (waiting on refcnt)
	nni_mtx             d_mtx;
	nni_cv              d_cv;
	nni_list            d_pipes;
	nni_aio *           d_con_aio;
	nni_aio *           d_tmo_aio;  // backoff timer
	nni_duration        d_maxrtime; // maximum time for reconnect
	nni_duration        d_currtime; // current time for reconnect
	nni_duration        d_inirtime; // initial time for reconnect
	nni_time            d_conntime; // time of last good connect
};

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
	nni_mtx_fini(&dialers_lk);
	nni_idhash_fini(dialers);
	dialers = NULL;
}

uint32_t
nni_dialer_id(nni_dialer *d)
{
	return ((uint32_t) d->d_id);
}

static void
dialer_destroy(nni_dialer *d)
{
	if (d == NULL) {
		return;
	}

	// Remove us from the table so we cannot be found.
	if (d->d_id != 0) {
		nni_idhash_remove(dialers, d->d_id);
	}

	nni_aio_stop(d->d_con_aio);
	nni_aio_stop(d->d_tmo_aio);

	nni_sock_remove_dialer(d->d_sock, d);

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
	d->d_url     = url;
	d->d_closed  = false;
	d->d_started = false;
	d->d_data    = NULL;
	d->d_refcnt  = 1;
	d->d_sock    = s;
	d->d_tran    = tran;
	nni_atomic_flag_reset(&d->d_closing);

	// Make a copy of the endpoint operations.  This allows us to
	// modify them (to override NULLs for example), and avoids an extra
	// dereference on hot paths.
	d->d_ops = *tran->tran_dialer;

	NNI_LIST_NODE_INIT(&d->d_node);

	nni_pipe_ep_list_init(&d->d_pipes);

	nni_mtx_init(&d->d_mtx);
	nni_cv_init(&d->d_cv, &d->d_mtx);

	if (((rv = nni_aio_init(&d->d_con_aio, dialer_connect_cb, d)) != 0) ||
	    ((rv = nni_aio_init(&d->d_tmo_aio, dialer_timer_cb, d)) != 0) ||
	    ((rv = d->d_ops.d_init(&d->d_data, url, s)) != 0) ||
	    ((rv = nni_idhash_alloc(dialers, &d->d_id, d)) != 0) ||
	    ((rv = nni_sock_add_dialer(s, d)) != 0)) {
		dialer_destroy(d);
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
	if (d->d_refcnt == 0) {
		nni_cv_wake(&d->d_cv);
	}
	nni_mtx_unlock(&dialers_lk);
}

int
nni_dialer_shutdown(nni_dialer *d)
{
	if (nni_atomic_flag_test_and_set(&d->d_closing)) {
		return (NNG_ECLOSED);
	}

	// Abort any remaining in-flight operations.
	nni_aio_close(d->d_con_aio);
	nni_aio_close(d->d_tmo_aio);

	// Stop the underlying transport.
	d->d_ops.d_close(d->d_data);

	return (0);
}

void
nni_dialer_close(nni_dialer *d)
{
	nni_pipe *p;

	nni_mtx_lock(&d->d_mtx);
	if (d->d_closed) {
		nni_mtx_unlock(&d->d_mtx);
		nni_dialer_rele(d);
		return;
	}
	d->d_closed = true;
	nni_mtx_unlock(&d->d_mtx);

	nni_dialer_shutdown(d);

	nni_aio_stop(d->d_con_aio);
	nni_aio_stop(d->d_tmo_aio);

	nni_mtx_lock(&d->d_mtx);
	NNI_LIST_FOREACH (&d->d_pipes, p) {
		nni_pipe_stop(p);
	}
	while ((!nni_list_empty(&d->d_pipes)) || (d->d_refcnt != 1)) {
		nni_cv_wait(&d->d_cv);
	}
	nni_mtx_unlock(&d->d_mtx);

	dialer_destroy(d);
}

// This function starts an exponential backoff timer for reconnecting.
static void
dialer_timer_start(nni_dialer *d)
{
	nni_duration backoff;

	backoff = d->d_currtime;
	d->d_currtime *= 2;
	if (d->d_currtime > d->d_maxrtime) {
		d->d_currtime = d->d_maxrtime;
	}

	// To minimize damage from storms, etc., we select a backoff
	// value randomly, in the range of [0, backoff-1]; this is
	// pretty similar to 802 style backoff, except that we have a
	// nearly uniform time period instead of discrete slot times.
	// This algorithm may lead to slight biases because we don't
	// have a statistically perfect distribution with the modulo of
	// the random number, but this really doesn't matter.
	nni_sleep_aio(backoff ? nni_random() % backoff : 0, d->d_tmo_aio);
}

static void
dialer_timer_cb(void *arg)
{
	nni_dialer *d   = arg;
	nni_aio *   aio = d->d_tmo_aio;

	nni_mtx_lock(&d->d_mtx);
	if (nni_aio_result(aio) == 0) {
		dialer_connect_start(d);
	}
	nni_mtx_unlock(&d->d_mtx);
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
		rv = nni_pipe_create2(&p, d->d_sock, d->d_tran, data);
	}
	nni_mtx_lock(&d->d_mtx);
	synch      = d->d_synch;
	d->d_synch = false;
	if (rv == 0) {
		nni_pipe_set_dialer(p, d);
		nni_list_append(&d->d_pipes, p);

		// Good connect, so reset the backoff timer.
		// Note that a host that accepts the connect, but drops
		// us immediately, is going to get hit pretty hard
		// (depending on the initial backoff) with no
		// exponential backoff. This can happen if we wind up
		// trying to connect to some port that does not speak
		// SP for example.
		d->d_currtime = d->d_inirtime;
	}
	nni_mtx_unlock(&d->d_mtx);

	if ((rv == 0) && ((rv = nni_sock_pipe_add(d->d_sock, p)) != 0)) {
		nni_pipe_stop(p);
	}

	nni_mtx_lock(&d->d_mtx);
	switch (rv) {
	case 0:
		// No further outgoing connects -- we will restart a
		// connection from the pipe when the pipe is removed.
		break;
	case NNG_ECLOSED:
	case NNG_ECANCELED:
		// Canceled/closed -- stop everything.
		break;
	default:
		// redial, but only if we are not synchronous
		if (!synch) {
			dialer_timer_start(d);
		}
		break;
	}
	if (synch) {
		d->d_lastrv = rv;
		nni_cv_wake(&d->d_cv);
	}
	nni_mtx_unlock(&d->d_mtx);
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

	//	nni_sock_reconntimes(d->d_sock, &d->d_inirtime,
	//&d->d_maxrtime);
	d->d_currtime = d->d_inirtime;

	nni_mtx_lock(&d->d_mtx);

	if (d->d_started) {
		nni_mtx_unlock(&d->d_mtx);
		return (NNG_ESTATE);
	}

	if ((flags & NNG_FLAG_NONBLOCK) != 0) {
		d->d_started = true;
		dialer_connect_start(d);
		nni_mtx_unlock(&d->d_mtx);
		return (0);
	}

	d->d_synch   = true;
	d->d_started = true;
	dialer_connect_start(d);

	while (d->d_synch) {
		nni_cv_wait(&d->d_cv);
	}
	rv = d->d_lastrv;
	nni_cv_wake(&d->d_cv);

	if (rv != 0) {
		d->d_started = false;
	}
	nni_mtx_unlock(&d->d_mtx);
	return (rv);
}

void
nni_dialer_remove_pipe(nni_dialer *d, nni_pipe *p)
{
	if (d == NULL) {
		return;
	}

	// Break up the relationship between the dialer and the pipe.
	nni_mtx_lock(&d->d_mtx);
	// During early init, the pipe might not have this set.
	if (nni_list_active(&d->d_pipes, p)) {
		nni_list_remove(&d->d_pipes, p);
	}
	// Wake up the close thread if it is waiting.
	if (d->d_closed) {
		if (nni_list_empty(&d->d_pipes)) {
			nni_cv_wake(&d->d_cv);
		}
	} else {
		// If this pipe closed, then lets restart the dial operation.
		// Since the remote side seems to have closed, lets start with
		// a backoff.  This keeps us from pounding the crap out of the
		// thing if a remote server accepts but then disconnects
		// immediately.
		dialer_timer_start(d);
	}
	nni_mtx_unlock(&d->d_mtx);
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

void
nni_dialer_list_init(nni_list *list)
{
	NNI_LIST_INIT(list, nni_dialer, d_node);
}
