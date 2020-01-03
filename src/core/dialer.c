//
// Copyright 2019 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
// Copyright 2018 Devolutions <info@devolutions.net>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "core/nng_impl.h"
#include "sockimpl.h"

#include <stdio.h>
#include <string.h>

// Functionality related to dialers.
static void dialer_connect_start(nni_dialer *);
static void dialer_connect_cb(void *);
static void dialer_timer_cb(void *);

static nni_idhash *dialers;
static nni_mtx     dialers_lk;

#define BUMP_STAT(x) nni_stat_inc_atomic(x, 1)

int
nni_dialer_sys_init(void)
{
	int rv;

	if ((rv = nni_idhash_init(&dialers)) != 0) {
		return (rv);
	}
	nni_mtx_init(&dialers_lk);
	nni_idhash_set_limits(dialers, 1, 0x7fffffff, 1);

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

	nni_aio_free(d->d_con_aio);
	nni_aio_free(d->d_tmo_aio);

	if (d->d_data != NULL) {
		d->d_ops.d_fini(d->d_data);
	}
	nni_mtx_fini(&d->d_mtx);
	nni_url_free(d->d_url);
	NNI_FREE_STRUCT(d);
}

static void
dialer_stats_init(nni_dialer *d)
{
	nni_dialer_stats *st   = &d->d_stats;
	nni_stat_item *   root = &st->s_root;

	nni_stat_init_scope(root, st->s_scope, "dialer statistics");

	nni_stat_init_id(&st->s_id, "id", "dialer id", d->d_id);
	nni_stat_add(root, &st->s_id);

	nni_stat_init_id(&st->s_sock, "socket", "socket for dialer",
	    nni_sock_id(d->d_sock));
	nni_stat_add(root, &st->s_sock);

	nni_stat_init_string(
	    &st->s_url, "url", "dialer url", d->d_url->u_rawurl);
	nni_stat_add(root, &st->s_url);

	nni_stat_init_atomic(&st->s_npipes, "npipes", "open pipes");
	nni_stat_add(root, &st->s_npipes);

	nni_stat_init_atomic(
	    &st->s_connok, "connect", "connections established");
	nni_stat_add(root, &st->s_connok);

	nni_stat_init_atomic(&st->s_refused, "refused", "connections refused");
	nni_stat_add(root, &st->s_refused);

	nni_stat_init_atomic(&st->s_discon, "discon", "remote disconnects");
	nni_stat_add(root, &st->s_discon);

	nni_stat_init_atomic(&st->s_canceled, "canceled", "canceled");
	nni_stat_add(root, &st->s_canceled);

	nni_stat_init_atomic(&st->s_othererr, "othererr", "other errors");
	nni_stat_add(root, &st->s_othererr);

	nni_stat_init_atomic(&st->s_etimedout, "timedout", "timed out");
	nni_stat_add(root, &st->s_etimedout);

	nni_stat_init_atomic(&st->s_eproto, "protoerr", "protcol errors");
	nni_stat_add(root, &st->s_eproto);

	nni_stat_init_atomic(&st->s_eauth, "autherr", "auth errors");
	nni_stat_add(root, &st->s_eauth);

	nni_stat_init_atomic(&st->s_enomem, "nomem", "out of memory");
	nni_stat_add(root, &st->s_enomem);

	nni_stat_init_atomic(&st->s_reject, "reject", "pipes rejected");
	nni_stat_add(root, &st->s_reject);
}

void
nni_dialer_bump_error(nni_dialer *d, int err)
{
#ifdef NNG_ENABLE_STATS
	switch (err) {
	case NNG_ECONNABORTED:
	case NNG_ECONNRESET:
		BUMP_STAT(&d->d_stats.s_discon);
		break;
	case NNG_ECONNREFUSED:
		BUMP_STAT(&d->d_stats.s_refused);
		break;
	case NNG_ECANCELED:
		BUMP_STAT(&d->d_stats.s_canceled);
		break;
	case NNG_ETIMEDOUT:
		BUMP_STAT(&d->d_stats.s_etimedout);
		break;
	case NNG_EPROTO:
		BUMP_STAT(&d->d_stats.s_eproto);
		break;
	case NNG_EPEERAUTH:
	case NNG_ECRYPTO:
		BUMP_STAT(&d->d_stats.s_eauth);
		break;
	case NNG_ENOMEM:
		BUMP_STAT(&d->d_stats.s_enomem);
		break;
	default:
		BUMP_STAT(&d->d_stats.s_othererr);
		break;
	}
#else
	NNI_ARG_UNUSED(d);
	NNI_ARG_UNUSED(err);
#endif
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
	d->d_closing = false;
	d->d_data    = NULL;
	d->d_refcnt  = 1;
	d->d_sock    = s;
	d->d_tran    = tran;
	nni_atomic_flag_reset(&d->d_started);

	// Make a copy of the endpoint operations.  This allows us to
	// modify them (to override NULLs for example), and avoids an extra
	// dereference on hot paths.
	d->d_ops = *tran->tran_dialer;

	NNI_LIST_NODE_INIT(&d->d_node);
	NNI_LIST_INIT(&d->d_pipes, nni_pipe, p_ep_node);

	nni_mtx_init(&d->d_mtx);

	dialer_stats_init(d);
	if (((rv = nni_aio_alloc(&d->d_con_aio, dialer_connect_cb, d)) != 0) ||
	    ((rv = nni_aio_alloc(&d->d_tmo_aio, dialer_timer_cb, d)) != 0) ||
	    ((rv = d->d_ops.d_init(&d->d_data, url, d)) != 0) ||
	    ((rv = nni_idhash_alloc32(dialers, &d->d_id, d)) != 0) ||
	    ((rv = nni_sock_add_dialer(s, d)) != 0)) {
		nni_dialer_destroy(d);
		return (rv);
	}

	snprintf(d->d_stats.s_scope, sizeof(d->d_stats.s_scope), "dialer%u",
	    d->d_id);
	nni_stat_set_value(&d->d_stats.s_id, d->d_id);
	nni_stat_register(&d->d_stats.s_root);
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
nni_dialer_close_rele(nni_dialer *d)
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

	nni_dialer_rele(d);
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
	nni_dialer *d   = arg;
	nni_aio *   aio = d->d_con_aio;
	nni_aio *   user_aio;
	int         rv;

	nni_mtx_lock(&d->d_mtx);
	user_aio      = d->d_user_aio;
	d->d_user_aio = NULL;
	nni_mtx_unlock(&d->d_mtx);

	switch ((rv = nni_aio_result(aio))) {
	case 0:
		BUMP_STAT(&d->d_stats.s_connok);
		nni_dialer_add_pipe(d, nni_aio_get_output(aio, 0));
		break;
	case NNG_ECLOSED:   // No further action.
	case NNG_ECANCELED: // No further action.
		break;
	case NNG_ECONNREFUSED:
	case NNG_ETIMEDOUT:
	default:
		if (user_aio == NULL) {
			nni_dialer_timer_start(d);
		} else {
			nni_atomic_flag_reset(&d->d_started);
		}
		break;
	}
	if (user_aio != NULL) {
		nni_aio_finish(user_aio, rv, 0);
	}
}

static void
dialer_connect_start(nni_dialer *d)
{
	nni_aio *aio = d->d_con_aio;

	d->d_ops.d_connect(d->d_data, aio);
}

int
nni_dialer_start(nni_dialer *d, int flags)
{
	int      rv = 0;
	nni_aio *aio;

	if (nni_atomic_flag_test_and_set(&d->d_started)) {
		return (NNG_ESTATE);
	}

	if ((flags & NNG_FLAG_NONBLOCK) != 0) {
		aio = NULL;
	} else {
		if ((rv = nni_aio_alloc(&aio, NULL, NULL)) != 0) {
			nni_atomic_flag_reset(&d->d_started);
			return (rv);
		}
		nni_aio_begin(aio);
	}

	nni_mtx_lock(&d->d_mtx);
	d->d_user_aio = aio;
	dialer_connect_start(d);
	nni_mtx_unlock(&d->d_mtx);

	if (aio != NULL) {
		nni_aio_wait(aio);
		rv = nni_aio_result(aio);
		nni_aio_free(aio);
	}

	return (rv);
}

nni_sock *
nni_dialer_sock(nni_dialer *d)
{
	return (d->d_sock);
}

int
nni_dialer_setopt(
    nni_dialer *d, const char *name, const void *val, size_t sz, nni_type t)
{
	nni_option *o;

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
		if (rv == 0) {
			d->d_currtime = d->d_inirtime;
		}
		nni_mtx_unlock(&d->d_mtx);
		return (rv);
	}

	if (d->d_ops.d_setopt != NULL) {
		int rv = d->d_ops.d_setopt(d->d_data, name, val, sz, t);
		if (rv != NNG_ENOTSUP) {
			return (rv);
		}
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
    nni_dialer *d, const char *name, void *valp, size_t *szp, nni_type t)
{
	nni_option *o;

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

	if (d->d_ops.d_getopt != NULL) {
		int rv = d->d_ops.d_getopt(d->d_data, name, valp, szp, t);
		if (rv != NNG_ENOTSUP) {
			return (rv);
		}
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
nni_dialer_add_stat(nni_dialer *d, nni_stat_item *stat)
{
	nni_stat_add(&d->d_stats.s_root, stat);
}
