//
// Copyright 2020 Staysail Systems, Inc. <info@staysail.tech>
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

static nni_id_map dialers;
static nni_mtx    dialers_lk;

int
nni_dialer_sys_init(void)
{
	nni_id_map_init(&dialers, 1, 0x7fffffff, false);
	nni_mtx_init(&dialers_lk);

	return (0);
}

void
nni_dialer_sys_fini(void)
{
	nni_reap_drain();
	nni_mtx_fini(&dialers_lk);
	nni_id_map_fini(&dialers);
}

uint32_t
nni_dialer_id(nni_dialer *d)
{
	return (d->d_id);
}

void
nni_dialer_destroy(nni_dialer *d)
{
	nni_aio_stop(&d->d_con_aio);
	nni_aio_stop(&d->d_tmo_aio);

	nni_aio_fini(&d->d_con_aio);
	nni_aio_fini(&d->d_tmo_aio);

	if (d->d_data != NULL) {
		d->d_ops.d_fini(d->d_data);
	}
	nni_mtx_fini(&d->d_mtx);
	nni_url_free(d->d_url);
	NNI_FREE_STRUCT(d);
}

#if NNG_ENABLE_STATS
static void
dialer_stat_init(nni_dialer *d, nni_stat_item *item, const nni_stat_info *info)
{
	nni_stat_init(item, info);
	nni_stat_add(&d->st_root, item);
}

static void
dialer_stats_init(nni_dialer *d)
{
	static const nni_stat_info root_info = {
		.si_name = "dialer",
		.si_desc = "dialer statistics",
		.si_type = NNG_STAT_SCOPE,
	};
	static const nni_stat_info id_info = {
		.si_name = "id",
		.si_desc = "dialer id",
		.si_type = NNG_STAT_ID,
	};
	static const nni_stat_info socket_info = {
		.si_name = "socket",
		.si_desc = "socket for dialer",
		.si_type = NNG_STAT_ID,
	};
	static const nni_stat_info url_info = {
		.si_name  = "url",
		.si_desc  = "dialer url",
		.si_type  = NNG_STAT_STRING,
		.si_alloc = true,
	};
	static const nni_stat_info pipes_info = {
		.si_name   = "pipes",
		.si_desc   = "open pipes",
		.si_type   = NNG_STAT_LEVEL,
		.si_atomic = true,
	};
	static const nni_stat_info connect_info = {
		.si_name   = "connect",
		.si_desc   = "connections established",
		.si_type   = NNG_STAT_COUNTER,
		.si_atomic = true,
	};
	static const nni_stat_info refused_info = {
		.si_name   = "refused",
		.si_desc   = "connections refused",
		.si_type   = NNG_STAT_COUNTER,
		.si_atomic = true,
	};
	static const nni_stat_info disconnect_info = {
		.si_name   = "disconnect",
		.si_desc   = "remote disconnects",
		.si_type   = NNG_STAT_COUNTER,
		.si_atomic = true,
	};
	static const nni_stat_info canceled_info = {
		.si_name   = "canceled",
		.si_desc   = "canceled connections",
		.si_type   = NNG_STAT_COUNTER,
		.si_atomic = true,
	};
	static const nni_stat_info other_info = {
		.si_name   = "other",
		.si_desc   = "other errors",
		.si_type   = NNG_STAT_COUNTER,
		.si_atomic = true,
	};
	static const nni_stat_info timeout_info = {
		.si_name   = "timeout",
		.si_desc   = "timeout errors",
		.si_type   = NNG_STAT_COUNTER,
		.si_atomic = true,
	};
	static const nni_stat_info proto_info = {
		.si_name   = "proto",
		.si_desc   = "protocol errors",
		.si_type   = NNG_STAT_COUNTER,
		.si_atomic = true,
	};
	static const nni_stat_info auth_info = {
		.si_name   = "auth",
		.si_desc   = "auth errors",
		.si_type   = NNG_STAT_COUNTER,
		.si_atomic = true,
	};
	static const nni_stat_info oom_info = {
		.si_name   = "oom",
		.si_desc   = "allocation failures",
		.si_type   = NNG_STAT_COUNTER,
		.si_atomic = true,
	};
	static const nni_stat_info reject_info = {
		.si_name   = "reject",
		.si_desc   = "rejected pipes",
		.si_type   = NNG_STAT_COUNTER,
		.si_atomic = true,
	};

	nni_stat_init(&d->st_root, &root_info);

	dialer_stat_init(d, &d->st_id, &id_info);
	dialer_stat_init(d, &d->st_sock, &socket_info);
	dialer_stat_init(d, &d->st_url, &url_info);
	dialer_stat_init(d, &d->st_pipes, &pipes_info);
	dialer_stat_init(d, &d->st_connect, &connect_info);
	dialer_stat_init(d, &d->st_refused, &refused_info);
	dialer_stat_init(d, &d->st_disconnect, &disconnect_info);
	dialer_stat_init(d, &d->st_canceled, &canceled_info);
	dialer_stat_init(d, &d->st_other, &other_info);
	dialer_stat_init(d, &d->st_timeout, &timeout_info);
	dialer_stat_init(d, &d->st_proto, &proto_info);
	dialer_stat_init(d, &d->st_auth, &auth_info);
	dialer_stat_init(d, &d->st_oom, &oom_info);
	dialer_stat_init(d, &d->st_reject, &reject_info);

	nni_stat_set_id(&d->st_root, d->d_id);
	nni_stat_set_id(&d->st_id, d->d_id);
	nni_stat_set_id(&d->st_sock, nni_sock_id(d->d_sock));
	nni_stat_set_string(&d->st_url, d->d_url->u_rawurl);
	nni_stat_register(&d->st_root);
}
#endif // NNG_ENABLE_STATS

void
nni_dialer_bump_error(nni_dialer *d, int err)
{
#ifdef NNG_ENABLE_STATS
	switch (err) {
	case NNG_ECONNABORTED:
	case NNG_ECONNRESET:
		nni_stat_inc(&d->st_disconnect, 1);
		break;
	case NNG_ECONNREFUSED:
		nni_stat_inc(&d->st_refused, 1);
		break;
	case NNG_ECANCELED:
		nni_stat_inc(&d->st_canceled, 1);
		break;
	case NNG_ETIMEDOUT:
		nni_stat_inc(&d->st_timeout, 1);
		break;
	case NNG_EPROTO:
		nni_stat_inc(&d->st_proto, 1);
		break;
	case NNG_EPEERAUTH:
	case NNG_ECRYPTO:
		nni_stat_inc(&d->st_auth, 1);
		break;
	case NNG_ENOMEM:
		nni_stat_inc(&d->st_oom, 1);
		break;
	default:
		nni_stat_inc(&d->st_other, 1);
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
	d->d_ref     = 1;
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

	nni_aio_init(&d->d_con_aio, dialer_connect_cb, d);
	nni_aio_init(&d->d_tmo_aio, dialer_timer_cb, d);

	nni_mtx_lock(&dialers_lk);
	rv = nni_id_alloc(&dialers, &d->d_id, d);
	nni_mtx_unlock(&dialers_lk);

#ifdef NNG_ENABLE_STATS
	dialer_stats_init(d);
#endif

	if ((rv != 0) || ((rv = d->d_ops.d_init(&d->d_data, url, d)) != 0) ||
	    ((rv = nni_sock_add_dialer(s, d)) != 0)) {
		nni_mtx_lock(&dialers_lk);
		nni_id_remove(&dialers, d->d_id);
		nni_mtx_unlock(&dialers_lk);
#ifdef NNG_ENABLE_STATS
		nni_stat_unregister(&d->st_root);
#endif
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
	if ((d = nni_id_get(&dialers, id)) != NULL) {
		d->d_ref++;
		*dp = d;
	}
	nni_mtx_unlock(&dialers_lk);
	return (d == NULL ? NNG_ENOENT : 0);
}

int
nni_dialer_hold(nni_dialer *d)
{
	int rv;
	nni_mtx_lock(&dialers_lk);
	if (d->d_closed) {
		rv = NNG_ECLOSED;
	} else {
		d->d_ref++;
		rv = 0;
	}
	nni_mtx_unlock(&dialers_lk);
	return (rv);
}

void
nni_dialer_rele(nni_dialer *d)
{
	bool reap;

	nni_mtx_lock(&dialers_lk);
	d->d_ref--;
	reap = ((d->d_ref == 0) && (d->d_closed));
	nni_mtx_unlock(&dialers_lk);

	if (reap) {
		nni_dialer_reap(d);
	}
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
	nni_id_remove(&dialers, d->d_id);
	nni_mtx_unlock(&dialers_lk);

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
	nni_id_remove(&dialers, d->d_id);
	nni_mtx_unlock(&dialers_lk);

	nni_dialer_shutdown(d);

	nni_dialer_rele(d);
}

static void
dialer_timer_cb(void *arg)
{
	nni_dialer *d = arg;

	if (nni_aio_result(&d->d_tmo_aio) == 0) {
		dialer_connect_start(d);
	}
}

static void
dialer_connect_cb(void *arg)
{
	nni_dialer *d   = arg;
	nni_aio *   aio = &d->d_con_aio;
	nni_aio *   user_aio;
	int         rv;

	nni_mtx_lock(&d->d_mtx);
	user_aio      = d->d_user_aio;
	d->d_user_aio = NULL;
	nni_mtx_unlock(&d->d_mtx);

	switch ((rv = nni_aio_result(aio))) {
	case 0:
#ifdef NNG_ENABLE_STATS
		nni_stat_inc(&d->st_connect, 1);
#endif
		nni_dialer_add_pipe(d, nni_aio_get_output(aio, 0));
		break;
	case NNG_ECLOSED:   // No further action.
	case NNG_ECANCELED: // No further action.
		nni_dialer_bump_error(d, rv);
		break;
	case NNG_ECONNREFUSED:
	case NNG_ETIMEDOUT:
	default:
		nni_dialer_bump_error(d, rv);
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
	d->d_ops.d_connect(d->d_data, &d->d_con_aio);
}

int
nni_dialer_start(nni_dialer *d, unsigned flags)
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
nni_dialer_add_stat(nni_dialer *d, nni_stat_item *item)
{
#ifdef NNG_ENABLE_STATS
	nni_stat_add(&d->st_root, item);
#else
	NNI_ARG_UNUSED(d);
	NNI_ARG_UNUSED(item);
#endif
}
