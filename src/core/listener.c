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

// Functionality related to listeners.

static void listener_accept_start(nni_listener *);
static void listener_accept_cb(void *);
static void listener_timer_cb(void *);

static nni_id_map listeners;
static nni_mtx    listeners_lk;

int
nni_listener_sys_init(void)
{
	nni_id_map_init(&listeners, 1, 0x7fffffff, false);
	nni_mtx_init(&listeners_lk);

	return (0);
}

void
nni_listener_sys_fini(void)
{
	nni_reap_drain();
	nni_mtx_fini(&listeners_lk);
	nni_id_map_fini(&listeners);
}

uint32_t
nni_listener_id(nni_listener *l)
{
	return (l->l_id);
}

void
nni_listener_destroy(nni_listener *l)
{
	nni_aio_stop(&l->l_acc_aio);
	nni_aio_stop(&l->l_tmo_aio);

	nni_aio_fini(&l->l_acc_aio);
	nni_aio_fini(&l->l_tmo_aio);

	if (l->l_data != NULL) {
		l->l_ops.l_fini(l->l_data);
	}
	nni_url_free(l->l_url);
	NNI_FREE_STRUCT(l);
}

#ifdef NNG_ENABLE_STATS
static void
listener_stat_init(
    nni_listener *l, nni_stat_item *item, const nni_stat_info *info)
{
	nni_stat_init(item, info);
	nni_stat_add(&l->st_root, item);
}

static void
listener_stats_init(nni_listener *l)
{
	static const nni_stat_info root_info = {
		.si_name = "listener",
		.si_desc = "listener statistics",
		.si_type = NNG_STAT_SCOPE,
	};
	static const nni_stat_info id_info = {
		.si_name = "id",
		.si_desc = "listener id",
		.si_type = NNG_STAT_ID,
	};
	static const nni_stat_info sock_info = {
		.si_name = "socket",
		.si_desc = "socket id",
		.si_type = NNG_STAT_ID,
	};
	static const nni_stat_info url_info = {
		.si_name  = "url",
		.si_desc  = "listener url",
		.si_type  = NNG_STAT_STRING,
		.si_alloc = true,
	};
	static const nni_stat_info pipes_info = {
		.si_name   = "pipes",
		.si_desc   = "open pipes",
		.si_type   = NNG_STAT_COUNTER,
		.si_atomic = true,
	};
	static const nni_stat_info accept_info = {
		.si_name   = "accept",
		.si_desc   = "connections accepted",
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

	nni_stat_init(&l->st_root, &root_info);

	listener_stat_init(l, &l->st_id, &id_info);
	listener_stat_init(l, &l->st_sock, &sock_info);
	listener_stat_init(l, &l->st_url, &url_info);
	listener_stat_init(l, &l->st_pipes, &pipes_info);
	listener_stat_init(l, &l->st_accept, &accept_info);
	listener_stat_init(l, &l->st_disconnect, &disconnect_info);
	listener_stat_init(l, &l->st_canceled, &canceled_info);
	listener_stat_init(l, &l->st_other, &other_info);
	listener_stat_init(l, &l->st_timeout, &timeout_info);
	listener_stat_init(l, &l->st_proto, &proto_info);
	listener_stat_init(l, &l->st_auth, &auth_info);
	listener_stat_init(l, &l->st_oom, &oom_info);
	listener_stat_init(l, &l->st_reject, &reject_info);

	nni_stat_set_id(&l->st_root, l->l_id);
	nni_stat_set_id(&l->st_id, l->l_id);
	nni_stat_set_string(&l->st_url, l->l_url->u_rawurl);
	nni_stat_register(&l->st_root);
}
#endif // NNG_ENABLE_STATS

void
nni_listener_bump_error(nni_listener *l, int err)
{
#ifdef NNG_ENABLE_STATS
	switch (err) {
	case NNG_ECONNABORTED:
	case NNG_ECONNRESET:
		nni_stat_inc(&l->st_disconnect, 1);
		break;
	case NNG_ECANCELED:
		nni_stat_inc(&l->st_canceled, 1);
		break;
	case NNG_ETIMEDOUT:
		nni_stat_inc(&l->st_timeout, 1);
		break;
	case NNG_EPROTO:
		nni_stat_inc(&l->st_proto, 1);
		break;
	case NNG_EPEERAUTH:
	case NNG_ECRYPTO:
		nni_stat_inc(&l->st_auth, 1);
		break;
	case NNG_ENOMEM:
		nni_stat_inc(&l->st_oom, 1);
		break;
	default:
		nni_stat_inc(&l->st_other, 1);
		break;
	}
#else
	NNI_ARG_UNUSED(l);
	NNI_ARG_UNUSED(err);
#endif
}

int
nni_listener_create(nni_listener **lp, nni_sock *s, const char *url_str)
{
	nni_tran *    tran;
	nni_listener *l;
	int           rv;
	nni_url *     url;

	if ((rv = nni_url_parse(&url, url_str)) != 0) {
		return (rv);
	}
	if (((tran = nni_tran_find(url)) == NULL) ||
	    (tran->tran_listener == NULL)) {
		nni_url_free(url);
		return (NNG_ENOTSUP);
	}

	if ((l = NNI_ALLOC_STRUCT(l)) == NULL) {
		nni_url_free(url);
		return (NNG_ENOMEM);
	}
	l->l_url     = url;
	l->l_closed  = false;
	l->l_closing = false;
	l->l_data    = NULL;
	l->l_ref     = 1;
	l->l_sock    = s;
	l->l_tran    = tran;
	nni_atomic_flag_reset(&l->l_started);

	// Make a copy of the endpoint operations.  This allows us to
	// modify them (to override NULLs for example), and avoids an extra
	// dereference on hot paths.
	l->l_ops = *tran->tran_listener;

	NNI_LIST_NODE_INIT(&l->l_node);
	NNI_LIST_INIT(&l->l_pipes, nni_pipe, p_ep_node);

	nni_aio_init(&l->l_acc_aio, listener_accept_cb, l);
	nni_aio_init(&l->l_tmo_aio, listener_timer_cb, l);

	nni_mtx_lock(&listeners_lk);
	rv = nni_id_alloc(&listeners, &l->l_id, l);
	nni_mtx_unlock(&listeners_lk);

#ifdef NNG_ENABLE_STATS
	listener_stats_init(l);
#endif

	if ((rv != 0) || ((rv = l->l_ops.l_init(&l->l_data, url, l)) != 0) ||
	    ((rv = nni_sock_add_listener(s, l)) != 0)) {
		nni_mtx_lock(&listeners_lk);
		nni_id_remove(&listeners, l->l_id);
		nni_mtx_unlock(&listeners_lk);
#ifdef NNG_ENABLE_STATS
		nni_stat_unregister(&l->st_root);
#endif
		nni_listener_destroy(l);
		return (rv);
	}

	*lp = l;
	return (0);
}

int
nni_listener_find(nni_listener **lp, uint32_t id)
{
	int           rv;
	nni_listener *l;

	if ((rv = nni_init()) != 0) {
		return (rv);
	}

	nni_mtx_lock(&listeners_lk);
	if ((l = nni_id_get(&listeners, id)) != NULL) {
		l->l_ref++;
		*lp = l;
	}
	nni_mtx_unlock(&listeners_lk);
	return (l == NULL ? NNG_ENOENT : 0);
}

int
nni_listener_hold(nni_listener *l)
{
	int rv;
	nni_mtx_lock(&listeners_lk);
	if (l->l_closed) {
		rv = NNG_ECLOSED;
	} else {
		l->l_ref++;
		rv = 0;
	}
	nni_mtx_unlock(&listeners_lk);
	return (rv);
}

void
nni_listener_rele(nni_listener *l)
{
	bool reap;

	nni_mtx_lock(&listeners_lk);
	l->l_ref--;
	reap = ((l->l_ref == 0) && (l->l_closed));
	nni_mtx_unlock(&listeners_lk);
	if (reap) {
		nni_listener_reap(l);
	}
}

void
nni_listener_close(nni_listener *l)
{
	nni_mtx_lock(&listeners_lk);
	if (l->l_closed) {
		nni_mtx_unlock(&listeners_lk);
		nni_listener_rele(l);
		return;
	}
	l->l_closed = true;
	nni_id_remove(&listeners, l->l_id);
	nni_mtx_unlock(&listeners_lk);

	nni_listener_shutdown(l);

	nni_listener_rele(l); // This will trigger a reap if id count is zero.
}

void
nni_listener_close_rele(nni_listener *l)
{
	// Listener should already be shutdown.  The socket lock may be held.
	nni_mtx_lock(&listeners_lk);
	if (l->l_closed) {
		nni_mtx_unlock(&listeners_lk);
		nni_listener_rele(l);
		return;
	}
	l->l_closed = true;
	nni_id_remove(&listeners, l->l_id);
	nni_mtx_unlock(&listeners_lk);

	nni_listener_rele(l); // This will trigger a reap if id count is zero.
}

static void
listener_timer_cb(void *arg)
{
	nni_listener *l = arg;

	if (nni_aio_result(&l->l_tmo_aio) == 0) {
		listener_accept_start(l);
	}
}

static void
listener_accept_cb(void *arg)
{
	nni_listener *l   = arg;
	nni_aio *     aio = &l->l_acc_aio;
	int           rv;

	switch ((rv = nni_aio_result(aio))) {
	case 0:
#ifdef NNG_ENABLE_STATS
		nni_stat_inc(&l->st_accept, 1);
#endif
		nni_listener_add_pipe(l, nni_aio_get_output(aio, 0));
		listener_accept_start(l);
		break;
	case NNG_ECONNABORTED: // remote condition, no cool down
	case NNG_ECONNRESET:   // remote condition, no cool down
	case NNG_ETIMEDOUT:    // No need to sleep, we timed out already.
	case NNG_EPEERAUTH:    // peer validation failure
		nni_listener_bump_error(l, rv);
		listener_accept_start(l);
		break;
	case NNG_ECLOSED:   // no further action
	case NNG_ECANCELED: // no further action
		nni_listener_bump_error(l, rv);
		break;
	default:
		// We don't really know why we failed, but we back off
		// here. This is because errors here are probably due
		// to system failures (resource exhaustion) and we hope
		// by not thrashing we give the system a chance to
		// recover.  100 ms is enough to cool down.
		nni_listener_bump_error(l, rv);
		nni_sleep_aio(100, &l->l_tmo_aio);
		break;
	}
}

static void
listener_accept_start(nni_listener *l)
{
	// Call with the listener lock held.
	l->l_ops.l_accept(l->l_data, &l->l_acc_aio);
}

int
nni_listener_start(nni_listener *l, int flags)
{
	int rv;
	NNI_ARG_UNUSED(flags);

	if (nni_atomic_flag_test_and_set(&l->l_started)) {
		return (NNG_ESTATE);
	}

	if ((rv = l->l_ops.l_bind(l->l_data)) != 0) {
		nni_listener_bump_error(l, rv);
		nni_atomic_flag_reset(&l->l_started);
		return (rv);
	}

	listener_accept_start(l);

	return (0);
}

nni_sock *
nni_listener_sock(nni_listener *l)
{
	return (l->l_sock);
}

int
nni_listener_setopt(
    nni_listener *l, const char *name, const void *val, size_t sz, nni_type t)
{
	nni_option *o;

	if (strcmp(name, NNG_OPT_URL) == 0) {
		return (NNG_EREADONLY);
	}

	if (l->l_ops.l_setopt != NULL) {
		int rv = l->l_ops.l_setopt(l->l_data, name, val, sz, t);
		if (rv != NNG_ENOTSUP) {
			return (rv);
		}
	}

	for (o = l->l_ops.l_options; o && o->o_name; o++) {
		if (strcmp(o->o_name, name) != 0) {
			continue;
		}
		if (o->o_set == NULL) {
			return (NNG_EREADONLY);
		}

		return (o->o_set(l->l_data, val, sz, t));
	}

	return (NNG_ENOTSUP);
}

int
nni_listener_getopt(
    nni_listener *l, const char *name, void *val, size_t *szp, nni_type t)
{
	nni_option *o;

	if (l->l_ops.l_getopt != NULL) {
		int rv = l->l_ops.l_getopt(l->l_data, name, val, szp, t);
		if (rv != NNG_ENOTSUP) {
			return (rv);
		}
	}

	for (o = l->l_ops.l_options; o && o->o_name; o++) {
		if (strcmp(o->o_name, name) != 0) {
			continue;
		}
		if (o->o_get == NULL) {
			return (NNG_EWRITEONLY);
		}
		return (o->o_get(l->l_data, val, szp, t));
	}

	// We provide a fallback on the URL, but let the implementation
	// override.  This allows the URL to be created with wildcards,
	// that are resolved later.
	if (strcmp(name, NNG_OPT_URL) == 0) {
		return (nni_copyout_str(l->l_url->u_rawurl, val, szp, t));
	}

	return (nni_sock_getopt(l->l_sock, name, val, szp, t));
}

void
nni_listener_add_stat(nni_listener *l, nni_stat_item *item)
{
#if NNG_ENABLE_STATS
	nni_stat_add(&l->st_root, item);
#else
	NNI_ARG_UNUSED(l);
	NNI_ARG_UNUSED(item);
#endif
}
