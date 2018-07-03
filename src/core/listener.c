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

struct nni_listener {
	nni_tran_listener_ops l_ops;  // transport ops
	nni_tran *            l_tran; // transport pointer
	void *                l_data; // transport private
	uint64_t              l_id;   // endpoint id
	nni_list_node         l_node; // per socket list
	nni_sock *            l_sock;
	nni_url *             l_url;
	int                   l_refcnt;
	bool                  l_started;
	bool                  l_closed;  // full shutdown
	nni_atomic_flag       l_closing; // close pending
	nni_mtx               l_mtx;
	nni_cv                l_cv;
	nni_list              l_pipes;
	nni_aio *             l_acc_aio;
	nni_aio *             l_tmo_aio;
};

// Functionality related to listeners.

static void listener_accept_start(nni_listener *);
static void listener_accept_cb(void *);
static void listener_timer_cb(void *);

static nni_idhash *listeners;
static nni_mtx     listeners_lk;

int
nni_listener_sys_init(void)
{
	int rv;

	if ((rv = nni_idhash_init(&listeners)) != 0) {
		return (rv);
	}
	nni_mtx_init(&listeners_lk);
	nni_idhash_set_limits(
	    listeners, 1, 0x7fffffff, nni_random() & 0x7fffffff);

	return (0);
}

void
nni_listener_sys_fini(void)
{
	nni_mtx_fini(&listeners_lk);
	nni_idhash_fini(listeners);
	listeners = NULL;
}

uint32_t
nni_listener_id(nni_listener *l)
{
	return ((uint32_t) l->l_id);
}

static void
listener_destroy(nni_listener *l)
{
	if (l == NULL) {
		return;
	}

	// Remove us from the table so we cannot be found.
	if (l->l_id != 0) {
		nni_idhash_remove(listeners, l->l_id);
	}

	nni_aio_stop(l->l_acc_aio);

	nni_sock_remove_listener(l->l_sock, l);

	nni_aio_fini(l->l_acc_aio);

	if (l->l_data != NULL) {
		l->l_ops.l_fini(l->l_data);
	}
	nni_cv_fini(&l->l_cv);
	nni_mtx_fini(&l->l_mtx);
	nni_url_free(l->l_url);
	NNI_FREE_STRUCT(l);
}

int
nni_listener_create(nni_listener **lp, nni_sock *s, const char *urlstr)
{
	nni_tran *    tran;
	nni_listener *l;
	int           rv;
	nni_url *     url;

	if ((rv = nni_url_parse(&url, urlstr)) != 0) {
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
	l->l_started = false;
	l->l_data    = NULL;
	l->l_refcnt  = 1;
	l->l_sock    = s;
	l->l_tran    = tran;
	nni_atomic_flag_reset(&l->l_closing);

	// Make a copy of the endpoint operations.  This allows us to
	// modify them (to override NULLs for example), and avoids an extra
	// dereference on hot paths.
	l->l_ops = *tran->tran_listener;

	NNI_LIST_NODE_INIT(&l->l_node);

	nni_pipe_ep_list_init(&l->l_pipes);

	nni_mtx_init(&l->l_mtx);
	nni_cv_init(&l->l_cv, &l->l_mtx);

	if (((rv = nni_aio_init(&l->l_acc_aio, listener_accept_cb, l)) != 0) ||
	    ((rv = nni_aio_init(&l->l_tmo_aio, listener_timer_cb, l)) != 0) ||
	    ((rv = l->l_ops.l_init(&l->l_data, url, s)) != 0) ||
	    ((rv = nni_idhash_alloc(listeners, &l->l_id, l)) != 0) ||
	    ((rv = nni_sock_add_listener(s, l)) != 0)) {
		listener_destroy(l);
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
	if ((rv = nni_idhash_find(listeners, id, (void **) &l)) == 0) {
		if (l->l_closed) {
			rv = NNG_ECLOSED;
		} else {
			l->l_refcnt++;
			*lp = l;
		}
	}
	nni_mtx_unlock(&listeners_lk);
	return (rv);
}

int
nni_listener_hold(nni_listener *l)
{
	int rv;
	nni_mtx_lock(&listeners_lk);
	if (l->l_closed) {
		rv = NNG_ECLOSED;
	} else {
		l->l_refcnt++;
		rv = 0;
	}
	nni_mtx_unlock(&listeners_lk);
	return (rv);
}

void
nni_listener_rele(nni_listener *l)
{
	nni_mtx_lock(&listeners_lk);
	l->l_refcnt--;
	if (l->l_refcnt == 0) {
		nni_cv_wake(&l->l_cv);
	}
	nni_mtx_unlock(&listeners_lk);
}

int
nni_listener_shutdown(nni_listener *l)
{
	if (nni_atomic_flag_test_and_set(&l->l_closing)) {
		return (NNG_ECLOSED);
	}

	// Abort any remaining in-flight accepts.
	nni_aio_close(l->l_acc_aio);
	nni_aio_close(l->l_tmo_aio);

	// Stop the underlying transport.
	l->l_ops.l_close(l->l_data);

	return (0);
}

void
nni_listener_close(nni_listener *l)
{
	nni_pipe *p;

	nni_mtx_lock(&l->l_mtx);
	if (l->l_closed) {
		nni_mtx_unlock(&l->l_mtx);
		nni_listener_rele(l);
		return;
	}
	l->l_closed = true;
	nni_mtx_unlock(&l->l_mtx);

	nni_listener_shutdown(l);

	nni_aio_stop(l->l_acc_aio);
	nni_aio_stop(l->l_tmo_aio);

	nni_mtx_lock(&l->l_mtx);
	NNI_LIST_FOREACH (&l->l_pipes, p) {
		nni_pipe_stop(p);
	}
	while ((!nni_list_empty(&l->l_pipes)) || (l->l_refcnt != 1)) {
		nni_cv_wait(&l->l_cv);
	}
	nni_mtx_unlock(&l->l_mtx);

	listener_destroy(l);
}

static void
listener_timer_cb(void *arg)
{
	nni_listener *l   = arg;
	nni_aio *     aio = l->l_tmo_aio;

	if (nni_aio_result(aio) == 0) {
		listener_accept_start(l);
	}
}

static void
listener_accept_cb(void *arg)
{
	nni_listener *l = arg;
	nni_pipe *    p;
	nni_aio *     aio = l->l_acc_aio;
	int           rv;

	if ((rv = nni_aio_result(aio)) == 0) {
		void *data = nni_aio_get_output(aio, 0);
		NNI_ASSERT(data != NULL);
		rv = nni_pipe_create2(&p, l->l_sock, l->l_tran, data);
	}
	switch (rv) {
	case 0:
		nni_mtx_lock(&l->l_mtx);
		nni_pipe_set_listener(p, l);
		nni_list_append(&l->l_pipes, p);
		nni_mtx_unlock(&l->l_mtx);
		listener_accept_start(l);
		break;
	case NNG_ECONNABORTED: // remote condition, no cooldown
	case NNG_ECONNRESET:   // remote condition, no cooldown
		listener_accept_start(l);
		break;
	case NNG_ECLOSED:   // no further action
	case NNG_ECANCELED: // no further action
		break;
	default:
		// We don't really know why we failed, but we backoff
		// here. This is because errors here are probably due
		// to system failures (resource exhaustion) and we hope
		// by not thrashing we give the system a chance to
		// recover.  100 msec is enough to cool down.
		nni_sleep_aio(100, l->l_tmo_aio);
		break;
	}

	if ((rv == 0) && ((rv = nni_sock_pipe_add(l->l_sock, p)) != 0)) {
		nni_pipe_stop(p);
	}
}

static void
listener_accept_start(nni_listener *l)
{
	nni_aio *aio = l->l_acc_aio;

	// Call with the listener lock held.
	l->l_ops.l_accept(l->l_data, aio);
}

int
nni_listener_start(nni_listener *l, int flags)
{
	int rv = 0;
	NNI_ARG_UNUSED(flags);

	nni_mtx_lock(&l->l_mtx);
	if (l->l_started) {
		nni_mtx_unlock(&l->l_mtx);
		return (NNG_ESTATE);
	}

	if ((rv = l->l_ops.l_bind(l->l_data)) != 0) {
		nni_mtx_unlock(&l->l_mtx);
		return (rv);
	}

	l->l_started = true;
	nni_mtx_unlock(&l->l_mtx);

	listener_accept_start(l);

	return (0);
}

void
nni_listener_remove_pipe(nni_listener *l, nni_pipe *p)
{
	if (l == NULL) {
		return;
	}
	// Break up relationship between listener and pipe.
	nni_mtx_lock(&l->l_mtx);
	// During early init, the pipe might not have this set.
	if (nni_list_active(&l->l_pipes, p)) {
		nni_list_remove(&l->l_pipes, p);
	}
	// Wake up the closer if it is waiting.
	if (l->l_closed && nni_list_empty(&l->l_pipes)) {
		nni_cv_wake(&l->l_cv);
	}
	nni_mtx_unlock(&l->l_mtx);
}

int
nni_listener_setopt(nni_listener *l, const char *name, const void *val,
    size_t sz, nni_opt_type t)
{
	nni_tran_option *o;

	if (strcmp(name, NNG_OPT_URL) == 0) {
		return (NNG_EREADONLY);
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
    nni_listener *l, const char *name, void *valp, size_t *szp, nni_opt_type t)
{
	nni_tran_option *o;

	for (o = l->l_ops.l_options; o && o->o_name; o++) {
		if (strcmp(o->o_name, name) != 0) {
			continue;
		}
		if (o->o_get == NULL) {
			return (NNG_EWRITEONLY);
		}
		return (o->o_get(l->l_data, valp, szp, t));
	}

	// We provide a fallback on the URL, but let the implementation
	// override.  This allows the URL to be created with wildcards,
	// that are resolved later.
	if (strcmp(name, NNG_OPT_URL) == 0) {
		return (nni_copyout_str(l->l_url->u_rawurl, valp, szp, t));
	}

	return (nni_sock_getopt(l->l_sock, name, valp, szp, t));
}

void
nni_listener_list_init(nni_list *list)
{
	NNI_LIST_INIT(list, nni_listener, l_node);
}
