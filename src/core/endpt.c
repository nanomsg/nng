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

struct nni_ep {
	nni_tran_ep_ops ep_ops;  // transport ops
	nni_tran *      ep_tran; // transport pointer
	void *          ep_data; // transport private
	uint64_t        ep_id;   // endpoint id
	nni_list_node   ep_node; // per socket list
	nni_sock *      ep_sock;
	nni_url *       ep_url;
	int             ep_mode;
	int             ep_refcnt;
	bool            ep_started;
	bool            ep_closed;  // full shutdown
	bool            ep_closing; // close pending (waiting on refcnt)
	bool            ep_tmo_run;
	nni_mtx         ep_mtx;
	nni_cv          ep_cv;
	nni_list        ep_pipes;
	nni_aio *       ep_acc_aio;
	nni_aio *       ep_con_aio;
	nni_aio *       ep_con_syn;  // used for sync connect
	nni_aio *       ep_tmo_aio;  // backoff timer
	nni_duration    ep_maxrtime; // maximum time for reconnect
	nni_duration    ep_currtime; // current time for reconnect
	nni_duration    ep_inirtime; // initial time for reconnect
	nni_time        ep_conntime; // time of last good connect
};

// Functionality related to end points.

static void nni_ep_acc_start(nni_ep *);
static void nni_ep_acc_cb(void *);
static void nni_ep_con_start(nni_ep *);
static void nni_ep_con_cb(void *);
static void nni_ep_tmo_start(nni_ep *);
static void nni_ep_tmo_cb(void *);

static nni_idhash *nni_eps;
static nni_mtx     nni_ep_lk;

int
nni_ep_sys_init(void)
{
	int rv;

	if ((rv = nni_idhash_init(&nni_eps)) != 0) {
		return (rv);
	}
	nni_mtx_init(&nni_ep_lk);
	nni_idhash_set_limits(
	    nni_eps, 1, 0x7fffffff, nni_random() & 0x7fffffff);

	return (0);
}

void
nni_ep_sys_fini(void)
{
	nni_mtx_fini(&nni_ep_lk);
	nni_idhash_fini(nni_eps);
	nni_eps = NULL;
}

uint32_t
nni_ep_id(nni_ep *ep)
{
	return ((uint32_t) ep->ep_id);
}

static void
nni_ep_destroy(nni_ep *ep)
{
	if (ep == NULL) {
		return;
	}

	// Remove us from the table so we cannot be found.
	if (ep->ep_id != 0) {
		nni_idhash_remove(nni_eps, ep->ep_id);
	}

	nni_aio_stop(ep->ep_acc_aio);
	nni_aio_stop(ep->ep_con_aio);
	nni_aio_stop(ep->ep_con_syn);
	nni_aio_stop(ep->ep_tmo_aio);

	nni_sock_ep_remove(ep->ep_sock, ep);

	nni_aio_fini(ep->ep_acc_aio);
	nni_aio_fini(ep->ep_con_aio);
	nni_aio_fini(ep->ep_con_syn);
	nni_aio_fini(ep->ep_tmo_aio);

	nni_mtx_lock(&ep->ep_mtx);
	if (ep->ep_data != NULL) {
		ep->ep_ops.ep_fini(ep->ep_data);
	}
	nni_mtx_unlock(&ep->ep_mtx);
	nni_cv_fini(&ep->ep_cv);
	nni_mtx_fini(&ep->ep_mtx);
	nni_url_free(ep->ep_url);
	NNI_FREE_STRUCT(ep);
}

static int
nni_ep_create(nni_ep **epp, nni_sock *s, const char *urlstr, int mode)
{
	nni_tran *tran;
	nni_ep *  ep;
	int       rv;
	nni_url * url;

	if ((rv = nni_url_parse(&url, urlstr)) != 0) {
		return (rv);
	}
	if ((tran = nni_tran_find(url)) == NULL) {
		nni_url_free(url);
		return (NNG_ENOTSUP);
	}

	if ((ep = NNI_ALLOC_STRUCT(ep)) == NULL) {
		nni_url_free(url);
		return (NNG_ENOMEM);
	}
	ep->ep_url     = url;
	ep->ep_closed  = false;
	ep->ep_closing = false;
	ep->ep_started = false;
	ep->ep_data    = NULL;
	ep->ep_refcnt  = 1;
	ep->ep_sock    = s;
	ep->ep_tran    = tran;
	ep->ep_mode    = mode;

	// Make a copy of the endpoint operations.  This allows us to
	// modify them (to override NULLs for example), and avoids an extra
	// dereference on hot paths.
	ep->ep_ops = *tran->tran_ep;

	NNI_LIST_NODE_INIT(&ep->ep_node);

	nni_pipe_ep_list_init(&ep->ep_pipes);

	nni_mtx_init(&ep->ep_mtx);
	nni_cv_init(&ep->ep_cv, &ep->ep_mtx);

	if (((rv = nni_aio_init(&ep->ep_acc_aio, nni_ep_acc_cb, ep)) != 0) ||
	    ((rv = nni_aio_init(&ep->ep_con_aio, nni_ep_con_cb, ep)) != 0) ||
	    ((rv = nni_aio_init(&ep->ep_tmo_aio, nni_ep_tmo_cb, ep)) != 0) ||
	    ((rv = nni_aio_init(&ep->ep_con_syn, NULL, NULL)) != 0) ||
	    ((rv = ep->ep_ops.ep_init(&ep->ep_data, url, s, mode)) != 0) ||
	    ((rv = nni_idhash_alloc(nni_eps, &ep->ep_id, ep)) != 0) ||
	    ((rv = nni_sock_ep_add(s, ep)) != 0)) {
		nni_ep_destroy(ep);
		return (rv);
	}

	*epp = ep;
	return (0);
}

int
nni_ep_create_dialer(nni_ep **epp, nni_sock *s, const char *urlstr)
{
	return (nni_ep_create(epp, s, urlstr, NNI_EP_MODE_DIAL));
}

int
nni_ep_create_listener(nni_ep **epp, nni_sock *s, const char *urlstr)
{
	return (nni_ep_create(epp, s, urlstr, NNI_EP_MODE_LISTEN));
}

int
nni_ep_find(nni_ep **epp, uint32_t id)
{
	int     rv;
	nni_ep *ep;

	if ((rv = nni_init()) != 0) {
		return (rv);
	}

	nni_mtx_lock(&nni_ep_lk);
	if ((rv = nni_idhash_find(nni_eps, id, (void **) &ep)) == 0) {
		if (ep->ep_closed) {
			rv = NNG_ECLOSED;
		} else {
			ep->ep_refcnt++;
			*epp = ep;
		}
	}
	nni_mtx_unlock(&nni_ep_lk);
	return (rv);
}

int
nni_ep_hold(nni_ep *ep)
{
	int rv;
	nni_mtx_lock(&nni_ep_lk);
	if (ep->ep_closed) {
		rv = NNG_ECLOSED;
	} else {
		ep->ep_refcnt++;
		rv = 0;
	}
	nni_mtx_unlock(&nni_ep_lk);
	return (rv);
}

void
nni_ep_rele(nni_ep *ep)
{
	nni_mtx_lock(&nni_ep_lk);
	ep->ep_refcnt--;
	if (ep->ep_closing) {
		nni_cv_wake(&ep->ep_cv);
	}
	nni_mtx_unlock(&nni_ep_lk);
}

int
nni_ep_shutdown(nni_ep *ep)
{
	nni_mtx_lock(&ep->ep_mtx);
	if (ep->ep_closing) {
		nni_mtx_unlock(&ep->ep_mtx);
		return (NNG_ECLOSED);
	}
	ep->ep_closing = true;
	nni_mtx_unlock(&ep->ep_mtx);

	// Abort any remaining in-flight operations.
	nni_aio_stop(ep->ep_acc_aio);
	nni_aio_stop(ep->ep_con_aio);
	nni_aio_stop(ep->ep_con_syn);
	nni_aio_stop(ep->ep_tmo_aio);

	// Stop the underlying transport.
	ep->ep_ops.ep_close(ep->ep_data);

	return (0);
}

void
nni_ep_close(nni_ep *ep)
{
	nni_pipe *p;

	nni_mtx_lock(&ep->ep_mtx);
	if (ep->ep_closed) {
		nni_mtx_unlock(&ep->ep_mtx);
		nni_ep_rele(ep);
		return;
	}
	ep->ep_closed = true;
	nni_mtx_unlock(&ep->ep_mtx);

	nni_ep_shutdown(ep);

	nni_aio_stop(ep->ep_acc_aio);
	nni_aio_stop(ep->ep_con_aio);
	nni_aio_stop(ep->ep_con_syn);
	nni_aio_stop(ep->ep_tmo_aio);

	nni_mtx_lock(&ep->ep_mtx);
	NNI_LIST_FOREACH (&ep->ep_pipes, p) {
		nni_pipe_stop(p);
	}
	while ((!nni_list_empty(&ep->ep_pipes)) || (ep->ep_refcnt != 1)) {
		nni_cv_wait(&ep->ep_cv);
	}
	nni_mtx_unlock(&ep->ep_mtx);

	nni_ep_destroy(ep);
}

static void
nni_ep_tmo_cancel(nni_aio *aio, int rv)
{
	nni_ep *ep = nni_aio_get_prov_data(aio);
	// The only way this ever gets "finished", is via cancellation.
	if (ep != NULL) {
		nni_mtx_lock(&ep->ep_mtx);
		if (ep->ep_tmo_run) {
			nni_aio_finish_error(aio, rv);
		}
		ep->ep_tmo_run = false;
		nni_mtx_unlock(&ep->ep_mtx);
	}
}

static void
nni_ep_tmo_start(nni_ep *ep)
{
	nni_duration backoff;
	int          rv;

	if (ep->ep_closing || (nni_aio_begin(ep->ep_tmo_aio) != 0)) {
		return;
	}
	backoff = ep->ep_currtime;
	ep->ep_currtime *= 2;
	if (ep->ep_currtime > ep->ep_maxrtime) {
		ep->ep_currtime = ep->ep_maxrtime;
	}

	// To minimize damage from storms, etc., we select a backoff
	// value randomly, in the range of [0, backoff-1]; this is
	// pretty similar to 802 style backoff, except that we have a
	// nearly uniform time period instead of discrete slot times.
	// This algorithm may lead to slight biases because we don't
	// have a statistically perfect distribution with the modulo of
	// the random number, but this really doesn't matter.

	nni_aio_set_timeout(
	    ep->ep_tmo_aio, (backoff ? nni_random() % backoff : 0));

	if ((rv = nni_aio_schedule(ep->ep_tmo_aio, nni_ep_tmo_cancel, ep)) !=
	    0) {
		nni_aio_finish_error(ep->ep_tmo_aio, rv);
	}

	ep->ep_tmo_run = true;
}

static void
nni_ep_tmo_cb(void *arg)
{
	nni_ep * ep  = arg;
	nni_aio *aio = ep->ep_tmo_aio;

	nni_mtx_lock(&ep->ep_mtx);
	if (nni_aio_result(aio) == NNG_ETIMEDOUT) {
		if (ep->ep_mode == NNI_EP_MODE_DIAL) {
			nni_ep_con_start(ep);
		} else {
			nni_ep_acc_start(ep);
		}
	}
	nni_mtx_unlock(&ep->ep_mtx);
}

static void
nni_ep_con_cb(void *arg)
{
	nni_ep * ep  = arg;
	nni_aio *aio = ep->ep_con_aio;
	int      rv;

	if ((rv = nni_aio_result(aio)) == 0) {
		rv = nni_pipe_create(ep, nni_aio_get_output(aio, 0));
	}
	nni_mtx_lock(&ep->ep_mtx);
	switch (rv) {
	case 0:
		// Good connect, so reset the backoff timer.
		// Note that a host that accepts the connect, but drops
		// us immediately, is going to get hit pretty hard
		// (depending on the initial backoff) with no
		// exponential backoff. This can happen if we wind up
		// trying to connect to some port that does not speak
		// SP for example.
		ep->ep_currtime = ep->ep_inirtime;

		// No further outgoing connects -- we will restart a
		// connection from the pipe when the pipe is removed.
		break;
	case NNG_ECLOSED:
	case NNG_ECANCELED:
		// Canceled/closed -- stop everything.
		break;
	default:
		// Other errors involve the use of the backoff timer.
		nni_ep_tmo_start(ep);
		break;
	}
	nni_mtx_unlock(&ep->ep_mtx);
}

static void
nni_ep_con_start(nni_ep *ep)
{
	nni_aio *aio = ep->ep_con_aio;

	// Call with the Endpoint lock held.
	if (ep->ep_closing) {
		return;
	}

	ep->ep_ops.ep_connect(ep->ep_data, aio);
}

int
nni_ep_dial(nni_ep *ep, int flags)
{
	int      rv = 0;
	nni_aio *aio;

	nni_sock_reconntimes(ep->ep_sock, &ep->ep_inirtime, &ep->ep_maxrtime);
	ep->ep_currtime = ep->ep_inirtime;

	nni_mtx_lock(&ep->ep_mtx);

	if (ep->ep_mode != NNI_EP_MODE_DIAL) {
		nni_mtx_unlock(&ep->ep_mtx);
		return (NNG_ENOTSUP);
	}
	if (ep->ep_closing) {
		nni_mtx_unlock(&ep->ep_mtx);
		return (NNG_ECLOSED);
	}

	if (ep->ep_started) {
		nni_mtx_unlock(&ep->ep_mtx);
		return (NNG_ESTATE);
	}

	if ((flags & NNG_FLAG_NONBLOCK) != 0) {
		ep->ep_started = true;
		nni_ep_con_start(ep);
		nni_mtx_unlock(&ep->ep_mtx);
		return (0);
	}

	// Synchronous mode: so we have to wait for it to complete.
	aio = ep->ep_con_syn;
	ep->ep_ops.ep_connect(ep->ep_data, aio);
	ep->ep_started = true;
	nni_mtx_unlock(&ep->ep_mtx);

	nni_aio_wait(aio);

	// As we're synchronous, we also have to handle the completion.
	if (((rv = nni_aio_result(aio)) != 0) ||
	    ((rv = nni_pipe_create(ep, nni_aio_get_output(aio, 0))) != 0)) {
		nni_mtx_lock(&ep->ep_mtx);
		ep->ep_started = false;
		nni_mtx_unlock(&ep->ep_mtx);
	}
	return (rv);
}

static void
nni_ep_acc_cb(void *arg)
{
	nni_ep * ep  = arg;
	nni_aio *aio = ep->ep_acc_aio;
	int      rv;

	if ((rv = nni_aio_result(aio)) == 0) {
		NNI_ASSERT(nni_aio_get_output(aio, 0) != NULL);
		rv = nni_pipe_create(ep, nni_aio_get_output(aio, 0));
	}

	nni_mtx_lock(&ep->ep_mtx);
	switch (rv) {
	case 0:
		nni_ep_acc_start(ep);
		break;
	case NNG_ECLOSED:
	case NNG_ECANCELED:
		// Canceled or closed, no further action.
		break;
	case NNG_ECONNABORTED:
	case NNG_ECONNRESET:
		// These are remote conditions, no cool down.
		nni_ep_acc_start(ep);
		break;
	default:
		// We don't really know why we failed, but we backoff
		// here. This is because errors here are probably due
		// to system failures (resource exhaustion) and we hope
		// by not thrashing we give the system a chance to
		// recover.
		nni_ep_tmo_start(ep);
		break;
	}
	nni_mtx_unlock(&ep->ep_mtx);
}

static void
nni_ep_acc_start(nni_ep *ep)
{
	nni_aio *aio = ep->ep_acc_aio;

	// Call with the Endpoint lock held.
	if (ep->ep_closing) {
		return;
	}
	ep->ep_ops.ep_accept(ep->ep_data, aio);
}

int
nni_ep_listen(nni_ep *ep, int flags)
{
	int rv = 0;
	NNI_ARG_UNUSED(flags);

	nni_sock_reconntimes(ep->ep_sock, &ep->ep_inirtime, &ep->ep_maxrtime);
	ep->ep_currtime = ep->ep_inirtime;

	nni_mtx_lock(&ep->ep_mtx);
	if (ep->ep_mode != NNI_EP_MODE_LISTEN) {
		nni_mtx_unlock(&ep->ep_mtx);
		return (NNG_ENOTSUP);
	}
	if (ep->ep_closing) {
		nni_mtx_unlock(&ep->ep_mtx);
		return (NNG_ECLOSED);
	}
	if (ep->ep_started) {
		nni_mtx_unlock(&ep->ep_mtx);
		return (NNG_ESTATE);
	}

	rv = ep->ep_ops.ep_bind(ep->ep_data);
	if (rv != 0) {
		nni_mtx_unlock(&ep->ep_mtx);
		return (rv);
	}

	ep->ep_started = true;
	nni_ep_acc_start(ep);
	nni_mtx_unlock(&ep->ep_mtx);

	return (0);
}

int
nni_ep_pipe_add(nni_ep *ep, nni_pipe *p)
{
	nni_mtx_lock(&ep->ep_mtx);
	if (ep->ep_closing) {
		nni_mtx_unlock(&ep->ep_mtx);
		return (NNG_ECLOSED);
	}
	nni_list_append(&ep->ep_pipes, p);
	nni_mtx_unlock(&ep->ep_mtx);
	return (0);
}

void
nni_ep_pipe_remove(nni_ep *ep, nni_pipe *pipe)
{
	// Break up the relationship between the EP and the pipe.
	nni_mtx_lock(&ep->ep_mtx);
	// During early init, the pipe might not have this set.
	if (nni_list_active(&ep->ep_pipes, pipe)) {
		nni_list_remove(&ep->ep_pipes, pipe);
	}
	// Wake up the close thread if it is waiting.
	if (ep->ep_closed && nni_list_empty(&ep->ep_pipes)) {
		nni_cv_wake(&ep->ep_cv);
	}

	// If this pipe closed, then lets restart the dial operation.
	// Since the remote side seems to have closed, lets start with
	// a backoff.  This keeps us from pounding the crap out of the
	// thing if a remote server accepts but then disconnects
	// immediately.
	if ((!ep->ep_closed) && (ep->ep_mode == NNI_EP_MODE_DIAL)) {
		nni_ep_tmo_start(ep);
	}
	nni_mtx_unlock(&ep->ep_mtx);
}

int
nni_ep_setopt(nni_ep *ep, const char *name, const void *val, size_t sz, int t)
{
	nni_tran_ep_option *eo;

	if (strcmp(name, NNG_OPT_URL) == 0) {
		return (NNG_EREADONLY);
	}

	for (eo = ep->ep_ops.ep_options; eo && eo->eo_name; eo++) {
		int rv;

		if (strcmp(eo->eo_name, name) != 0) {
			continue;
		}
		if (eo->eo_setopt == NULL) {
			return (NNG_EREADONLY);
		}

		nni_mtx_lock(&ep->ep_mtx);
		rv = eo->eo_setopt(ep->ep_data, val, sz, t);
		nni_mtx_unlock(&ep->ep_mtx);
		return (rv);
	}

	return (NNG_ENOTSUP);
}

int
nni_ep_mode(nni_ep *ep)
{
	return (ep->ep_mode);
}

int
nni_ep_opttype(nni_ep *ep, const char *name, int *tp)
{
	nni_tran_ep_option *eo;

	for (eo = ep->ep_ops.ep_options; eo && eo->eo_name; eo++) {
		if (strcmp(eo->eo_name, name) == 0) {
			*tp = eo->eo_type;
			return (0);
		}
	}
	if (strcmp(name, NNG_OPT_URL) == 0) {
		*tp = NNI_TYPE_STRING;
		return (0);
	}
	return (NNG_ENOTSUP);
}

int
nni_ep_getopt(nni_ep *ep, const char *name, void *valp, size_t *szp, int t)
{
	nni_tran_ep_option *eo;

	for (eo = ep->ep_ops.ep_options; eo && eo->eo_name; eo++) {
		int rv;
		if (strcmp(eo->eo_name, name) != 0) {
			continue;
		}
		if (eo->eo_getopt == NULL) {
			return (NNG_EWRITEONLY);
		}
		nni_mtx_lock(&ep->ep_mtx);
		rv = eo->eo_getopt(ep->ep_data, valp, szp, t);
		nni_mtx_unlock(&ep->ep_mtx);
		return (rv);
	}

	// We provide a fallback on the URL, but let the implementation
	// override.  This allows the URL to be created with wildcards,
	// that are resolved later.
	if (strcmp(name, NNG_OPT_URL) == 0) {
		return (nni_copyout_str(ep->ep_url->u_rawurl, valp, szp, t));
	}

	return (nni_sock_getopt(ep->ep_sock, name, valp, szp, t));
}

void
nni_ep_list_init(nni_list *list)
{
	NNI_LIST_INIT(list, nni_ep, ep_node);
}

nni_tran *
nni_ep_tran(nni_ep *ep)
{
	return (ep->ep_tran);
}

nni_sock *
nni_ep_sock(nni_ep *ep)
{
	return (ep->ep_sock);
}
