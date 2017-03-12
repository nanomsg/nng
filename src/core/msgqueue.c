//
// Copyright 2017 Garrett D'Amore <garrett@damore.org>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "nng_impl.h"

// Message queue.  These operate in some respects like Go channels,
// but as we have access to the internals, we have made some fundamental
// differences and improvements.  For example, these can grow, and either
// side can close, and they may be closed more than once.

struct nni_msgq {
	nni_mtx		mq_lock;
	nni_cv		mq_drained;
	int		mq_cap;
	int		mq_alloc;         // alloc is cap + 2...
	int		mq_len;
	int		mq_get;
	int		mq_put;
	int		mq_closed;
	int		mq_puterr;
	int		mq_geterr;
	int		mq_draining;
	nni_msg **	mq_msgs;

	nni_list	mq_aio_putq;
	nni_list	mq_aio_getq;
	nni_list	mq_aio_notify_get;
	nni_list	mq_aio_notify_put;

	nni_timer_node	mq_timer;
	nni_time	mq_expire;
};


static void nni_msgq_run_timeout(void *);

int
nni_msgq_init(nni_msgq **mqp, int cap)
{
	struct nni_msgq *mq;
	int rv;
	int alloc;

	if (cap < 0) {
		return (NNG_EINVAL);
	}

	// We allocate 2 extra cells in the fifo.  One to accommodate a
	// waiting writer when cap == 0. (We can "briefly" move the message
	// through.)  This lets us behave the same as unbuffered Go channels.
	// The second cell is to permit pushback later, e.g. for REQ to stash
	// a message back at the end to do a retry.
	alloc = cap + 2;

	if ((mq = NNI_ALLOC_STRUCT(mq)) == NULL) {
		return (NNG_ENOMEM);
	}
	NNI_LIST_INIT(&mq->mq_aio_putq, nni_aio, a_prov_node);
	NNI_LIST_INIT(&mq->mq_aio_getq, nni_aio, a_prov_node);
	NNI_LIST_INIT(&mq->mq_aio_notify_get, nni_aio, a_prov_node);
	NNI_LIST_INIT(&mq->mq_aio_notify_put, nni_aio, a_prov_node);

	if ((rv = nni_mtx_init(&mq->mq_lock)) != 0) {
		goto fail;
	}
	if ((rv = nni_cv_init(&mq->mq_drained, &mq->mq_lock)) != 0) {
		goto fail;
	}
	if ((mq->mq_msgs = nni_alloc(sizeof (nng_msg *) * alloc)) == NULL) {
		rv = NNG_ENOMEM;
		goto fail;
	}

	nni_timer_init(&mq->mq_timer, nni_msgq_run_timeout, mq);

	mq->mq_cap = cap;
	mq->mq_alloc = alloc;
	mq->mq_len = 0;
	mq->mq_get = 0;
	mq->mq_put = 0;
	mq->mq_closed = 0;
	mq->mq_puterr = 0;
	mq->mq_geterr = 0;
	mq->mq_expire = NNI_TIME_NEVER;
	mq->mq_draining = 0;
	*mqp = mq;

	return (0);

fail:
	nni_cv_fini(&mq->mq_drained);
	nni_mtx_fini(&mq->mq_lock);
	if (mq->mq_msgs != NULL) {
		nni_free(mq->mq_msgs, sizeof (nng_msg *) * alloc);
	}
	NNI_FREE_STRUCT(mq);
	return (rv);
}


void
nni_msgq_fini(nni_msgq *mq)
{
	nni_msg *msg;

	if (mq == NULL) {
		return;
	}
	nni_timer_cancel(&mq->mq_timer);
	nni_cv_fini(&mq->mq_drained);
	nni_mtx_fini(&mq->mq_lock);

	/* Free any orphaned messages. */
	while (mq->mq_len > 0) {
		msg = mq->mq_msgs[mq->mq_get];
		mq->mq_get++;
		if (mq->mq_get > mq->mq_alloc) {
			mq->mq_get = 0;
		}
		mq->mq_len--;
		nni_msg_free(msg);
	}

	nni_free(mq->mq_msgs, mq->mq_alloc * sizeof (nng_msg *));
	NNI_FREE_STRUCT(mq);
}


void
nni_msgq_set_get_error(nni_msgq *mq, int error)
{
	nni_aio *naio;
	nni_aio *aio;

	// Let all pending blockers know we are closing the queue.
	nni_mtx_lock(&mq->mq_lock);
	if (error != 0) {
		naio = nni_list_first(&mq->mq_aio_getq);
		while ((aio = naio) != NULL) {
			naio = nni_list_next(&mq->mq_aio_getq, aio);
			nni_list_remove(&mq->mq_aio_getq, aio);
			nni_aio_finish(aio, error, 0);
		}
	}
	mq->mq_geterr = error;
	nni_mtx_unlock(&mq->mq_lock);
}


void
nni_msgq_set_put_error(nni_msgq *mq, int error)
{
	nni_aio *naio;
	nni_aio *aio;

	// Let all pending blockers know we are closing the queue.
	nni_mtx_lock(&mq->mq_lock);
	if (error != 0) {
		naio = nni_list_first(&mq->mq_aio_putq);
		while ((aio = naio) != NULL) {
			naio = nni_list_next(&mq->mq_aio_getq, aio);
			nni_list_remove(&mq->mq_aio_getq, aio);
			nni_aio_finish(aio, error, 0);
		}
	}
	mq->mq_puterr = error;
	nni_mtx_unlock(&mq->mq_lock);
}


void
nni_msgq_set_error(nni_msgq *mq, int error)
{
	nni_aio *naio;
	nni_aio *aio;

	// Let all pending blockers know we are closing the queue.
	nni_mtx_lock(&mq->mq_lock);
	if (error != 0) {
		naio = nni_list_first(&mq->mq_aio_getq);
		while ((aio = naio) != NULL) {
			naio = nni_list_next(&mq->mq_aio_getq, aio);
			nni_list_remove(&mq->mq_aio_getq, aio);
			nni_aio_finish(aio, error, 0);
		}
		naio = nni_list_first(&mq->mq_aio_putq);
		while ((aio = naio) != NULL) {
			naio = nni_list_next(&mq->mq_aio_getq, aio);
			nni_list_remove(&mq->mq_aio_getq, aio);
			nni_aio_finish(aio, error, 0);
		}
	}
	mq->mq_puterr = error;
	mq->mq_geterr = error;
	nni_mtx_unlock(&mq->mq_lock);
}


static void
nni_msgq_run_putq(nni_msgq *mq)
{
	nni_aio *waio;
	nni_aio *raio;
	nni_msg *msg;
	size_t len;

	while ((waio = nni_list_first(&mq->mq_aio_putq)) != NULL) {
		msg = waio->a_msg;
		len = nni_msg_len(msg);

		// The presence of any blocked reader indicates that
		// the queue is empty, otherwise it would have just taken
		// data from the queue.
		if ((raio = nni_list_first(&mq->mq_aio_getq)) != NULL) {
			nni_list_remove(&mq->mq_aio_getq, raio);
			nni_list_remove(&mq->mq_aio_putq, waio);

			raio->a_msg = msg;
			waio->a_msg = NULL;

			nni_aio_finish(raio, 0, len);
			nni_aio_finish(waio, 0, len);
			continue;
		}

		// Otherwise if we have room in the buffer, just queue it.
		if (mq->mq_len < mq->mq_cap) {
			nni_list_remove(&mq->mq_aio_putq, waio);
			mq->mq_msgs[mq->mq_put++] = msg;
			if (mq->mq_put == mq->mq_alloc) {
				mq->mq_put = 0;
			}
			mq->mq_len++;
			waio->a_msg = NULL;
			nni_aio_finish(waio, 0, len);
			continue;
		}

		// Unable to make progress, leave the aio where it is.
		break;
	}
}


static void
nni_msgq_run_getq(nni_msgq *mq)
{
	nni_aio *raio;
	nni_aio *waio;
	nni_msg *msg;
	size_t len;

	while ((raio = nni_list_first(&mq->mq_aio_getq)) != NULL) {
		// If anything is waiting in the queue, get it first.
		if (mq->mq_len != 0) {
			nni_list_remove(&mq->mq_aio_getq, raio);
			msg = mq->mq_msgs[mq->mq_get++];
			if (mq->mq_get == mq->mq_alloc) {
				mq->mq_get = 0;
			}
			mq->mq_len--;
			len = nni_msg_len(msg);
			raio->a_msg = msg;
			nni_aio_finish(raio, 0, len);
			continue;
		}

		// Nothing queued (unbuffered?), maybe a writer is waiting.
		if ((waio = nni_list_first(&mq->mq_aio_putq)) != NULL) {
			nni_list_remove(&mq->mq_aio_putq, waio);
			nni_list_remove(&mq->mq_aio_getq, raio);

			msg = waio->a_msg;
			len = nni_msg_len(msg);
			waio->a_msg = NULL;
			raio->a_msg = msg;
			nni_aio_finish(raio, 0, len);
			nni_aio_finish(waio, 0, len);
			continue;
		}

		// No data to get, and no unbuffered writers waiting.  Just
		// wait until something arrives.
		break;
	}
}


static void
nni_msgq_run_notify(nni_msgq *mq)
{
	nni_aio *aio;

	if (mq->mq_closed) {
		return;
	}
	if ((mq->mq_len < mq->mq_cap) ||
	    (nni_list_first(&mq->mq_aio_getq) != NULL)) {
		NNI_LIST_FOREACH (&mq->mq_aio_notify_put, aio) {
			// This stays on the list.
			nni_aio_finish(aio, 0, 0);
		}
	}

	if ((mq->mq_len != 0) || (nni_list_first(&mq->mq_aio_putq) != NULL)) {
		NNI_LIST_FOREACH (&mq->mq_aio_notify_get, aio) {
			nni_aio_finish(aio, 0, 0);
		}
	}

	if (mq->mq_draining) {
		if ((mq->mq_len == 0) &&
		    (nni_list_first(&mq->mq_aio_putq) == NULL)) {
			nni_cv_wake(&mq->mq_drained);
		}
	}
}


void
nni_msgq_aio_notify_put(nni_msgq *mq, nni_aio *aio)
{
	nni_mtx_lock(&mq->mq_lock);
	if (nni_list_active(&mq->mq_aio_notify_put, aio)) {
		nni_list_remove(&mq->mq_aio_notify_put, aio);
	}
	nni_list_append(&mq->mq_aio_notify_put, aio);
	nni_mtx_unlock(&mq->mq_lock);
}


void
nni_msgq_aio_notify_get(nni_msgq *mq, nni_aio *aio)
{
	nni_mtx_lock(&mq->mq_lock);
	if (nni_list_active(&mq->mq_aio_notify_get, aio)) {
		nni_list_remove(&mq->mq_aio_notify_get, aio);
	}
	nni_list_append(&mq->mq_aio_notify_get, aio);
	nni_mtx_unlock(&mq->mq_lock);
}


void
nni_msgq_aio_put(nni_msgq *mq, nni_aio *aio)
{
	nni_time expire = aio->a_expire;

	nni_mtx_lock(&mq->mq_lock);
	if (mq->mq_closed) {
		nni_aio_finish(aio, NNG_ECLOSED, 0);
		nni_mtx_unlock(&mq->mq_lock);
		return;
	}
	if (mq->mq_puterr) {
		nni_aio_finish(aio, mq->mq_puterr, 0);
		nni_mtx_unlock(&mq->mq_lock);
		return;
	}
	nni_list_append(&mq->mq_aio_putq, aio);
	nni_msgq_run_putq(mq);
	nni_msgq_run_notify(mq);

	if (expire < mq->mq_expire) {
		mq->mq_expire = expire;
		nni_timer_schedule(&mq->mq_timer, mq->mq_expire);
	}
	nni_mtx_unlock(&mq->mq_lock);
}


void
nni_msgq_aio_get(nni_msgq *mq, nni_aio *aio)
{
	nni_time expire = aio->a_expire;

	nni_mtx_lock(&mq->mq_lock);
	if (mq->mq_closed) {
		nni_aio_finish(aio, NNG_ECLOSED, 0);
		nni_mtx_unlock(&mq->mq_lock);
		return;
	}
	if (mq->mq_geterr) {
		nni_aio_finish(aio, mq->mq_geterr, 0);
		nni_mtx_unlock(&mq->mq_lock);
		return;
	}
	nni_list_append(&mq->mq_aio_getq, aio);
	nni_msgq_run_getq(mq);
	nni_msgq_run_notify(mq);

	if (expire < mq->mq_expire) {
		mq->mq_expire = expire;
		nni_timer_schedule(&mq->mq_timer, mq->mq_expire);
	}
	nni_mtx_unlock(&mq->mq_lock);
}


void
nni_msgq_aio_cancel(nni_msgq *mq, nni_aio *aio)
{
	nni_mtx_lock(&mq->mq_lock);
	// NB: nni_list_active and nni_list_remove only use the list structure
	// to determine list node offsets.  Otherwise, they only look at the
	// node's linkage structure.  Therefore the following check will remove
	// the node from either the getq or the putq list.
	if (nni_list_active(&mq->mq_aio_getq, aio)) {
		nni_list_remove(&mq->mq_aio_getq, aio);
		nni_aio_finish(aio, NNG_ECANCELED, 0);
	}
	nni_mtx_unlock(&mq->mq_lock);
}


int
nni_msgq_canput(nni_msgq *mq)
{
	nni_mtx_lock(&mq->mq_lock);
	if (mq->mq_closed) {
		nni_mtx_unlock(&mq->mq_lock);
		return (0);
	}
	if ((mq->mq_len < mq->mq_cap) ||
	    (nni_list_first(&mq->mq_aio_getq) != NULL)) {
		nni_mtx_unlock(&mq->mq_lock);
		return (1);
	}
	nni_mtx_unlock(&mq->mq_lock);
	return (0);
}


int
nni_msgq_canget(nni_msgq *mq)
{
	nni_mtx_lock(&mq->mq_lock);
	if (mq->mq_closed) {
		nni_mtx_unlock(&mq->mq_lock);
		return (0);
	}
	if ((mq->mq_len != 0) ||
	    (nni_list_first(&mq->mq_aio_putq) != NULL)) {
		nni_mtx_unlock(&mq->mq_lock);
		return (1);
	}
	nni_mtx_unlock(&mq->mq_lock);
	return (0);
}


int
nni_msgq_tryput(nni_msgq *mq, nni_msg *msg)
{
	nni_aio *raio;
	size_t len = nni_msg_len(msg);

	nni_mtx_lock(&mq->mq_lock);
	if (mq->mq_closed) {
		nni_mtx_unlock(&mq->mq_lock);
		return (NNG_ECLOSED);
	}

	// The presence of any blocked reader indicates that
	// the queue is empty, otherwise it would have just taken
	// data from the queue.
	if ((raio = nni_list_first(&mq->mq_aio_getq)) != NULL) {
		nni_list_remove(&mq->mq_aio_getq, raio);

		raio->a_msg = msg;

		nni_aio_finish(raio, 0, len);
		nni_mtx_unlock(&mq->mq_lock);
		return (0);
	}

	// Otherwise if we have room in the buffer, just queue it.
	if (mq->mq_len < mq->mq_cap) {
		mq->mq_msgs[mq->mq_put++] = msg;
		if (mq->mq_put == mq->mq_alloc) {
			mq->mq_put = 0;
		}
		mq->mq_len++;
		nni_mtx_unlock(&mq->mq_lock);
		return (0);
	}

	nni_mtx_unlock(&mq->mq_lock);
	return (NNG_EAGAIN);
}


void
nni_msgq_run_timeout(void *arg)
{
	nni_msgq *mq = arg;
	nni_time now;
	nni_time exp;
	nni_aio *aio;
	nni_aio *naio;
	int rv;

	now = nni_clock();
	exp = NNI_TIME_NEVER;

	nni_mtx_lock(&mq->mq_lock);
	naio = nni_list_first(&mq->mq_aio_getq);
	while ((aio = naio) != NULL) {
		naio = nni_list_next(&mq->mq_aio_getq, aio);
		if (aio->a_expire == NNI_TIME_ZERO) {
			nni_list_remove(&mq->mq_aio_getq, aio);
			nni_aio_finish(aio, NNG_EAGAIN, 0);
		} else if (now >= aio->a_expire) {
			nni_list_remove(&mq->mq_aio_getq, aio);
			nni_aio_finish(aio, NNG_ETIMEDOUT, 0);
		} else if (exp > aio->a_expire) {
			exp = aio->a_expire;
		}
	}

	naio = nni_list_first(&mq->mq_aio_putq);
	while ((aio = naio) != NULL) {
		naio = nni_list_next(&mq->mq_aio_putq, aio);
		if (aio->a_expire == NNI_TIME_ZERO) {
			nni_list_remove(&mq->mq_aio_putq, aio);
			nni_aio_finish(aio, NNG_EAGAIN, 0);
		} else if (now >= aio->a_expire) {
			nni_list_remove(&mq->mq_aio_putq, aio);
			nni_aio_finish(aio, NNG_ETIMEDOUT, 0);
		} else if (exp > aio->a_expire) {
			exp = aio->a_expire;
		}
	}

	mq->mq_expire = exp;
	if (mq->mq_expire != NNI_TIME_NEVER) {
		nni_timer_schedule(&mq->mq_timer, mq->mq_expire);
	}
	nni_mtx_unlock(&mq->mq_lock);
}


int
nni_msgq_get_until(nni_msgq *mq, nni_msg **msgp, nni_time expire)
{
	nni_aio aio;
	int rv;

	if ((rv = nni_aio_init(&aio, NULL, NULL)) != 0) {
		return (rv);
	}
	aio.a_expire = expire;
	nni_msgq_aio_get(mq, &aio);
	nni_aio_wait(&aio);
	if ((rv = nni_aio_result(&aio)) == 0) {
		*msgp = aio.a_msg;
		aio.a_msg = NULL;
	}
	nni_aio_fini(&aio);
	return (rv);
}


int
nni_msgq_get(nni_msgq *mq, nni_msg **msgp)
{
	return (nni_msgq_get_until(mq, msgp, NNI_TIME_NEVER));
}


int
nni_msgq_put_until(nni_msgq *mq, nni_msg *msg, nni_time expire)
{
	nni_aio aio;
	int rv;

	if ((rv = nni_aio_init(&aio, NULL, NULL)) != 0) {
		return (rv);
	}
	aio.a_expire = expire;
	aio.a_msg = msg;
	nni_msgq_aio_put(mq, &aio);
	nni_aio_wait(&aio);
	rv = nni_aio_result(&aio);
	nni_aio_fini(&aio);
	return (rv);
}


int
nni_msgq_put(nni_msgq *mq, nni_msg *msg)
{
	return (nni_msgq_put_until(mq, msg, NNI_TIME_NEVER));
}


void
nni_msgq_drain(nni_msgq *mq, nni_time expire)
{
	nni_aio *aio;

	nni_mtx_lock(&mq->mq_lock);
	mq->mq_closed = 1;
	mq->mq_draining = 1;
	while ((mq->mq_len > 0) || (nni_list_first(&mq->mq_aio_putq) != NULL)) {
		if (nni_cv_until(&mq->mq_drained, expire) != 0) {
			break;
		}
	}
	// If we timedout, free any remaining messages in the queue.
	// Also complete the putq as NNG_ECLOSED.

	while ((aio = nni_list_first(&mq->mq_aio_putq)) != NULL) {
		nni_list_remove(&mq->mq_aio_putq, aio);
		nni_aio_finish(aio, NNG_ECLOSED, 0);
	}
	while (mq->mq_len > 0) {
		nni_msg *msg = mq->mq_msgs[mq->mq_get++];
		if (mq->mq_get > mq->mq_alloc) {
			mq->mq_get = 0;
		}
		mq->mq_len--;
		nni_msg_free(msg);
	}
	nni_mtx_unlock(&mq->mq_lock);
}


void
nni_msgq_close(nni_msgq *mq)
{
	nni_aio *aio;
	nni_aio *naio;

	nni_mtx_lock(&mq->mq_lock);
	mq->mq_closed = 1;

	// Free the messages orphaned in the queue.
	while (mq->mq_len > 0) {
		nni_msg *msg = mq->mq_msgs[mq->mq_get++];
		if (mq->mq_get > mq->mq_alloc) {
			mq->mq_get = 0;
		}
		mq->mq_len--;
		nni_msg_free(msg);
	}

	// Let all pending blockers know we are closing the queue.
	naio = nni_list_first(&mq->mq_aio_getq);
	while ((aio = naio) != NULL) {
		naio = nni_list_next(&mq->mq_aio_getq, aio);
		nni_list_remove(&mq->mq_aio_getq, aio);
		nni_aio_finish(aio, NNG_ECLOSED, 0);
	}

	naio = nni_list_first(&mq->mq_aio_putq);
	while ((aio = naio) != NULL) {
		naio = nni_list_next(&mq->mq_aio_putq, aio);
		nni_list_remove(&mq->mq_aio_putq, aio);
		nni_aio_finish(aio, NNG_ECLOSED, 0);
	}

	nni_mtx_unlock(&mq->mq_lock);
}


int
nni_msgq_len(nni_msgq *mq)
{
	int rv;

	nni_mtx_lock(&mq->mq_lock);
	rv = mq->mq_len;
	nni_mtx_unlock(&mq->mq_lock);
	return (rv);
}


int
nni_msgq_cap(nni_msgq *mq)
{
	int rv;

	nni_mtx_lock(&mq->mq_lock);
	rv = mq->mq_cap;
	nni_mtx_unlock(&mq->mq_lock);
	return (rv);
}


int
nni_msgq_resize(nni_msgq *mq, int cap)
{
	int alloc;
	nni_msg *msg;
	nni_msg **newq, **oldq;
	int oldget;
	int oldput;
	int oldcap;
	int oldlen;
	int oldalloc;

	alloc = cap + 2;

	if (alloc > mq->mq_alloc) {
		newq = nni_alloc(sizeof (nni_msg *) * alloc);
		if (newq == NULL) {
			return (NNG_ENOMEM);
		}
	} else {
		newq = NULL;
	}

	nni_mtx_lock(&mq->mq_lock);
	while (mq->mq_len > (cap + 1)) {
		// too many messages -- we allow that one for
		// the case of pushback or cap == 0.
		// we delete the oldest messages first
		msg = mq->mq_msgs[mq->mq_get++];
		if (mq->mq_get > mq->mq_alloc) {
			mq->mq_get = 0;
		}
		mq->mq_len--;
		nni_msg_free(msg);
	}
	if (newq == NULL) {
		// Just shrinking the queue, no changes
		mq->mq_cap = cap;
		goto out;
	}

	oldq = mq->mq_msgs;
	oldget = mq->mq_get;
	oldput = mq->mq_put;
	oldcap = mq->mq_cap;
	oldalloc = mq->mq_alloc;
	oldlen = mq->mq_len;

	mq->mq_msgs = newq;
	mq->mq_len = mq->mq_get = mq->mq_put = 0;
	mq->mq_cap = cap;
	mq->mq_alloc = alloc;

	while (oldlen) {
		mq->mq_msgs[mq->mq_put++] = oldq[oldget++];
		if (oldget == oldalloc) {
			oldget = 0;
		}
		if (mq->mq_put == mq->mq_alloc) {
			mq->mq_put = 0;
		}
		mq->mq_len++;
		oldlen--;
	}
	nni_free(oldq, sizeof (nni_msg *) * oldalloc);

out:
	// Wake everyone up -- we changed everything.
	nni_cv_wake(&mq->mq_drained);
	nni_mtx_unlock(&mq->mq_lock);
	return (0);
}
