//
// Copyright 2017 Garrett D'Amore <garrett@damore.org>
// Copyright 2017 Capitar IT Group BV <info@capitar.com>
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
	nni_mtx   mq_lock;
	nni_cv    mq_drained;
	int       mq_cap;
	int       mq_alloc; // alloc is cap + 2...
	int       mq_len;
	int       mq_get;
	int       mq_put;
	int       mq_closed;
	int       mq_puterr;
	int       mq_geterr;
	int       mq_draining;
	nni_msg **mq_msgs;

	nni_list mq_aio_putq;
	nni_list mq_aio_getq;
	nni_list mq_aio_notify_get;
	nni_list mq_aio_notify_put;
};

int
nni_msgq_init(nni_msgq **mqp, unsigned cap)
{
	struct nni_msgq *mq;
	int              alloc;

	// We allocate 2 extra cells in the fifo.  One to accommodate a
	// waiting writer when cap == 0. (We can "briefly" move the message
	// through.)  This lets us behave the same as unbuffered Go channels.
	// The second cell is to permit pushback later, e.g. for REQ to stash
	// a message back at the end to do a retry.
	alloc = cap + 2;

	if ((mq = NNI_ALLOC_STRUCT(mq)) == NULL) {
		return (NNG_ENOMEM);
	}
	if ((mq->mq_msgs = nni_alloc(sizeof(nng_msg *) * alloc)) == NULL) {
		NNI_FREE_STRUCT(mq);
		return (NNG_ENOMEM);
	}

	nni_aio_list_init(&mq->mq_aio_putq);
	nni_aio_list_init(&mq->mq_aio_getq);
	nni_aio_list_init(&mq->mq_aio_notify_get);
	nni_aio_list_init(&mq->mq_aio_notify_put);

	nni_mtx_init(&mq->mq_lock);
	nni_cv_init(&mq->mq_drained, &mq->mq_lock);

	mq->mq_cap      = cap;
	mq->mq_alloc    = alloc;
	mq->mq_len      = 0;
	mq->mq_get      = 0;
	mq->mq_put      = 0;
	mq->mq_closed   = 0;
	mq->mq_puterr   = 0;
	mq->mq_geterr   = 0;
	mq->mq_draining = 0;
	*mqp            = mq;

	return (0);
}

void
nni_msgq_fini(nni_msgq *mq)
{
	nni_msg *msg;

	if (mq == NULL) {
		return;
	}
	nni_cv_fini(&mq->mq_drained);
	nni_mtx_fini(&mq->mq_lock);

	/* Free any orphaned messages. */
	while (mq->mq_len > 0) {
		msg = mq->mq_msgs[mq->mq_get];
		mq->mq_get++;
		if (mq->mq_get >= mq->mq_alloc) {
			mq->mq_get = 0;
		}
		mq->mq_len--;
		nni_msg_free(msg);
	}

	nni_free(mq->mq_msgs, mq->mq_alloc * sizeof(nng_msg *));
	NNI_FREE_STRUCT(mq);
}

void
nni_msgq_set_get_error(nni_msgq *mq, int error)
{
	nni_aio *aio;

	// Let all pending blockers know we are closing the queue.
	nni_mtx_lock(&mq->mq_lock);
	if (error != 0) {
		while ((aio = nni_list_first(&mq->mq_aio_getq)) != NULL) {
			nni_aio_list_remove(aio);
			nni_aio_finish_error(aio, error);
		}
	}
	mq->mq_geterr = error;
	nni_mtx_unlock(&mq->mq_lock);
}

void
nni_msgq_set_put_error(nni_msgq *mq, int error)
{
	nni_aio *aio;

	// Let all pending blockers know we are closing the queue.
	nni_mtx_lock(&mq->mq_lock);
	if (error != 0) {
		while ((aio = nni_list_first(&mq->mq_aio_putq)) != NULL) {
			nni_aio_list_remove(aio);
			nni_aio_finish_error(aio, error);
		}
	}
	mq->mq_puterr = error;
	nni_mtx_unlock(&mq->mq_lock);
}

void
nni_msgq_set_error(nni_msgq *mq, int error)
{
	nni_aio *aio;

	// Let all pending blockers know we are closing the queue.
	nni_mtx_lock(&mq->mq_lock);
	if (error != 0) {
		while (((aio = nni_list_first(&mq->mq_aio_getq)) != NULL) ||
		    ((aio = nni_list_first(&mq->mq_aio_putq)) != NULL)) {
			nni_aio_list_remove(aio);
			nni_aio_finish_error(aio, error);
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
	size_t   len;

	while ((waio = nni_list_first(&mq->mq_aio_putq)) != NULL) {
		msg = nni_aio_get_msg(waio);
		len = nni_msg_len(msg);

		// The presence of any blocked reader indicates that
		// the queue is empty, otherwise it would have just taken
		// data from the queue.
		if ((raio = nni_list_first(&mq->mq_aio_getq)) != NULL) {
			nni_aio_set_msg(waio, NULL);

			nni_aio_list_remove(raio);
			nni_aio_list_remove(waio);
			nni_aio_finish(waio, 0, len);
			nni_aio_finish_msg(raio, msg);
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
			nni_aio_set_msg(waio, NULL);
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

	while ((raio = nni_list_first(&mq->mq_aio_getq)) != NULL) {
		// If anything is waiting in the queue, get it first.
		if (mq->mq_len != 0) {
			msg = mq->mq_msgs[mq->mq_get++];
			if (mq->mq_get == mq->mq_alloc) {
				mq->mq_get = 0;
			}
			mq->mq_len--;
			nni_aio_list_remove(raio);
			nni_aio_finish_msg(raio, msg);
			continue;
		}

		// Nothing queued (unbuffered?), maybe a writer is waiting.
		if ((waio = nni_list_first(&mq->mq_aio_putq)) != NULL) {
			msg = nni_aio_get_msg(waio);
			nni_aio_set_msg(waio, NULL);
			nni_aio_list_remove(waio);
			nni_aio_list_remove(raio);

			nni_aio_finish(waio, 0, nni_msg_len(msg));
			nni_aio_finish_msg(raio, msg);
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
	if ((mq->mq_len < mq->mq_cap) || !nni_list_empty(&mq->mq_aio_getq)) {
		NNI_LIST_FOREACH (&mq->mq_aio_notify_put, aio) {
			// This stays on the list.
			nni_aio_finish(aio, 0, 0);
		}
	}

	if ((mq->mq_len != 0) || !nni_list_empty(&mq->mq_aio_putq)) {
		NNI_LIST_FOREACH (&mq->mq_aio_notify_get, aio) {
			// This stays on the list.
			nni_aio_finish(aio, 0, 0);
		}
	}

	if (mq->mq_draining) {
		if ((mq->mq_len == 0) && !nni_list_empty(&mq->mq_aio_putq)) {
			nni_cv_wake(&mq->mq_drained);
		}
	}
}

static void
nni_msgq_cancel(nni_aio *aio, int rv)
{
	nni_msgq *mq = aio->a_prov_data;

	nni_mtx_lock(&mq->mq_lock);
	if (nni_aio_list_active(aio)) {
		nni_aio_list_remove(aio);
		nni_aio_finish_error(aio, rv);
	}
	nni_mtx_unlock(&mq->mq_lock);
}

void
nni_msgq_aio_notify_put(nni_msgq *mq, nni_aio *aio)
{
	nni_mtx_lock(&mq->mq_lock);
	if (nni_aio_start(aio, nni_msgq_cancel, mq) != 0) {
		nni_mtx_unlock(&mq->mq_lock);
		return;
	}
	nni_aio_list_append(&mq->mq_aio_notify_put, aio);
	nni_mtx_unlock(&mq->mq_lock);
}

void
nni_msgq_aio_notify_get(nni_msgq *mq, nni_aio *aio)
{
	nni_mtx_lock(&mq->mq_lock);
	if (nni_aio_start(aio, nni_msgq_cancel, mq) != 0) {
		nni_mtx_unlock(&mq->mq_lock);
		return;
	}
	nni_aio_list_append(&mq->mq_aio_notify_get, aio);
	nni_mtx_unlock(&mq->mq_lock);
}

void
nni_msgq_aio_put(nni_msgq *mq, nni_aio *aio)
{
	nni_mtx_lock(&mq->mq_lock);
	if (nni_aio_start(aio, nni_msgq_cancel, mq) != 0) {
		nni_mtx_unlock(&mq->mq_lock);
		return;
	}
	if (mq->mq_closed) {
		nni_aio_finish_error(aio, NNG_ECLOSED);
		nni_mtx_unlock(&mq->mq_lock);
		return;
	}
	if (mq->mq_puterr) {
		nni_aio_finish_error(aio, mq->mq_puterr);
		nni_mtx_unlock(&mq->mq_lock);
		return;
	}

	nni_aio_list_append(&mq->mq_aio_putq, aio);
	nni_msgq_run_putq(mq);
	nni_msgq_run_notify(mq);

	nni_mtx_unlock(&mq->mq_lock);
}

void
nni_msgq_aio_get(nni_msgq *mq, nni_aio *aio)
{
	nni_mtx_lock(&mq->mq_lock);
	if (nni_aio_start(aio, nni_msgq_cancel, mq) != 0) {
		nni_mtx_unlock(&mq->mq_lock);
		return;
	}
	if (mq->mq_closed) {
		nni_aio_finish_error(aio, NNG_ECLOSED);
		nni_mtx_unlock(&mq->mq_lock);
		return;
	}
	if (mq->mq_geterr) {
		nni_aio_finish_error(aio, mq->mq_geterr);
		nni_mtx_unlock(&mq->mq_lock);
		return;
	}

	nni_aio_list_append(&mq->mq_aio_getq, aio);
	nni_msgq_run_getq(mq);
	nni_msgq_run_notify(mq);

	nni_mtx_unlock(&mq->mq_lock);
}

int
nni_msgq_tryput(nni_msgq *mq, nni_msg *msg)
{
	nni_aio *raio;

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

		nni_aio_finish_msg(raio, msg);
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

int
nni_msgq_get_until(nni_msgq *mq, nni_msg **msgp, nni_time expire)
{
	nni_aio *aio;
	int      rv;

	if ((rv = nni_aio_init(&aio, NULL, NULL)) != 0) {
		return (rv);
	}
	nni_aio_set_timeout(aio, expire);
	nni_msgq_aio_get(mq, aio);
	nni_aio_wait(aio);
	if ((rv = nni_aio_result(aio)) == 0) {
		*msgp = nni_aio_get_msg(aio);
		nni_aio_set_msg(aio, NULL);
	}
	nni_aio_fini(aio);
	return (rv);
}

int
nni_msgq_put_until(nni_msgq *mq, nni_msg *msg, nni_time expire)
{
	nni_aio *aio;
	int      rv;

	if ((rv = nni_aio_init(&aio, NULL, NULL)) != 0) {
		return (rv);
	}
	nni_aio_set_timeout(aio, expire);
	nni_aio_set_msg(aio, msg);
	nni_msgq_aio_put(mq, aio);
	nni_aio_wait(aio);
	rv = nni_aio_result(aio);
	nni_aio_fini(aio);
	return (rv);
}

void
nni_msgq_drain(nni_msgq *mq, nni_time expire)
{
	nni_aio *aio;

	nni_mtx_lock(&mq->mq_lock);
	mq->mq_closed   = 1;
	mq->mq_draining = 1;
	while ((mq->mq_len > 0) || !nni_list_empty(&mq->mq_aio_putq)) {
		if (nni_cv_until(&mq->mq_drained, expire) != 0) {
			break;
		}
	}

	// Timed out or writers drained.

	// Complete the putq as NNG_ECLOSED.
	while ((aio = nni_list_first(&mq->mq_aio_putq)) != NULL) {
		nni_aio_list_remove(aio);
		nni_aio_finish_error(aio, NNG_ECLOSED);
	}

	// Free any remaining messages in the queue.
	while (mq->mq_len > 0) {
		nni_msg *msg = mq->mq_msgs[mq->mq_get++];
		if (mq->mq_get >= mq->mq_alloc) {
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

	nni_mtx_lock(&mq->mq_lock);
	mq->mq_closed = 1;

	// Free the messages orphaned in the queue.
	while (mq->mq_len > 0) {
		nni_msg *msg = mq->mq_msgs[mq->mq_get++];
		if (mq->mq_get >= mq->mq_alloc) {
			mq->mq_get = 0;
		}
		mq->mq_len--;
		nni_msg_free(msg);
	}

	// Let all pending blockers know we are closing the queue.
	while (((aio = nni_list_first(&mq->mq_aio_getq)) != NULL) ||
	    ((aio = nni_list_first(&mq->mq_aio_putq)) != NULL)) {
		nni_aio_list_remove(aio);
		nni_aio_finish_error(aio, NNG_ECLOSED);
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
	int       alloc;
	nni_msg * msg;
	nni_msg **newq, **oldq;
	int       oldget;
	int       oldput;
	int       oldcap;
	int       oldlen;
	int       oldalloc;

	alloc = cap + 2;

	if (alloc > mq->mq_alloc) {
		newq = nni_alloc(sizeof(nni_msg *) * alloc);
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

	oldq     = mq->mq_msgs;
	oldget   = mq->mq_get;
	oldput   = mq->mq_put;
	oldcap   = mq->mq_cap;
	oldalloc = mq->mq_alloc;
	oldlen   = mq->mq_len;

	mq->mq_msgs = newq;
	mq->mq_len = mq->mq_get = mq->mq_put = 0;
	mq->mq_cap                           = cap;
	mq->mq_alloc                         = alloc;

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
	nni_free(oldq, sizeof(nni_msg *) * oldalloc);

out:
	// Wake everyone up -- we changed everything.
	nni_cv_wake(&mq->mq_drained);
	nni_mtx_unlock(&mq->mq_lock);
	return (0);
}
