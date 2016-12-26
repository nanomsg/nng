//
// Copyright 2016 Garrett D'Amore <garrett@damore.org>
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

struct nni_msgqueue {
	nni_mutex	mq_lock;
	nni_cond	mq_readable;
	nni_cond	mq_writeable;
	nni_cond	mq_drained;
	int		mq_cap;
	int		mq_alloc;       // alloc is cap + 2...
	int		mq_len;
	int		mq_get;
	int		mq_put;
	int		mq_closed;
	int		mq_rwait;       // readers waiting (unbuffered)
	nni_msg **	mq_msgs;
};

int
nni_msgqueue_create(nni_msgqueue **mqp, int cap)
{
	struct nni_msgqueue *mq;
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

	if ((mq = nni_alloc(sizeof (*mq))) == NULL) {
		return (NNG_ENOMEM);
	}
	if ((rv = nni_mutex_init(&mq->mq_lock)) != 0) {
		nni_free(mq, sizeof (*mq));
		return (rv);
	}
	if ((rv = nni_cond_init(&mq->mq_readable, &mq->mq_lock)) != 0) {
		nni_mutex_fini(&mq->mq_lock);
		nni_free(mq, sizeof (*mq));
		return (NNG_ENOMEM);
	}
	if ((rv = nni_cond_init(&mq->mq_writeable, &mq->mq_lock)) != 0) {
		nni_cond_fini(&mq->mq_readable);
		nni_mutex_fini(&mq->mq_lock);
		return (NNG_ENOMEM);
	}
	if ((rv = nni_cond_init(&mq->mq_drained, &mq->mq_lock)) != 0) {
		nni_cond_fini(&mq->mq_writeable);
		nni_cond_fini(&mq->mq_readable);
		nni_mutex_fini(&mq->mq_lock);
		return (NNG_ENOMEM);
	}
	if ((mq->mq_msgs = nni_alloc(sizeof (nng_msg *) * alloc)) == NULL) {
		nni_cond_fini(&mq->mq_drained);
		nni_cond_fini(&mq->mq_writeable);
		nni_cond_fini(&mq->mq_readable);
		nni_mutex_fini(&mq->mq_lock);
		return (NNG_ENOMEM);
	}

	mq->mq_cap = cap;
	mq->mq_alloc = alloc;
	mq->mq_len = 0;
	mq->mq_get = 0;
	mq->mq_put = 0;
	mq->mq_closed = 0;
	*mqp = mq;

	return (0);
}


void
nni_msgqueue_destroy(nni_msgqueue *mq)
{
	nni_msg *msg;

	nni_cond_fini(&mq->mq_drained);
	nni_cond_fini(&mq->mq_writeable);
	nni_cond_fini(&mq->mq_readable);
	nni_mutex_fini(&mq->mq_lock);

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
	nni_free(mq, sizeof (*mq));
}


// nni_msgqueue_signal raises a signal on the signal object. This allows a
// waiter to be signaled, so that it can be woken e.g. due to a pipe closing.
// Note that the signal object must be *zero* if no signal is raised.
void
nni_msgqueue_signal(nni_msgqueue *mq, int *signal)
{
	nni_mutex_enter(&mq->mq_lock);
	*signal = 1;

	// We have to wake everyone.
	nni_cond_broadcast(&mq->mq_readable);
	nni_cond_broadcast(&mq->mq_writeable);
	nni_mutex_exit(&mq->mq_lock);
}


int
nni_msgqueue_put_impl(nni_msgqueue *mq, nni_msg *msg,
    nni_time expire, nni_signal *signal)
{
	nni_mutex_enter(&mq->mq_lock);

	for (;;) {
		// if closed, we don't put more... this check is first!
		if (mq->mq_closed) {
			nni_mutex_exit(&mq->mq_lock);
			return (NNG_ECLOSED);
		}

		// room in the queue?
		if (mq->mq_len < mq->mq_cap) {
			break;
		}

		// unbuffered, room for one, and a reader waiting?
		if (mq->mq_rwait && (mq->mq_len == mq->mq_cap)) {
			break;
		}

		// interrupted?
		if (*signal) {
			nni_mutex_exit(&mq->mq_lock);
			return (NNG_EINTR);
		}

		// single poll?
		if (expire == NNI_TIME_ZERO) {
			nni_mutex_exit(&mq->mq_lock);
			return (NNG_EAGAIN);
		}

		// timedout?
		if (expire <= nni_clock()) {
			nni_mutex_exit(&mq->mq_lock);
			return (NNG_ETIMEDOUT);
		}

		// not writeable, so wait until something changes
		(void) nni_cond_waituntil(&mq->mq_writeable, expire);
	}

	// Writeable!  Yay!!

	mq->mq_msgs[mq->mq_put] = msg;
	mq->mq_put++;
	if (mq->mq_put == mq->mq_alloc) {
		mq->mq_put = 0;
	}
	mq->mq_len++;
	if (mq->mq_len == 1) {
		nni_cond_signal(&mq->mq_readable);
	}
	nni_mutex_exit(&mq->mq_lock);
	return (0);
}


static int
nni_msgqueue_get_impl(nni_msgqueue *mq, nni_msg **msgp,
    nni_time expire, nni_signal *signal)
{
	nni_mutex_enter(&mq->mq_lock);

	while ((!mq->mq_closed) && (mq->mq_len == 0) && (*signal == 0)) {
		if (expire <= nni_clock()) {
			nni_mutex_exit(&mq->mq_lock);
			if (expire == NNI_TIME_ZERO) {
				return (NNG_EAGAIN);
			}
			return (NNG_ETIMEDOUT);
		}
		mq->mq_rwait++;
		if (mq->mq_cap == 0) {
			// If a writer is blocked, unblock him.
			nni_cond_signal(&mq->mq_writeable);
		}
		(void) nni_cond_waituntil(&mq->mq_readable, expire);
		mq->mq_rwait--;
	}

	// If there is any data left in the message queue, we will still
	// provide it, so that the reader can drain.
	if (mq->mq_len == 0) {
		if (mq->mq_closed) {
			nni_cond_signal(&mq->mq_drained);
			nni_mutex_exit(&mq->mq_lock);
			return (NNG_ECLOSED);
		}

		if (*signal) {
			// We are being interrupted.
			nni_mutex_exit(&mq->mq_lock);
			return (NNG_EINTR);
		}
	}

	*msgp = mq->mq_msgs[mq->mq_get];
	mq->mq_len--;
	mq->mq_get++;
	if (mq->mq_get == mq->mq_alloc) {
		mq->mq_get = 0;
	}
	if (mq->mq_len == (mq->mq_cap - 1)) {
		nni_cond_signal(&mq->mq_writeable);
	}
	nni_mutex_exit(&mq->mq_lock);
	return (0);
}


int
nni_msgqueue_get(nni_msgqueue *mq, nni_msg **msgp)
{
	nni_signal nosig = 0;

	return (nni_msgqueue_get_impl(mq, msgp, NNI_TIME_NEVER, &nosig));
}


int
nni_msgqueue_get_sig(nni_msgqueue *mq, nni_msg **msgp, nni_signal *signal)
{
	return (nni_msgqueue_get_impl(mq, msgp, NNI_TIME_NEVER, signal));
}


int
nni_msgqueue_get_until(nni_msgqueue *mq, nni_msg **msgp, nni_time expire)
{
	nni_signal nosig = 0;

	return (nni_msgqueue_get_impl(mq, msgp, expire, &nosig));
}


int
nni_msgqueue_put(nni_msgqueue *mq, nni_msg *msg)
{
	nni_signal nosig = 0;

	return (nni_msgqueue_put_impl(mq, msg, NNI_TIME_NEVER, &nosig));
}


int
nni_msgqueue_put_sig(nni_msgqueue *mq, nni_msg *msg, nni_signal *signal)
{
	return (nni_msgqueue_put_impl(mq, msg, NNI_TIME_NEVER, signal));
}


int
nni_msgqueue_put_until(nni_msgqueue *mq, nni_msg *msg, nni_time expire)
{
	nni_signal nosig = 0;

	return (nni_msgqueue_put_impl(mq, msg, expire, &nosig));
}


void
nni_msgqueue_drain(nni_msgqueue *mq, nni_time expire)
{
	nni_mutex_enter(&mq->mq_lock);
	mq->mq_closed = 1;
	nni_cond_broadcast(&mq->mq_writeable);
	nni_cond_broadcast(&mq->mq_readable);
	while (mq->mq_len > 0) {
		if (nni_cond_waituntil(&mq->mq_drained, expire) ==
		    NNG_ETIMEDOUT) {
			break;
		}
	}
	// If we timedout, free any remaining messages in the queue.
	while (mq->mq_len > 0) {
		nni_msg *msg = mq->mq_msgs[mq->mq_get++];
		if (mq->mq_get > mq->mq_alloc) {
			mq->mq_get = 0;
		}
		mq->mq_len--;
		nni_msg_free(msg);
	}
	nni_mutex_exit(&mq->mq_lock);
}


void
nni_msgqueue_close(nni_msgqueue *mq)
{
	nni_mutex_enter(&mq->mq_lock);
	mq->mq_closed = 1;
	nni_cond_broadcast(&mq->mq_writeable);
	nni_cond_broadcast(&mq->mq_readable);

	// Free the messages orphaned in the queue.
	while (mq->mq_len > 0) {
		nni_msg *msg = mq->mq_msgs[mq->mq_get++];
		if (mq->mq_get > mq->mq_alloc) {
			mq->mq_get = 0;
		}
		mq->mq_len--;
		nni_msg_free(msg);
	}
	nni_mutex_exit(&mq->mq_lock);
}


int
nni_msgqueue_len(nni_msgqueue *mq)
{
	int rv;

	nni_mutex_enter(&mq->mq_lock);
	rv = mq->mq_len;
	nni_mutex_exit(&mq->mq_lock);
	return (rv);
}


int
nni_msgqueue_cap(nni_msgqueue *mq)
{
	int rv;

	nni_mutex_enter(&mq->mq_lock);
	rv = mq->mq_cap;
	nni_mutex_exit(&mq->mq_lock);
	return (rv);
}


int
nni_msgqueue_resize(nni_msgqueue *mq, int cap)
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

	nni_mutex_enter(&mq->mq_lock);
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
	nni_cond_broadcast(&mq->mq_readable);
	nni_cond_broadcast(&mq->mq_writeable);
	nni_cond_broadcast(&mq->mq_drained);
	nni_mutex_exit(&mq->mq_lock);
	return (0);
}
