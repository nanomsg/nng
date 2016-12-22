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
	int		mq_cap;
	int		mq_len;
	int		mq_get;
	int		mq_put;
	int		mq_closed;
	nni_msg **	mq_msgs;
};

int
nni_msgqueue_create(nni_msgqueue **mqp, int cap)
{
	struct nni_msgqueue *mq;
	int rv;

	if (cap < 1) {
		return (NNG_EINVAL);
	}
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
	if ((mq->mq_msgs = nni_alloc(sizeof (nng_msg_t) * cap)) == NULL) {
		nni_cond_fini(&mq->mq_writeable);
		nni_cond_fini(&mq->mq_readable);
		nni_mutex_fini(&mq->mq_lock);
		return (NNG_ENOMEM);
	}

	mq->mq_cap = cap;
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

	nni_cond_fini(&mq->mq_writeable);
	nni_cond_fini(&mq->mq_readable);
	nni_mutex_fini(&mq->mq_lock);

	/* Free any orphaned messages. */
	while (mq->mq_len > 0) {
		msg = mq->mq_msgs[mq->mq_get];
		mq->mq_get++;
		if (mq->mq_get > mq->mq_cap) {
			mq->mq_get = 0;
		}
		mq->mq_len--;
		nni_msg_free(msg);
	}

	nni_free(mq->mq_msgs, mq->mq_cap * sizeof (nng_msg_t));
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

	while ((!mq->mq_closed) &&
	    (mq->mq_len == mq->mq_cap) &&
	    (!*signal)) {
		if (expire <= nni_clock()) {
			nni_mutex_exit(&mq->mq_lock);
			if (expire == NNI_TIME_ZERO) {
				return (NNG_EAGAIN);
			}
			return (NNG_ETIMEDOUT);
		}
		(void) nni_cond_waituntil(&mq->mq_writeable, expire);
	}

	if (mq->mq_closed) {
		nni_mutex_exit(&mq->mq_lock);
		return (NNG_ECLOSED);
	}

	if ((mq->mq_len == mq->mq_cap) && (*signal)) {
		// We are being interrupted.  We only allow an interrupt
		// if there is no room though, because we'd really prefer
		// to queue the data.  Otherwise our failure to queue
		// the data could lead to starvation.
		nni_mutex_exit(&mq->mq_lock);
		return (NNG_EINTR);
	}

	mq->mq_msgs[mq->mq_put] = msg;
	mq->mq_put++;
	if (mq->mq_put == mq->mq_cap) {
		mq->mq_put = 0;
	}
	mq->mq_len++;
	if (mq->mq_len == 1) {
		(void) nni_cond_signal(&mq->mq_readable);
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
		(void) nni_cond_waituntil(&mq->mq_readable, expire);
	}

	if (mq->mq_closed) {
		nni_mutex_exit(&mq->mq_lock);
		return (NNG_ECLOSED);
	}

	if ((mq->mq_len == 0) && (*signal)) {
		// We are being interrupted.  We only allow an interrupt
		// if there is no data though, because we'd really prefer
		// to give back the data.  Otherwise our failure to deal
		// with the data could lead to starvation; also lingering
		// relies on this not interrupting if data is pending.
		nni_mutex_exit(&mq->mq_lock);
		return (NNG_EINTR);
	}

	*msgp = mq->mq_msgs[mq->mq_get];
	mq->mq_len--;
	mq->mq_get++;
	if (mq->mq_get == mq->mq_cap) {
		mq->mq_get = 0;
	}
	mq->mq_len++;
	if (mq->mq_len == (mq->mq_cap - 1)) {
		(void) nni_cond_signal(&mq->mq_writeable);
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
nni_msgqueue_close(nni_msgqueue *mq)
{
	nni_msg_t msg;

	nni_mutex_enter(&mq->mq_lock);
	mq->mq_closed = 1;
	nni_cond_broadcast(&mq->mq_writeable);
	nni_cond_broadcast(&mq->mq_readable);

	// Free the messages orphaned in the queue.
	while (mq->mq_len > 0) {
		msg = mq->mq_msgs[mq->mq_get];
		mq->mq_get++;
		if (mq->mq_get > mq->mq_cap) {
			mq->mq_get = 0;
		}
		mq->mq_len--;
		nni_msg_free(msg);
	}
	nni_mutex_exit(&mq->mq_lock);
}
