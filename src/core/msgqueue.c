/*
 * Copyright 2016 Garrett D'Amore <garrett@damore.org>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom
 * the Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#include "nng_impl.h"

/*
 * Message queue.  These operate in some respects like Go channels,
 * but as we have access to the internals, we have made some fundamental
 * differences and improvements.  For example, these can grow, and either
 * side can close, and they may be closed more than once.
 */

struct nni_msgqueue {
	nni_mutex_t	mq_lock;
	nni_cond_t	mq_readable;
	nni_cond_t	mq_writeable;
	int		mq_cap;
	int		mq_len;
	int		mq_get;
	int		mq_put;
	int		mq_closed;
	nng_msg_t	*mq_msgs;
};

int
nni_msgqueue_create(nni_msgqueue_t *mqp, int cap)
{
	struct nni_msgqueue *mq;
	int rv;

	if (cap < 1) {
		return (NNG_EINVAL);
	}
	if ((mq = nni_alloc(sizeof (*mq))) == NULL) {
		return (NNG_ENOMEM);
	}
	if ((rv = nni_mutex_create(&mq->mq_lock)) != 0) {
		nni_free(mq, sizeof (*mq));
		return (rv);
	}
	if ((rv = nni_cond_create(&mq->mq_readable, mq->mq_lock)) != 0) {
		nni_mutex_destroy(mq->mq_lock);
		nni_free(mq, sizeof (*mq));
		return (NNG_ENOMEM);
	}
	if ((rv = nni_cond_create(&mq->mq_writeable, mq->mq_lock)) != 0) {
		nni_cond_destroy(mq->mq_readable);
		nni_mutex_destroy(mq->mq_lock);
		return (NNG_ENOMEM);
	}
	if ((mq->mq_msgs = nni_alloc(sizeof (nng_msg_t) * cap)) == NULL) {
		nni_cond_destroy(mq->mq_writeable);
		nni_cond_destroy(mq->mq_readable);
		nni_mutex_destroy(mq->mq_lock);
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
nni_msgqueue_destroy(nni_msgqueue_t mq)
{
	nng_msg_t msg;

	nni_cond_destroy(mq->mq_writeable);
	nni_cond_destroy(mq->mq_readable);
	nni_mutex_destroy(mq->mq_lock);

	/* Free any orphaned messages. */
	while (mq->mq_len > 0) {
		msg = mq->mq_msgs[mq->mq_get];
		mq->mq_get++;
		if (mq->mq_get > mq->mq_cap) {
			mq->mq_get = 0;
		}
		mq->mq_len--;
		nng_msg_free(msg);
	}

	nni_free(mq->mq_msgs, mq->mq_cap * sizeof (nng_msg_t));
	nni_free(mq, sizeof (*mq));
}

/*
 * nni_msgqueue_signal raises a signal on the signal object. This allows a
 * waiter to be signaled, so that it can be woken e.g. due to a pipe closing.
 * Note that the signal object must be *zero* if no signal is raised.
 */
void
nni_msgqueue_signal(nni_msgqueue_t mq, int *signal)
{
	nni_mutex_enter(mq->mq_lock);
	*signal = 1;
	/*
	 * We have to wake everyone.
	 */
	nni_cond_broadcast(mq->mq_readable);
	nni_cond_broadcast(mq->mq_writeable);
	nni_mutex_exit(mq->mq_lock);
}

int
nni_msgqueue_put_sig(nni_msgqueue_t mq, nng_msg_t msg, int tmout, int *signal)
{
	uint64_t expire, now;

	if (tmout > 0) {
		expire = nni_clock() + tmout;
	}

	nni_mutex_enter(mq->mq_lock);

	while ((!mq->mq_closed) && (mq->mq_len == mq->mq_cap) && (!*signal)) {
		if (tmout == 0) {
			nni_mutex_exit(mq->mq_lock);
			return (NNG_EAGAIN);
		}
	
		if (tmout < 0) {
			(void) nni_cond_wait(mq->mq_writeable);
			continue;
		}

		now = nni_clock();
		if (now >= expire) {
			nni_mutex_exit(mq->mq_lock);
			return (NNG_ETIMEDOUT);
		}
		(void) nni_cond_timedwait(mq->mq_writeable, (expire - now));
	}

	if (mq->mq_closed) {
		nni_mutex_exit(mq->mq_lock);
		return (NNG_ECLOSED);
	}

	if ((mq->mq_len == mq->mq_cap) && (*signal)) {
		/*
		 * We are being interrupted.  We only allow an interrupt
		 * if there is no room though, because we'd really prefer
		 * to queue the data.  Otherwise our failure to queue
		 * the data could lead to starvation.
		 */
		nni_mutex_exit(mq->mq_lock);
		return (NNG_EINTR);
	}

	mq->mq_msgs[mq->mq_put] = msg;
	mq->mq_put++;
	if (mq->mq_put == mq->mq_cap) {
		mq->mq_put = 0;
	}
	mq->mq_len++;
	if (mq->mq_len == 1) {
		(void) nni_cond_signal(mq->mq_readable);
	}
	nni_mutex_exit(mq->mq_lock);
	return (0);
}

int
nni_msgqueue_get_sig(nni_msgqueue_t mq, nng_msg_t *msgp, int tmout, int *signal)
{
	uint64_t expire, now;

	if (tmout > 0) {
		expire = nni_clock() + tmout;
	}

	nni_mutex_enter(mq->mq_lock);

	while ((!mq->mq_closed) && (mq->mq_len == 0) && (*signal == 0)) {
		if (tmout == 0) {
			nni_mutex_exit(mq->mq_lock);
			return (NNG_EAGAIN);
		}
	
		if (tmout < 0) {
			(void) nni_cond_wait(mq->mq_readable);
			continue;
		}

		now = nni_clock();
		if (now >= expire) {
			nni_mutex_exit(mq->mq_lock);
			return (NNG_ETIMEDOUT);
		}
		(void) nni_cond_timedwait(mq->mq_readable, (expire - now));
	}

	if (mq->mq_closed) {
		nni_mutex_exit(mq->mq_lock);
		return (NNG_ECLOSED);
	}

	if ((mq->mq_len == 0) && (*signal)) {
		/*
		 * We are being interrupted.  We only allow an interrupt
		 * if there is no data though, because we'd really prefer
		 * to give back the data.  Otherwise our failure to deal
		 * with the data could lead to starvation.
		 */
		nni_mutex_exit(mq->mq_lock);
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
		(void) nni_cond_signal(mq->mq_writeable);
	}
	nni_mutex_exit(mq->mq_lock);
	return (0);

}

int
nni_msgqueue_get(nni_msgqueue_t mq, nng_msg_t *msgp, int tmout)
{
	int nosig = 0;
	return (nni_msgqueue_get_sig(mq, msgp, tmout, &nosig));
}

int
nni_msgqueue_put(nni_msgqueue_t mq, nng_msg_t msg, int tmout)
{
	int nosig = 0;
	return (nni_msgqueue_put_sig(mq, msg, tmout, &nosig));
}

void
nni_msgqueue_close(nni_msgqueue_t mq)
{
	nng_msg_t msg;

	nni_mutex_enter(mq->mq_lock);
	mq->mq_closed = 1;
	nni_cond_broadcast(mq->mq_writeable);
	nni_cond_broadcast(mq->mq_readable);

	/* Free the messages orphaned in the queue. */
	while (mq->mq_len > 0) {
		msg = mq->mq_msgs[mq->mq_get];
		mq->mq_get++;
		if (mq->mq_get > mq->mq_cap) {
			mq->mq_get = 0;
		}
		mq->mq_len--;
		nng_msg_free(msg);
	}
	nni_mutex_exit(mq->mq_lock);
}
