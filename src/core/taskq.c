//
// Copyright 2017 Garrett D'Amore <garrett@damore.org>
// Copyright 2017 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "core/nng_impl.h"

typedef struct nni_taskq_thr nni_taskq_thr;
struct nni_taskq_thr {
	nni_taskq *tqt_tq;
	nni_thr    tqt_thread;
	nni_task * tqt_running;
	int        tqt_wait;
};
struct nni_taskq {
	nni_list       tq_tasks;
	nni_mtx        tq_mtx;
	nni_cv         tq_cv;
	nni_taskq_thr *tq_threads;
	int            tq_nthreads;
	int            tq_close;
	int            tq_waiting;
};

static nni_taskq *nni_taskq_systq = NULL;

static void
nni_taskq_thread(void *self)
{
	nni_taskq_thr *thr = self;
	nni_taskq *    tq  = thr->tqt_tq;
	nni_task *     task;

	nni_mtx_lock(&tq->tq_mtx);
	for (;;) {
		if ((task = nni_list_first(&tq->tq_tasks)) != NULL) {
			nni_list_remove(&tq->tq_tasks, task);
			thr->tqt_running = task;
			nni_mtx_unlock(&tq->tq_mtx);
			task->task_cb(task->task_arg);
			nni_mtx_lock(&tq->tq_mtx);
			thr->tqt_running = NULL;
			if (thr->tqt_wait) {
				thr->tqt_wait = 0;
				nni_cv_wake(&tq->tq_cv);
			}
			if (tq->tq_waiting) {
				tq->tq_waiting = 0;
				nni_cv_wake(&tq->tq_cv);
			}

			continue;
		}

		if (tq->tq_waiting) {
			tq->tq_waiting = 0;
			nni_cv_wake(&tq->tq_cv);
		}
		if (tq->tq_close) {
			break;
		}
		nni_cv_wait(&tq->tq_cv);
	}
	nni_mtx_unlock(&tq->tq_mtx);
}

int
nni_taskq_init(nni_taskq **tqp, int nthr)
{
	int        rv;
	nni_taskq *tq;
	int        i;

	if ((tq = NNI_ALLOC_STRUCT(tq)) == NULL) {
		return (NNG_ENOMEM);
	}
	if ((rv = nni_mtx_init(&tq->tq_mtx)) != 0) {
		NNI_FREE_STRUCT(tq);
		return (rv);
	}
	if ((rv = nni_cv_init(&tq->tq_cv, &tq->tq_mtx)) != 0) {
		nni_mtx_fini(&tq->tq_mtx);
		NNI_FREE_STRUCT(tq);
		return (rv);
	}
	tq->tq_close = 0;
	NNI_LIST_INIT(&tq->tq_tasks, nni_task, task_node);

	tq->tq_threads = nni_alloc(sizeof(nni_taskq_thr) * nthr);
	if (tq->tq_threads == NULL) {
		nni_cv_fini(&tq->tq_cv);
		nni_mtx_fini(&tq->tq_mtx);
		NNI_FREE_STRUCT(tq);
		return (NNG_ENOMEM);
	}
	tq->tq_nthreads = nthr;
	for (i = 0; i < nthr; i++) {
		tq->tq_threads[i].tqt_tq      = tq;
		tq->tq_threads[i].tqt_running = NULL;
		rv = nni_thr_init(&tq->tq_threads[i].tqt_thread,
		    nni_taskq_thread, &tq->tq_threads[i]);
		if (rv != 0) {
			goto fail;
		}
	}
	tq->tq_nthreads = nthr;
	for (i = 0; i < tq->tq_nthreads; i++) {
		nni_thr_run(&tq->tq_threads[i].tqt_thread);
	}
	*tqp = tq;
	return (0);

fail:

	nni_taskq_fini(tq);
	return (rv);
}

static void
nni_taskq_drain_locked(nni_taskq *tq)
{
	// We need to first let the taskq completely drain.
	for (;;) {
		int busy = 0;
		if (!nni_list_empty(&tq->tq_tasks)) {
			busy = 1;
		} else {
			int i;
			for (i = 0; i < tq->tq_nthreads; i++) {
				if (tq->tq_threads[i].tqt_running != 0) {
					busy = 1;
					break;
				}
			}
		}
		if (!busy) {
			break;
		}
		tq->tq_waiting++;
		nni_cv_wait(&tq->tq_cv);
	}
}

void
nni_taskq_drain(nni_taskq *tq)
{
	nni_mtx_lock(&tq->tq_mtx);
	nni_taskq_drain_locked(tq);
	nni_mtx_unlock(&tq->tq_mtx);
}

void
nni_taskq_fini(nni_taskq *tq)
{
	int i;

	// First drain the taskq completely.  This is necessary since some
	// tasks that are presently running may need to schedule additional
	// tasks, and we don't want those to block.

	nni_mtx_lock(&tq->tq_mtx);
	nni_taskq_drain_locked(tq);

	tq->tq_close = 1;
	nni_cv_wake(&tq->tq_cv);
	nni_mtx_unlock(&tq->tq_mtx);
	for (i = 0; i < tq->tq_nthreads; i++) {
		nni_thr_fini(&tq->tq_threads[i].tqt_thread);
	}
	nni_free(tq->tq_threads, tq->tq_nthreads * sizeof(nni_taskq_thr));
	nni_cv_fini(&tq->tq_cv);
	nni_mtx_fini(&tq->tq_mtx);
	NNI_FREE_STRUCT(tq);
}

void
nni_task_dispatch(nni_task *task)
{
	nni_taskq *tq = task->task_tq;

	// If there is no callback to perform, then do nothing!
	// The user will be none the wiser.
	if (task->task_cb == NULL) {
		return;
	}
	nni_mtx_lock(&tq->tq_mtx);
	// It might already be scheduled... if so don't redo it.
	if (!nni_list_active(&tq->tq_tasks, task)) {
		nni_list_append(&tq->tq_tasks, task);
	}
	nni_cv_wake(&tq->tq_cv);
	nni_mtx_unlock(&tq->tq_mtx);
}

void
nni_task_wait(nni_task *task)
{
	nni_taskq *tq = task->task_tq;
	int        i;
	int        running;

	nni_mtx_lock(&tq->tq_mtx);
	for (;;) {
		running = 0;
		if (nni_list_active(&tq->tq_tasks, task)) {
			running = 1;
		} else {
			for (i = 0; i < tq->tq_nthreads; i++) {
				if (tq->tq_threads[i].tqt_running == task) {
					running = 1;
					break;
				}
			}
		}
		if (!running) {
			break;
		}

		tq->tq_waiting = 1;
		nni_cv_wait(&tq->tq_cv);
	}
	nni_mtx_unlock(&tq->tq_mtx);
}

int
nni_task_cancel(nni_task *task)
{
	nni_taskq *tq = task->task_tq;
	int        i;
	int        running;

	nni_mtx_lock(&tq->tq_mtx);
	running = 1;
	for (;;) {
		running = 0;
		for (i = 0; i < tq->tq_nthreads; i++) {
			if (tq->tq_threads[i].tqt_running == task) {
				running = 1;
				break;
			}
		}

		if (!running) {
			break;
		}
		// tq->tq_threads[i].tqt_wait = 1;
		tq->tq_waiting++;
		nni_cv_wait(&tq->tq_cv);
	}

	if (nni_list_active(&tq->tq_tasks, task)) {
		nni_list_remove(&tq->tq_tasks, task);
	}
	nni_mtx_unlock(&tq->tq_mtx);
	return (0);
}

void
nni_task_init(nni_taskq *tq, nni_task *task, nni_cb cb, void *arg)
{
	if (tq == NULL) {
		tq = nni_taskq_systq;
	}
	NNI_LIST_NODE_INIT(&task->task_node);
	task->task_cb  = cb;
	task->task_arg = arg;
	task->task_tq  = tq;
}

int
nni_taskq_sys_init(void)
{
	int rv;

	// XXX: Make the "16" = NCPUs * 2
	rv = nni_taskq_init(&nni_taskq_systq, 16);
	return (rv);
}

void
nni_taskq_sys_fini(void)
{
	nni_taskq_fini(nni_taskq_systq);
}
