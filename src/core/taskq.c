//
// Copyright 2020 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
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
};
struct nni_taskq {
	nni_list       tq_tasks;
	nni_mtx        tq_mtx;
	nni_cv         tq_sched_cv;
	nni_cv         tq_wait_cv;
	nni_taskq_thr *tq_threads;
	int            tq_nthreads;
	bool           tq_run;
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

			nni_mtx_lock(&task->task_mtx);
			nni_list_remove(&tq->tq_tasks, task);
			nni_mtx_unlock(&task->task_mtx);

			nni_mtx_unlock(&tq->tq_mtx);

			task->task_cb(task->task_arg);

			nni_mtx_lock(&task->task_mtx);
			task->task_busy--;
			if (task->task_busy == 0) {
				nni_cv_wake(&task->task_cv);
			}
			nni_mtx_unlock(&task->task_mtx);

			nni_mtx_lock(&tq->tq_mtx);

			continue;
		}

		if (!tq->tq_run) {
			break;
		}
		nni_cv_wait(&tq->tq_sched_cv);
	}
	nni_mtx_unlock(&tq->tq_mtx);
}

int
nni_taskq_init(nni_taskq **tqp, int nthr)
{
	nni_taskq *tq;

	if ((tq = NNI_ALLOC_STRUCT(tq)) == NULL) {
		return (NNG_ENOMEM);
	}
	if ((tq->tq_threads = NNI_ALLOC_STRUCTS(tq->tq_threads, nthr)) ==
	    NULL) {
		NNI_FREE_STRUCT(tq);
		return (NNG_ENOMEM);
	}
	tq->tq_nthreads = nthr;
	NNI_LIST_INIT(&tq->tq_tasks, nni_task, task_node);

	nni_mtx_init(&tq->tq_mtx);
	nni_cv_init(&tq->tq_sched_cv, &tq->tq_mtx);
	nni_cv_init(&tq->tq_wait_cv, &tq->tq_mtx);

	for (int i = 0; i < nthr; i++) {
		int rv;
		tq->tq_threads[i].tqt_tq = tq;
		rv = nni_thr_init(&tq->tq_threads[i].tqt_thread,
		    nni_taskq_thread, &tq->tq_threads[i]);
		if (rv != 0) {
			nni_taskq_fini(tq);
			return (rv);
		}
	}
	tq->tq_run = true;
	for (int i = 0; i < tq->tq_nthreads; i++) {
		nni_thr_run(&tq->tq_threads[i].tqt_thread);
	}
	*tqp = tq;
	return (0);
}

void
nni_taskq_fini(nni_taskq *tq)
{
	if (tq == NULL) {
		return;
	}
	if (tq->tq_run) {
		nni_mtx_lock(&tq->tq_mtx);
		tq->tq_run = false;
		nni_cv_wake(&tq->tq_sched_cv);
		nni_mtx_unlock(&tq->tq_mtx);
	}
	for (int i = 0; i < tq->tq_nthreads; i++) {
		nni_thr_fini(&tq->tq_threads[i].tqt_thread);
	}
	nni_cv_fini(&tq->tq_wait_cv);
	nni_cv_fini(&tq->tq_sched_cv);
	nni_mtx_fini(&tq->tq_mtx);
	NNI_FREE_STRUCTS(tq->tq_threads, tq->tq_nthreads);
	NNI_FREE_STRUCT(tq);
}

void
nni_task_exec(nni_task *task)
{
	nni_mtx_lock(&task->task_mtx);
	if (task->task_prep) {
		task->task_prep = false;
	} else {
		task->task_busy++;
	}
	nni_mtx_unlock(&task->task_mtx);

	if (task->task_cb != NULL) {
		task->task_cb(task->task_arg);
	}

	nni_mtx_lock(&task->task_mtx);
	task->task_busy--;
	if (task->task_busy == 0) {
		nni_cv_wake(&task->task_cv);
	}
	nni_mtx_unlock(&task->task_mtx);
}

void
nni_task_dispatch(nni_task *task)
{
	nni_taskq *tq = task->task_tq;

	// If there is no callback to perform, then do nothing!
	// The user will be none the wiser.
	if (task->task_cb == NULL) {
		nni_task_exec(task);
		return;
	}
	nni_mtx_lock(&task->task_mtx);
	if (task->task_prep) {
		task->task_prep = false;
	} else {
		task->task_busy++;
	}
	nni_mtx_unlock(&task->task_mtx);

	nni_mtx_lock(&tq->tq_mtx);
	nni_list_append(&tq->tq_tasks, task);
	nni_cv_wake1(&tq->tq_sched_cv); // waking just one waiter is adequate
	nni_mtx_unlock(&tq->tq_mtx);
}

void
nni_task_prep(nni_task *task)
{
	nni_mtx_lock(&task->task_mtx);
	task->task_busy++;
	task->task_prep = true;
	nni_mtx_unlock(&task->task_mtx);
}

void
nni_task_wait(nni_task *task)
{
	nni_mtx_lock(&task->task_mtx);
	while (task->task_busy) {
		nni_cv_wait(&task->task_cv);
	}
	nni_mtx_unlock(&task->task_mtx);
}

void
nni_task_init(nni_task *task, nni_taskq *tq, nni_cb cb, void *arg)
{
	NNI_LIST_NODE_INIT(&task->task_node);
	nni_mtx_init(&task->task_mtx);
	nni_cv_init(&task->task_cv, &task->task_mtx);
	task->task_prep = false;
	task->task_busy = 0;
	task->task_cb   = cb;
	task->task_arg  = arg;
	task->task_tq   = tq != NULL ? tq : nni_taskq_systq;
}

void
nni_task_fini(nni_task *task)
{
	nni_mtx_lock(&task->task_mtx);
	while (task->task_busy) {
		nni_cv_wait(&task->task_cv);
	}
	nni_mtx_unlock(&task->task_mtx);
	nni_cv_fini(&task->task_cv);
	nni_mtx_fini(&task->task_mtx);
}

int
nni_taskq_sys_init(void)
{
	int nthrs;

#ifndef NNG_NUM_TASKQ_THREADS
	nthrs = nni_plat_ncpu() * 2;
#else
	nthrs = NNG_NUM_TASKQ_THREADS;
#endif
#if NNG_MAX_TASKQ_THREADS > 0
	if (nthrs > NNG_MAX_TASKQ_THREADS) {
		nthrs = NNG_MAX_TASKQ_THREADS;
	}
#endif

	return (nni_taskq_init(&nni_taskq_systq, nthrs));
}

void
nni_taskq_sys_fini(void)
{
	nni_taskq_fini(nni_taskq_systq);
	nni_taskq_systq = NULL;
}
