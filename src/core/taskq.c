//
// Copyright 2017 Garrett D'Amore <garrett@damore.org>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "core/nng_impl.h"

typedef struct nni_taskq_thr   nni_taskq_thr;
struct nni_taskq_thr {
	nni_taskq *	tqt_tq;
	nni_thr		tqt_thread;
	nni_taskq_ent * tqt_running;
	int		tqt_wait;
};
struct nni_taskq {
	nni_list	tq_ents;
	nni_mtx		tq_mtx;
	nni_cv		tq_cv;
	nni_taskq_thr * tq_threads;
	int		tq_nthreads;
	int		tq_close;
};

static nni_taskq *nni_taskq_systq = NULL;

static void
nni_taskq_thread(void *self)
{
	nni_taskq_thr *thr = self;
	nni_taskq *tq = thr->tqt_tq;
	nni_taskq_ent *ent;

	nni_mtx_lock(&tq->tq_mtx);
	for (;;) {
		if ((ent = nni_list_first(&tq->tq_ents)) != NULL) {
			nni_list_remove(&tq->tq_ents, ent);
			ent->tqe_tq = NULL;
			thr->tqt_running = ent;
			nni_mtx_unlock(&tq->tq_mtx);
			ent->tqe_cb(ent->tqe_arg);
			nni_mtx_lock(&tq->tq_mtx);
			thr->tqt_running = NULL;
			if (thr->tqt_wait) {
				thr->tqt_wait = 0;
				nni_cv_wake(&tq->tq_cv);
			}
			continue;
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
	int rv;
	nni_taskq *tq;
	int i;

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
	NNI_LIST_INIT(&tq->tq_ents, nni_taskq_ent, tqe_node);

	tq->tq_threads = nni_alloc(sizeof (nni_taskq_thr) * nthr);
	if (tq->tq_threads == NULL) {
		nni_cv_fini(&tq->tq_cv);
		nni_mtx_fini(&tq->tq_mtx);
		NNI_FREE_STRUCT(tq);
		return (NNG_ENOMEM);
	}
	tq->tq_nthreads = nthr;
	for (i = 0; i < nthr; i++) {
		tq->tq_threads[i].tqt_tq = tq;
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


void
nni_taskq_fini(nni_taskq *tq)
{
	int i;

	nni_mtx_lock(&tq->tq_mtx);
	tq->tq_close = 1;
	nni_cv_wake(&tq->tq_cv);
	nni_mtx_unlock(&tq->tq_mtx);
	for (i = 0; i < tq->tq_nthreads; i++) {
		nni_thr_fini(&tq->tq_threads[i].tqt_thread);
	}
	nni_free(tq->tq_threads, tq->tq_nthreads * sizeof (nni_taskq_thr));
	nni_cv_fini(&tq->tq_cv);
	nni_mtx_fini(&tq->tq_mtx);
	NNI_FREE_STRUCT(tq);
}


int
nni_taskq_dispatch(nni_taskq *tq, nni_taskq_ent *ent)
{
	if (tq == NULL) {
		tq = nni_taskq_systq;
	}

	nni_mtx_lock(&tq->tq_mtx);
	if (tq->tq_close) {
		nni_mtx_unlock(&tq->tq_mtx);
		return (NNG_ECLOSED);
	}
	// It might already be scheduled... if so don't redo it.
	if (ent->tqe_tq == NULL) {
		ent->tqe_tq = tq;
		nni_list_append(&tq->tq_ents, ent);
	}
	nni_cv_wake(&tq->tq_cv);
	nni_mtx_unlock(&tq->tq_mtx);
	return (0);
}


int
nni_taskq_cancel(nni_taskq *tq, nni_taskq_ent *ent)
{
	int i;
	int running;

	if (tq == NULL) {
		tq = nni_taskq_systq;
	}

	nni_mtx_lock(&tq->tq_mtx);
	running = 1;
	do {
		running = 0;
		for (i = 0; i < tq->tq_nthreads; i++) {
			if (tq->tq_threads[i].tqt_running == ent) {
				tq->tq_threads[i].tqt_wait = 1;
				nni_cv_wait(&tq->tq_cv);
				running = 1;
				break;
			}
		}
	} while (running != 0);

	if (ent->tqe_tq != tq) {
		nni_mtx_unlock(&tq->tq_mtx);
		return (NNG_ENOENT);
	}
	nni_list_remove(&tq->tq_ents, ent);
	nni_mtx_unlock(&tq->tq_mtx);
	return (0);
}


void
nni_taskq_ent_init(nni_taskq_ent *ent, nni_cb cb, void *arg)
{
	NNI_LIST_NODE_INIT(&ent->tqe_node);
	ent->tqe_cb = cb;
	ent->tqe_arg = arg;
	ent->tqe_tq = NULL;
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
