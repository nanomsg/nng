//
// Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#ifndef CORE_TASKQ_H
#define CORE_TASKQ_H

#include "core/defs.h"
#include "core/list.h"

typedef struct nni_taskq nni_taskq;
typedef struct nni_task  nni_task;

extern int  nni_taskq_init(nni_taskq **, int);
extern void nni_taskq_fini(nni_taskq *);

// nni_task_dispatch sends the task to the queue.  It is guaranteed to
// succeed.  (If the queue is shutdown, then the behavior is undefined.)
extern void nni_task_dispatch(nni_task *);

// nni_task_exec runs the task synchronously, if possible.  (Under certain
// circumstances the task must be run asynchronously.)  The caller is
// responsible for ensuring that it does not hold any resources which might
// be acquired by the task itself; otherwise deadlock may occur.  (When in
// doubt, use nni_task_dispatch instead.)
extern void nni_task_exec(nni_task *);

// nni_task_prep is used by and exclusively for the aio framework.
// nni_task_prep marks the task as "scheduled" without actually
// dispatching anything to it yet; nni_task_wait will block waiting for the
// task to complete normally (after a call to nni_task_dispatch or
// nni_task_exec).
extern void nni_task_prep(nni_task *);

extern void nni_task_wait(nni_task *);
extern void  nni_task_init(nni_task *, nni_taskq *, nni_cb, void *);

// nni_task_fini destroys the task.  It will reap resources asynchronously
// if the task is currently executing.  Use nni_task_wait() first if the
// callback must be stopped entirely before destroying the task (such as if
// it reschedules the task.)
extern void nni_task_fini(nni_task *);

extern int  nni_taskq_sys_init(void);
extern void nni_taskq_sys_fini(void);

// nni_task implementation details are not to be used except by the
// nni_task_framework.  Placing here allows for inlining this in
// consuming structures.
struct nni_task {
	nni_list_node task_node;
	void *        task_arg;
	nni_cb        task_cb;
	nni_taskq *   task_tq;
	unsigned      task_busy;
	bool          task_prep;
	nni_mtx       task_mtx;
	nni_cv        task_cv;
};

#endif // CORE_TASKQ_H
