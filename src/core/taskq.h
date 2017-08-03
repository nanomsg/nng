//
// Copyright 2017 Garrett D'Amore <garrett@damore.org>
// Copyright 2017 Capitar IT Group BV <info@capitar.com>
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

// nni_task is a structure representing a task.  Its intended to inlined
// into structures so that taskq_dispatch can be a guaranteed operation.
struct nni_task {
	nni_list_node task_node;
	void *        task_arg;
	nni_cb        task_cb;
	nni_taskq *   task_tq;
};

extern int  nni_taskq_init(nni_taskq **, int);
extern void nni_taskq_fini(nni_taskq *);
extern void nni_taskq_drain(nni_taskq *);

// nni_task_dispatch sends the task to the queue.  It is guaranteed to
// succeed.  (If the queue is shutdown, then the behavior is undefined.)
extern void nni_task_dispatch(nni_task *);

// nni_task_cancel cancels the task.  It will wait for the task to complete
// if it is already running.
extern int  nni_task_cancel(nni_task *);
extern void nni_task_wait(nni_task *);
extern void nni_task_init(nni_taskq *, nni_task *, nni_cb, void *);

extern int  nni_taskq_sys_init(void);
extern void nni_taskq_sys_fini(void);

#endif // CORE_TASKQ_H
