//
// Copyright 2017 Garrett D'Amore <garrett@damore.org>
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

typedef struct nni_taskq	nni_taskq;
typedef struct nni_taskq_ent	nni_taskq_ent;

struct nni_taskq_ent {
	nni_list_node	tqe_node;
	void *		tqe_arg;
	nni_cb		tqe_cb;
	nni_taskq *	tqe_tq;
};

extern int nni_taskq_init(nni_taskq **, int);
extern void nni_taskq_fini(nni_taskq *);

extern int nni_taskq_dispatch(nni_taskq *, nni_taskq_ent *);
extern int nni_taskq_cancel(nni_taskq *, nni_taskq_ent *);
extern void nni_taskq_ent_init(nni_taskq_ent *, nni_cb, void *);

extern int nni_taskq_sys_init(void);
extern void nni_taskq_sys_fini(void);

#endif // CORE_TASKQ_H
