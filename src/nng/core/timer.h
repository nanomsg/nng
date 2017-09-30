//
// Copyright 2017 Garrett D'Amore <garrett@damore.org>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#ifndef CORE_TIMER_H
#define CORE_TIMER_H

#include "core/defs.h"
#include "core/list.h"

// For the sake of simplicity, we just maintain a single global timer thread.

struct nni_timer_node {
	nni_time      t_expire;
	nni_cb        t_cb;
	void *        t_arg;
	nni_list_node t_node;
};

typedef struct nni_timer_node nni_timer_node;

extern void nni_timer_init(nni_timer_node *, nni_cb, void *);
extern void nni_timer_fini(nni_timer_node *);
extern void nni_timer_schedule(nni_timer_node *, nni_time);
extern void nni_timer_cancel(nni_timer_node *);
extern int  nni_timer_sys_init(void);
extern void nni_timer_sys_fini(void);

#endif // CORE_TIMER_H
