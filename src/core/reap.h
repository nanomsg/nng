//
// Copyright 2017 Garrett D'Amore <garrett@damore.org>
// Copyright 2017 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#ifndef CORE_REAP_H
#define CORE_REAP_H

#include "core/defs.h"
#include "core/list.h"

// nni_reap_item is defined here so that it can be inlined into
// structures.  Callers must access its members directly.
typedef struct nni_reap_item {
	nni_list_node r_link;
	void *        r_ptr;
	nni_cb        r_func;
} nni_reap_item;

// nni_reap performs an asynchronous reap of an item.  This allows functions
// it calls to acquire locks or resources without worrying about deadlocks
// (such as from a completion callback.)  The called function should avoid
// blocking for too long if possible, since only one reap thread is present
// in the system.  The intended usage is for an nni_reap_item to be a member
// of the structure to be reaped, and and then this function is called to
// finalize it.
extern void nni_reap(nni_reap_item *, nni_cb, void *);
extern int  nni_reap_sys_init(void);
extern void nni_reap_sys_fini(void);

#endif // CORE_REAP_H
