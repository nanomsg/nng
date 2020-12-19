//
// Copyright 2020 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
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

// nni_reap_node is to be inserted inline into structures
// for subsystems that wish to support deferred reaping.
// It should be zeroed at object initialization, but apart
// from that it must not be touched directly except by the
// reap subsystem.
typedef struct nni_reap_node nni_reap_node;
struct nni_reap_node {
	nni_reap_node *rn_next;
};

// nni_reap_list is for subsystems to define their own reap lists.
// This allows for the reap linkage to be restricted to a single
// pointer.  Subsystems should initialize rl_offset and rl_func,
// and leave the rest zeroed.  The intention is that this is a global
// static member for each subsystem.
typedef struct nni_reap_list nni_reap_list;
struct nni_reap_list {
	nni_reap_list *rl_next;   // linkage in global reap list
	nni_reap_node *rl_nodes;  // list of nodes to reap
	size_t         rl_offset; // offset of reap_node within member.
	nni_cb         rl_func;   // function called to reap the item
	bool           rl_inited; // initialized means it is linked in the list
};

// nni_reap performs an asynchronous reap of an item.  This allows functions
// it calls to acquire locks or resources without worrying about deadlocks
// (such as from a completion callback.)  The called function should avoid
// blocking for too long if possible, since only one reap thread is present
// in the system.  The intended usage is for an nni_reap_node to be a member
// of the structure to be reaped, and and then this function is called to
// finalize it.
//
// Note that is is possible to re-queue an item to reap on the reap list.
// This is useful if, for example, a reference count indicates that the item
// is busy.  These will be queued at the end of the reap list.  This will
// allow a dependency to defer reaping until its dependents have first been
// reaped.  HOWEVER, it is important that the item in question actually be
// part of a fully reap-able graph; otherwise this can lead to an infinite
// loop in the reap thread.

extern void nni_reap(nni_reap_list *, void *);

// nni_reap_drain waits for the reap queue to be drained.
extern void nni_reap_drain(void);

extern int  nni_reap_sys_init(void);
extern void nni_reap_sys_fini(void);

#endif // CORE_REAP_H
