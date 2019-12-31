//
// Copyright 2019 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#ifndef CORE_STATS_H
#define CORE_STATS_H

#include "core/defs.h"

// Statistics support.  This is inspired in part by the Solaris
// kstats framework, but we've simplified and tuned it for our use.
//
// Collection of the stats will be done in two steps.  First we
// will walk the list of stats, with the chain held, allocating
// a user local copy of the stat and pointers.
//
// In phase 2, we run the update, and copy the values. We conditionally
// acquire the lock on the stat first though.

typedef struct nni_stat_item nni_stat_item;

typedef void (*nni_stat_update)(nni_stat_item *, void *);
typedef enum nng_stat_type_enum nni_stat_type;
typedef enum nng_unit_enum      nni_stat_unit;

// nni_stat_item is used by providers.  Providers should avoid accessing
// this directly, but use accessors below.  It is important that we offer
// this structure so that providers can declare them inline, in order to
// avoid having to spend dereference costs or (worse) to have to include
// extra conditionals on hot code paths.
struct nni_stat_item {
#ifdef NNG_ENABLE_STATS
	nni_list_node   si_node;     // list node, framework use only
	nni_stat_item * si_parent;   // link back to parent, framework use only
	nni_list        si_children; // children, framework use only
	const char *    si_name;     // name of statistic
	const char *    si_desc;     // description of statistic (English)
	nni_mtx *       si_lock;     // lock for accessing, can be NULL
	void *          si_private;  // provider private pointer
	nni_stat_type   si_type;     // type of stat, e.g. NNG_STAT_LEVEL
	nni_stat_unit   si_unit;     // units, e.g. NNG_UNIT_MILLIS
	nni_stat_update si_update;   // update function (can be NULL)
	const char *    si_string;   // string value (NULL for numerics)
	uint64_t        si_number;   // numeric value
	nni_atomic_u64  si_atomic;   // atomic value
#else
	char		si_disabled; // place holder, cannot be empty in C
#endif
};

// nni_stat_add adds a statistic, but the operation is unlocked, and the
// add is to an unregistered stats tree.
void nni_stat_add(nni_stat_item *, nni_stat_item *);

// nni_stat_register registers a statistic tree into the global tree.
// The tree is rooted at the root.  This is a locked operation.
void nni_stat_register(nni_stat_item *);

// nni_stat_unregister removes the entire tree.  This is a locked operation.
void nni_stat_unregister(nni_stat_item *);

void nni_stat_set_value(nni_stat_item *, uint64_t);
void nni_stat_set_lock(nni_stat_item *, nni_mtx *);
void nni_stat_set_update(nni_stat_item *, nni_stat_update, void *);

#ifdef NNG_ENABLE_STATS
void nni_stat_init(nni_stat_item *, const char *, const char *);
void nni_stat_init_scope(nni_stat_item *, const char *, const char *);
void nni_stat_init_string(
    nni_stat_item *, const char *, const char *, const char *);
void nni_stat_init_id(nni_stat_item *, const char *, const char *, uint64_t);
void nni_stat_init_bool(nni_stat_item *, const char *, const char *, bool);
void nni_stat_init_atomic(nni_stat_item *, const char *, const char *);
void nni_stat_inc_atomic(nni_stat_item *, uint64_t);
void nni_stat_dec_atomic(nni_stat_item *, uint64_t);
void nni_stat_set_type(nni_stat_item *, int);
void nni_stat_set_unit(nni_stat_item *, int);
#else
// We override initialization so that we can avoid compiling static strings
// into the binary.  Presumably if stats are disabled, we are trying to save
// space for constrained environments.  We do evaluate an unused arg to
// prevent the compiler from bitching about unused values.
#define nni_stat_init(a, b, c) ((void) (a))
#define nni_stat_init_scope(a, b, c) ((void) (a))
#define nni_stat_init_atomic(a, b, c) ((void) (a))
#define nni_stat_init_id(a, b, c, d) ((void) (a))
#define nni_stat_init_bool(a, b, c, d) ((void) (a))
#define nni_stat_init_string(a, b, c, d) ((void) (a))
#define nni_stat_set_unit(a, b) ((void) (a))
#define nni_stat_set_type(a, b) ((void) (a))
#define nni_stat_inc_atomic(stat, inc)
#define nni_stat_dec_atomic(stat, inc)
#endif

int  nni_stat_sys_init(void);
void nni_stat_sys_fini(void);

#endif // CORE_STATS_H
