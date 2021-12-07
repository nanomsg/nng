//
// Copyright 2020 Staysail Systems, Inc. <info@staysail.tech>
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
// kernel stats framework, but we've simplified and tuned it for our use.
//
// Collection of the stats will be done in two steps.  First we
// will walk the list of stats, with the chain held, allocating
// a user local copy of the stat and pointers.
//
// In phase 2, we run the update, and copy the values. We conditionally
// acquire the lock on the stat first though.

typedef struct nni_stat_item nni_stat_item;
typedef struct nni_stat_info nni_stat_info;

typedef void (*nni_stat_update)(nni_stat_item *);
typedef enum nng_stat_type_enum nni_stat_type;
typedef enum nng_unit_enum      nni_stat_unit;

// nni_stat_item is used by providers.  Providers should avoid accessing
// this directly, but use accessors below.  It is important that we offer
// this structure so that providers can declare them inline, in order to
// avoid having to spend dereference costs or (worse) to have to include
// extra conditionals on hot code paths.
struct nni_stat_item {
	nni_list_node        si_node;     // list node, framework use only
	nni_list             si_children; // children, framework use only
	const nni_stat_info *si_info;     // statistic description
	union {
		uint64_t       sv_number;
		nni_atomic_u64 sv_atomic;
		char *         sv_string;
		bool           sv_bool;
		int            sv_id;
	} si_u;
};

struct nni_stat_info {
	const char *    si_name;       // name of statistic
	const char *    si_desc;       // description of statistic (English)
	nni_stat_type   si_type;       // statistic type, e.g. NNG_STAT_LEVEL
	nni_stat_unit   si_unit;       // statistic unit, e.g. NNG_UNIT_MILLIS
	nni_stat_update si_update;     // update function (can be NULL)
	bool            si_atomic : 1; // stat is atomic
	bool            si_alloc : 1;  // stat string is allocated
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
void nni_stat_set_id(nni_stat_item *, int);
void nni_stat_set_bool(nni_stat_item *, bool);
void nni_stat_set_string(nni_stat_item *, const char *);
void nni_stat_init(nni_stat_item *, const nni_stat_info *);
void nni_stat_inc(nni_stat_item *, uint64_t);
void nni_stat_dec(nni_stat_item *, uint64_t);

#endif // CORE_STATS_H
