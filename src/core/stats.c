//
// Copyright 2020 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <stdio.h>
#include <string.h>

#include "core/nng_impl.h"

typedef struct nng_stat nni_stat;

struct nng_stat {
	const nni_stat_info *s_info;
	const nni_stat_item *s_item; // Used during snapshot collection
	nni_list             s_children;
	nni_stat            *s_parent;
	nni_list_node        s_node;
	nni_time             s_timestamp;
	union {
		int      sv_id;
		bool     sv_bool;
		uint64_t sv_value;
		char    *sv_string;
	} s_val;
};

#ifdef NNG_ENABLE_STATS
static nni_stat_info stats_root_info = {
	.si_name = "",
	.si_desc = "all statistics",
	.si_type = NNG_STAT_SCOPE,
};

static nni_stat_item stats_root = {
	.si_children = NNI_LIST_INITIALIZER(
	    stats_root.si_children, nni_stat_item, si_node),
	.si_info = &stats_root_info,
};
static nni_mtx stats_lock     = NNI_MTX_INITIALIZER;
static nni_mtx stats_val_lock = NNI_MTX_INITIALIZER;
#endif

void
nni_stat_add(nni_stat_item *parent, nni_stat_item *child)
{
#ifdef NNG_ENABLE_STATS
	// Make sure that the lists for both children and parents
	// are correctly initialized.
	if (parent->si_children.ll_head.ln_next == NULL) {
		NNI_LIST_INIT(&parent->si_children, nni_stat_item, si_node);
	}
	if (child->si_children.ll_head.ln_next == NULL) {
		NNI_LIST_INIT(&child->si_children, nni_stat_item, si_node);
	}
	nni_list_append(&parent->si_children, child);
#else
	NNI_ARG_UNUSED(parent);
	NNI_ARG_UNUSED(child);
#endif
}

// nni_stat_register registers a stat tree, acquiring the lock
// on the stats structures before doing so.
void
nni_stat_register(nni_stat_item *child)
{
#ifdef NNG_ENABLE_STATS
	nni_mtx_lock(&stats_lock);
	nni_stat_add(&stats_root, child);
	nni_mtx_unlock(&stats_lock);
#else
	NNI_ARG_UNUSED(child);
#endif
}

#ifdef NNG_ENABLE_STATS
void
stat_unregister(nni_stat_item *item)
{
	nni_stat_item *child;
	while ((child = nni_list_first(&item->si_children)) != NULL) {
		stat_unregister(child);
	}
	if ((item->si_info->si_alloc) &&
	    (item->si_info->si_type == NNG_STAT_STRING)) {
		nni_strfree(item->si_u.sv_string);
		item->si_u.sv_string = NULL;
	}
	nni_list_node_remove(&item->si_node);
}
#endif

void
nni_stat_unregister(nni_stat_item *item)
{
#ifdef NNG_ENABLE_STATS
	nni_mtx_lock(&stats_lock);
	stat_unregister(item);
	nni_mtx_unlock(&stats_lock);
#else
	NNI_ARG_UNUSED(item);
#endif
}

void
nni_stat_init(nni_stat_item *item, const nni_stat_info *info)
{
#ifdef NNG_ENABLE_STATS
	memset(item, 0, sizeof(*item));
	NNI_LIST_INIT(&item->si_children, nni_stat_item, si_node);
	item->si_info = info;
#else
	NNI_ARG_UNUSED(item);
	NNI_ARG_UNUSED(info);
#endif
}

void
nni_stat_inc(nni_stat_item *item, uint64_t inc)
{
#ifdef NNG_ENABLE_STATS
	if (item->si_info->si_atomic) {
		nni_atomic_add64(&item->si_u.sv_atomic, inc);
	} else {
		item->si_u.sv_number += inc;
	}
#else
	NNI_ARG_UNUSED(item);
	NNI_ARG_UNUSED(inc);
#endif
}

void
nni_stat_dec(nni_stat_item *item, uint64_t inc)
{
#ifdef NNG_ENABLE_STATS

	if (item->si_info->si_atomic) {
		nni_atomic_sub64(&item->si_u.sv_atomic, inc);
	} else {
		item->si_u.sv_number -= inc;
	}
#else
	NNI_ARG_UNUSED(item);
	NNI_ARG_UNUSED(inc);
#endif
}

void
nni_stat_set_id(nni_stat_item *item, int id)
{
#ifdef NNG_ENABLE_STATS
	// IDs don't change, so just set it.
	item->si_u.sv_id = id;
#else
	NNI_ARG_UNUSED(item);
	NNI_ARG_UNUSED(id);
#endif
}

void
nni_stat_set_bool(nni_stat_item *item, bool b)
{
#ifdef NNG_ENABLE_STATS
	// bool is atomic by definitions.
	item->si_u.sv_bool = b;
#else
	NNI_ARG_UNUSED(item);
	NNI_ARG_UNUSED(b);
#endif
}

void
nni_stat_set_string(nni_stat_item *item, const char *s)
{
#ifdef NNG_ENABLE_STATS
	const nni_stat_info *info = item->si_info;
	char                *old  = item->si_u.sv_string;

	nni_mtx_lock(&stats_val_lock);
	if ((s != NULL) && (old != NULL) && (strcmp(s, old) == 0)) {
		// no change
		nni_mtx_unlock(&stats_val_lock);
		return;
	}

	if (!info->si_alloc) {
		// no allocation, just set it.
		item->si_u.sv_string = (char *) s;
		nni_mtx_unlock(&stats_val_lock);
		return;
	}

	item->si_u.sv_string = nni_strdup(s);
	nni_mtx_unlock(&stats_val_lock);

	nni_strfree(old);
#else
	NNI_ARG_UNUSED(item);
	NNI_ARG_UNUSED(s);
#endif
}

void
nni_stat_set_value(nni_stat_item *item, uint64_t v)
{
#ifdef NNG_ENABLE_STATS
	if (item->si_info->si_atomic) {
		nni_atomic_set64(&item->si_u.sv_atomic, v);
	} else {
		item->si_u.sv_number = v;
	}
#else
	NNI_ARG_UNUSED(item);
	NNI_ARG_UNUSED(v);
#endif
}

void
nng_stats_free(nni_stat *st)
{
#ifdef NNG_ENABLE_STATS
	nni_stat *child;

	while ((child = nni_list_first(&st->s_children)) != NULL) {
		nni_list_remove(&st->s_children, child);
		nng_stats_free(child);
	}
	if (st->s_info->si_alloc) {
		nni_strfree(st->s_val.sv_string);
	}
	NNI_FREE_STRUCT(st);
#else
	NNI_ARG_UNUSED(st);
#endif
}

#ifdef NNG_ENABLE_STATS
static int
stat_make_tree(nni_stat_item *item, nni_stat **sp)
{
	nni_stat      *stat;
	nni_stat_item *child;

	if ((stat = NNI_ALLOC_STRUCT(stat)) == NULL) {
		return (NNG_ENOMEM);
	}
	NNI_LIST_INIT(&stat->s_children, nni_stat, s_node);

	stat->s_info   = item->si_info;
	stat->s_item   = item;
	stat->s_parent = NULL;

	NNI_LIST_FOREACH (&item->si_children, child) {
		nni_stat *cs;
		int       rv;
		if ((rv = stat_make_tree(child, &cs)) != 0) {
			nng_stats_free(stat);
			return (rv);
		}
		nni_list_append(&stat->s_children, cs);
		cs->s_parent = stat;
	}
	*sp = stat;
	return (0);
}

static void
stat_update(nni_stat *stat)
{
	const nni_stat_item *item = stat->s_item;
	const nni_stat_info *info = item->si_info;
	char                *old;
	char                *str;

	switch (info->si_type) {
	case NNG_STAT_SCOPE:
	case NNG_STAT_ID:
		stat->s_val.sv_id = item->si_u.sv_id;
		break;
	case NNG_STAT_BOOLEAN:
		stat->s_val.sv_bool = item->si_u.sv_bool;
		break;
	case NNG_STAT_COUNTER:
	case NNG_STAT_LEVEL:
		if (info->si_atomic) {
			stat->s_val.sv_value = nni_atomic_get64(
			    (nni_atomic_u64 *) &item->si_u.sv_atomic);
		} else {
			stat->s_val.sv_value = item->si_u.sv_number;
		}
		break;
	case NNG_STAT_STRING:
		nni_mtx_lock(&stats_val_lock);
		old = stat->s_val.sv_string;
		str = item->si_u.sv_string;

		// If we have to allocate a new string, do so.  But
		// only do it if new string is different.
		if ((info->si_alloc) && (str != NULL) &&
		    ((old == NULL) || (strcmp(str, old) != 0))) {

			stat->s_val.sv_string = nni_strdup(str);
			nni_strfree(old);

		} else if (info->si_alloc) {
			nni_strfree(stat->s_val.sv_string);
			stat->s_val.sv_string = NULL;

		} else {
			stat->s_val.sv_string = str;
		}
		nni_mtx_unlock(&stats_val_lock);
		break;
	}
	stat->s_timestamp = nni_clock();
}

static void
stat_update_tree(nni_stat *stat)
{
	nni_stat *child;
	stat_update(stat);
	NNI_LIST_FOREACH (&stat->s_children, child) {
		stat_update_tree(child);
	}
}

int
nni_stat_snapshot(nni_stat **statp, nni_stat_item *item)
{
	int       rv;
	nni_stat *stat;

	if (item == NULL) {
		item = &stats_root;
	}
	nni_mtx_lock(&stats_lock);
	if ((rv = stat_make_tree(item, &stat)) != 0) {
		nni_mtx_unlock(&stats_lock);
		return (rv);
	}
	stat_update_tree(stat);
	nni_mtx_unlock(&stats_lock);
	*statp = stat;
	return (0);
}
#endif

int
nng_stats_get(nng_stat **statp)
{
#ifdef NNG_ENABLE_STATS
	int rv;
	if ((rv = nni_init()) != 0) {
		return (rv);
	}
	return (nni_stat_snapshot(statp, &stats_root));
#else
	NNI_ARG_UNUSED(statp);
	return (NNG_ENOTSUP);
#endif
}

nng_stat *
nng_stat_parent(nng_stat *stat)
{
	return (stat->s_parent);
}

nng_stat *
nng_stat_next(nng_stat *stat)
{
	if (stat->s_parent == NULL) {
		return (NULL); // Root node, no siblings.
	}
	return (nni_list_next(&stat->s_parent->s_children, stat));
}

nng_stat *
nng_stat_child(nng_stat *stat)
{
	return (nni_list_first(&stat->s_children));
}

const char *
nng_stat_name(nni_stat *stat)
{
	return (stat->s_info->si_name);
}

uint64_t
nng_stat_value(nni_stat *stat)
{
	return (stat->s_val.sv_value);
}

bool
nng_stat_bool(nni_stat *stat)
{
	return (stat->s_val.sv_bool);
}

const char *
nng_stat_string(nng_stat *stat)
{
	if (stat->s_info->si_type != NNG_STAT_STRING) {
		return ("");
	}
	return (stat->s_val.sv_string);
}

uint64_t
nng_stat_timestamp(nng_stat *stat)
{
	return ((uint64_t) stat->s_timestamp);
}

int
nng_stat_type(nng_stat *stat)
{
	return (stat->s_info->si_type);
}

int
nng_stat_unit(nng_stat *stat)
{
	return (stat->s_info->si_unit);
}

const char *
nng_stat_desc(nng_stat *stat)
{
	return (stat->s_info->si_desc);
}

nng_stat *
nng_stat_find(nng_stat *stat, const char *name)
{
	nng_stat *child;
	if (stat == NULL) {
		return (NULL);
	}
	if (strcmp(name, stat->s_info->si_name) == 0) {
		return (stat);
	}
	NNI_LIST_FOREACH (&stat->s_children, child) {
		nng_stat *result;
		if ((result = nng_stat_find(child, name)) != NULL) {
			return (result);
		}
	}
	return (NULL);
}

nng_stat *
nng_stat_find_scope(nng_stat *stat, const char *name, int id)
{
	nng_stat *child;
	if (stat == NULL) {
		return (NULL);
	}
	if ((stat->s_val.sv_id == id) &&
	    (stat->s_info->si_type == NNG_STAT_SCOPE) &&
	    (strcmp(name, stat->s_info->si_name) == 0)) {
		return (stat);
	}
	NNI_LIST_FOREACH (&stat->s_children, child) {
		nng_stat *result;
		if ((result = nng_stat_find(child, name)) != NULL) {
			return (result);
		}
	}
	return (NULL);
}

nng_stat *
nng_stat_find_socket(nng_stat *stat, nng_socket s)
{
	return (nng_stat_find_scope(stat, "socket", nng_socket_id(s)));
}

nng_stat *
nng_stat_find_dialer(nng_stat *stat, nng_dialer d)
{
	return (nng_stat_find_scope(stat, "dialer", nng_dialer_id(d)));
}

nng_stat *
nng_stat_find_listener(nng_stat *stat, nng_listener l)
{
	return (nng_stat_find_scope(stat, "listener", nng_listener_id(l)));
}

#ifdef NNG_ENABLE_STATS
void
stat_sprint_scope(nni_stat *stat, char **scope, int *lenp)
{
	if (stat->s_parent != NULL) {
		stat_sprint_scope(stat->s_parent, scope, lenp);
	}
	if (strlen(stat->s_info->si_name) > 0) {
		snprintf(*scope, *lenp, "%s#%d.", stat->s_info->si_name,
		    stat->s_val.sv_id);
	} else {
		(*scope)[0] = '\0';
	}
	*lenp -= (int) strlen(*scope);
	*scope += strlen(*scope);
}
#endif

void
nng_stats_dump(nng_stat *stat)
{
#ifdef NNG_ENABLE_STATS
	static char        buf[128]; // to minimize recursion, not thread safe
	int                len;
	char              *scope;
	char              *indent = "        ";
	unsigned long long val;
	nni_stat          *child;

	switch (nng_stat_type(stat)) {
	case NNG_STAT_SCOPE:
		scope = buf;
		len   = sizeof(buf);
		stat_sprint_scope(stat, &scope, &len);
		len = (int) strlen(buf);
		if (len > 0) {
			if (buf[len - 1] == '.') {
				buf[--len] = '\0';
			}
		}
		if (len > 0) {
			nni_plat_printf("\n%s:\n", buf);
		}
		break;
	case NNG_STAT_STRING:
		nni_plat_printf("%s%-32s\"%s\"\n", indent, nng_stat_name(stat),
		    nng_stat_string(stat));
		break;
	case NNG_STAT_BOOLEAN:
		nni_plat_printf("%s%-32s%s\n", indent, nng_stat_name(stat),
		    nng_stat_bool(stat) ? "true" : "false");
		break;
	case NNG_STAT_LEVEL:
	case NNG_STAT_COUNTER:
		val = nng_stat_value(stat);
		nni_plat_printf(
		    "%s%-32s%llu", indent, nng_stat_name(stat), val);
		switch (nng_stat_unit(stat)) {
		case NNG_UNIT_BYTES:
			nni_plat_printf(" bytes\n");
			break;
		case NNG_UNIT_MESSAGES:
			nni_plat_printf(" msgs\n");
			break;
		case NNG_UNIT_MILLIS:
			nni_plat_printf(" ms\n");
			break;
		case NNG_UNIT_NONE:
		case NNG_UNIT_EVENTS:
		default:
			nni_plat_printf("\n");
			break;
		}
		break;
	case NNG_STAT_ID:
		val = nng_stat_value(stat);
		nni_plat_printf(
		    "%s%-32s%llu\n", indent, nng_stat_name(stat), val);
		break;
	default:
		nni_plat_printf("%s%-32s<?>\n", indent, nng_stat_name(stat));
		break;
	}

	NNI_LIST_FOREACH (&stat->s_children, child) {
		nng_stats_dump(child);
	}
#else
	NNI_ARG_UNUSED(stat);
#endif
}
