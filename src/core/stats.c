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
	char *         s_name;
	char *         s_desc;
	char *         s_string;
	uint64_t       s_value;
	nni_time       s_time;
	nni_stat_type  s_type;
	nni_stat_unit  s_unit;
	nni_stat_item *s_item; // Used during snapshot collection
	nni_list       s_children;
	nni_stat *     s_parent;
	nni_list_node  s_node;
};

#ifdef NNG_ENABLE_STATS
static nni_stat_item stats_root;
static nni_mtx       stats_lock;
static nni_mtx *     stats_held = NULL;
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
	child->si_parent = parent;
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

void
nni_stat_unregister(nni_stat_item *child)
{
#ifdef NNG_ENABLE_STATS
	nni_stat_item *parent;
	nni_mtx_lock(&stats_lock);
	if ((parent = child->si_parent) != NULL) {
		nni_list_remove(&parent->si_children, child);
		child->si_parent = NULL;
	}
	nni_mtx_unlock(&stats_lock);
#else
	NNI_ARG_UNUSED(child);
#endif
}

#ifdef NNG_ENABLE_STATS
void
nni_stat_init(nni_stat_item *stat, const char *name, const char *desc)
{
	NNI_LIST_INIT(&stat->si_children, nni_stat_item, si_node);
	stat->si_parent  = NULL;
	stat->si_name    = name;
	stat->si_desc    = desc;
	stat->si_lock    = NULL;
	stat->si_update  = NULL;
	stat->si_private = NULL;
	stat->si_string  = NULL;
	stat->si_number  = 0;
	stat->si_type    = NNG_STAT_COUNTER;
	stat->si_unit    = NNG_UNIT_NONE;
}

void
nni_stat_init_scope(nni_stat_item *stat, const char *name, const char *desc)
{
	nni_stat_init(stat, name, desc);
	stat->si_type = NNG_STAT_SCOPE;
	stat->si_unit = NNG_UNIT_NONE;
}

void
nni_stat_init_string(
    nni_stat_item *stat, const char *name, const char *desc, const char *str)
{
	nni_stat_init(stat, name, desc);
	stat->si_string = str;
	stat->si_type   = NNG_STAT_STRING;
	stat->si_unit   = NNG_UNIT_NONE;
}

void
nni_stat_init_id(
    nni_stat_item *stat, const char *name, const char *desc, uint64_t id)
{
	nni_stat_init(stat, name, desc);
	stat->si_number = id;
	stat->si_type   = NNG_STAT_ID;
	stat->si_unit   = NNG_UNIT_NONE;
}

void
nni_stat_init_bool(
    nni_stat_item *stat, const char *name, const char *desc, bool v)
{
	nni_stat_init(stat, name, desc);
	stat->si_number = v ? 1 : 0;
	stat->si_type   = NNG_STAT_BOOLEAN;
	stat->si_unit   = NNG_UNIT_NONE;
}

static void
stat_atomic_update(nni_stat_item *stat, void *notused)
{
	NNI_ARG_UNUSED(notused);
	stat->si_number = nni_atomic_get64(&stat->si_atomic);
}

void
nni_stat_init_atomic(nni_stat_item *stat, const char *name, const char *desc)
{
	nni_stat_init(stat, name, desc);
	stat->si_number  = 0;
	stat->si_private = NULL;
	stat->si_update  = stat_atomic_update;
	nni_atomic_init64(&stat->si_atomic);
}

void
nni_stat_inc_atomic(nni_stat_item *stat, uint64_t inc)
{
	nni_atomic_add64(&stat->si_atomic, inc);
}

void
nni_stat_dec_atomic(nni_stat_item *stat, uint64_t inc)
{
	nni_atomic_sub64(&stat->si_atomic, inc);
}
#endif

void
nni_stat_set_value(nni_stat_item *stat, uint64_t v)
{
#ifdef NNG_ENABLE_STATS
	stat->si_number = v;
#else
	NNI_ARG_UNUSED(stat);
	NNI_ARG_UNUSED(v);
#endif
}

void
nni_stat_set_lock(nni_stat_item *stat, nni_mtx *mtx)
{
#ifdef NNG_ENABLE_STATS
	stat->si_lock = mtx;
#else
	NNI_ARG_UNUSED(stat);
	NNI_ARG_UNUSED(mtx);
#endif
}

void
nni_stat_set_update(nni_stat_item *stat, nni_stat_update f, void *a)
{
#ifdef NNG_ENABLE_STATS
	stat->si_update  = f;
	stat->si_private = a;
#else
	NNI_ARG_UNUSED(stat);
	NNI_ARG_UNUSED(f);
	NNI_ARG_UNUSED(a);
#endif
}

#ifdef NNG_ENABLE_STATS
void
nni_stat_set_type(nni_stat_item *stat, int type)
{
	stat->si_type = type;
}

void
nni_stat_set_unit(nni_stat_item *stat, int unit)
{
	stat->si_unit = unit;
}
#endif

void
nng_stats_free(nni_stat *st)
{
#ifdef NNG_ENABLE_STATS
	nni_stat *child;

	while ((child = nni_list_first(&st->s_children)) != NULL) {
		nni_list_remove(&st->s_children, child);
		nng_stats_free(child);
	}
	nni_strfree(st->s_name);
	nni_strfree(st->s_desc);
	nni_strfree(st->s_string);
	NNI_FREE_STRUCT(st);
#else
	NNI_ARG_UNUSED(st);
#endif
}

#ifdef NNG_ENABLE_STATS
static int
stat_make_tree(nni_stat_item *item, nni_stat **sp)
{
	nni_stat *     stat;
	nni_stat_item *child;

	if ((stat = NNI_ALLOC_STRUCT(stat)) == NULL) {
		return (NNG_ENOMEM);
	}
	NNI_LIST_INIT(&stat->s_children, nni_stat, s_node);

	if (((stat->s_name = nni_strdup(item->si_name)) == NULL) ||
	    ((stat->s_desc = nni_strdup(item->si_desc)) == NULL)) {
		nng_stats_free(stat);
		return (NNG_ENOMEM);
	}
	if ((item->si_type == NNG_STAT_STRING) &&
	    ((stat->s_string = nni_strdup(item->si_string)) == NULL)) {
		nng_stats_free(stat);
		return (NNG_ENOMEM);
	}
	stat->s_item   = item;
	stat->s_type   = item->si_type;
	stat->s_unit   = item->si_unit;
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
	nni_stat_item *item = stat->s_item;

	if (item->si_lock != stats_held) {
		if (stats_held != NULL) {
			nni_mtx_unlock(stats_held);
			stats_held = NULL;
		}
		if (item->si_lock != NULL) {
			nni_mtx_lock(item->si_lock);
			stats_held = item->si_lock;
		}
	}
	if (item->si_update != NULL) {
		item->si_update(item, item->si_private);
	}
	stat->s_value = item->si_number;
	stat->s_time  = nni_clock();
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
	if (stats_held != NULL) {
		nni_mtx_unlock(stats_held);
		stats_held = NULL;
	}
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
	return (stat->s_name);
}

uint64_t
nng_stat_value(nni_stat *stat)
{
	return (stat->s_value);
}

const char *
nng_stat_string(nng_stat *stat)
{
	return (stat->s_string);
}

uint64_t
nng_stat_timestamp(nng_stat *stat)
{
	return ((uint64_t) stat->s_time);
}

int
nng_stat_type(nng_stat *stat)
{
	return (stat->s_type);
}

int
nng_stat_unit(nng_stat *stat)
{
	return (stat->s_unit);
}

const char *
nng_stat_desc(nng_stat *stat)
{
	return (stat->s_desc);
}

nng_stat *
nng_stat_find(nng_stat *stat, const char *name)
{
	nng_stat *child;
	if (stat == NULL) {
		return (NULL);
	}
	if (strcmp(name, stat->s_name) == 0) {
		return (stat);
	}
	NNI_LIST_FOREACH(&stat->s_children, child) {
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
	char name[16];
	(void) snprintf(name, sizeof (name), "socket%d", nng_socket_id(s));
	return (nng_stat_find(stat, name));
}

nng_stat *
nng_stat_find_dialer(nng_stat *stat, nng_dialer d)
{
	char name[16];
	(void) snprintf(name, sizeof (name), "dialer%d", nng_dialer_id(d));
	return (nng_stat_find(stat, name));
}

nng_stat *
nng_stat_find_listener(nng_stat *stat, nng_listener l)
{
	char name[16];
	(void) snprintf(name, sizeof (name), "listener%d", nng_listener_id(l));
	return (nng_stat_find(stat, name));
}

int
nni_stat_sys_init(void)
{
#ifdef NNG_ENABLE_STATS
	nni_mtx_init(&stats_lock);
	NNI_LIST_INIT(&stats_root.si_children, nni_stat_item, si_node);
	stats_root.si_name = "";
	stats_root.si_desc = "all statistics";
#endif
	return (0);
}

void
nni_stat_sys_fini(void)
{
#ifdef NNG_ENABLE_STATS
	nni_mtx_fini(&stats_lock);
#endif
}

#ifdef NNG_ENABLE_STATS
void
stat_sprint_scope(nni_stat *stat, char **scope, int *lenp)
{
	if (stat->s_parent != NULL) {
		stat_sprint_scope(stat->s_parent, scope, lenp);
	}
	if (strlen(stat->s_name) > 0) {
		snprintf(*scope, *lenp, "%s.", stat->s_name);
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
	char *             scope;
	char *             indent = "        ";
	unsigned long long val;
	nni_stat *         child;

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
		val = nng_stat_value(stat);
		nni_plat_printf("%s%-32s%s\n", indent, nng_stat_name(stat),
		    val != 0 ? "true" : "false");
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
			nni_plat_printf(" msec\n");
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
