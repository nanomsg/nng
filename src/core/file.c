//
// Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "core/nng_impl.h"

int
nni_file_put(const char *name, const void *data, size_t sz)
{
	return (nni_plat_file_put(name, data, sz));
}

int
nni_file_get(const char *name, void **datap, size_t *szp)
{
	return (nni_plat_file_get(name, datap, szp));
}

int
nni_file_delete(const char *name)
{
	return (nni_plat_file_delete(name));
}

bool
nni_file_is_file(const char *name)
{
	int ft;
	if ((nni_file_type(name, &ft) == 0) && (ft == NNI_FILE_TYPE_FILE)) {
		return (true);
	}
	return (false);
}

bool
nni_file_is_dir(const char *name)
{
	int ft;
	if ((nni_file_type(name, &ft) == 0) && (ft == NNI_FILE_TYPE_DIR)) {
		return (true);
	}
	return (false);
}

struct walkdata {
	nni_file_walker fn;
	void *          arg;
};

static int
plat_walker(const char *name, void *arg)
{
	struct walkdata *w = arg;
	int              rv;

	rv = w->fn(name, w->arg);
	switch (rv) {
	case NNI_FILE_WALK_CONTINUE:
		return (NNI_PLAT_FILE_WALK_CONTINUE);
	case NNI_FILE_WALK_STOP:
		return (NNI_PLAT_FILE_WALK_STOP);
	case NNI_FILE_WALK_PRUNE_CHILD:
		return (NNI_PLAT_FILE_WALK_PRUNE_CHILD);
	case NNI_FILE_WALK_PRUNE_SIB:
		return (NNI_PLAT_FILE_WALK_PRUNE_SIB);
	}
	// We treat any other value as a stop condition.  The program
	// is returning something invalid.
	return (NNI_PLAT_FILE_WALK_STOP);
}

int
nni_file_walk(const char *name, nni_file_walker walker, void *arg, int flags)
{
	struct walkdata w;
	int             wflags = 0;

	w.fn  = walker;
	w.arg = arg;

	if (flags & NNI_FILE_WALK_FILES_ONLY) {
		wflags |= NNI_PLAT_FILE_WALK_FILES_ONLY;
	}
	if (flags & NNI_FILE_WALK_SHALLOW) {
		wflags |= NNI_PLAT_FILE_WALK_SHALLOW;
	}

	return (nni_plat_file_walk(name, plat_walker, &w, wflags));
}

int
nni_file_type(const char *name, int *ftype)
{
	int rv;
	int t;

	if ((rv = nni_plat_file_type(name, &t)) != 0) {
		return (rv);
	}

	switch (t) {
	case NNI_PLAT_FILE_TYPE_FILE:
		*ftype = NNI_FILE_TYPE_FILE;
		break;
	case NNI_PLAT_FILE_TYPE_DIR:
		*ftype = NNI_FILE_TYPE_DIR;
		break;
	default:
		*ftype = NNI_FILE_TYPE_OTHER;
		break;
	}
	return (0);
}

char *
nni_file_join(const char *dir, const char *file)
{
	return (nni_plat_join_dir(dir, file));
}

const char *
nni_file_basename(const char *path)
{
	return (nni_plat_file_basename(path));
}

struct nni_file_lockh {
	nni_plat_flock lk;
};

int
nni_file_lock(const char *path, nni_file_lockh **hp)
{
	nni_file_lockh *h;
	int             rv;
	if ((h = NNI_ALLOC_STRUCT(h)) == NULL) {
		return (NNG_ENOMEM);
	}
	rv = nni_plat_file_lock(path, &h->lk);
	if (rv != 0) {
		NNI_FREE_STRUCT(h);
		return (rv);
	}
	*hp = h;
	return (0);
}

void
nni_file_unlock(nni_file_lockh *h)
{
	nni_plat_file_unlock(&h->lk);
	NNI_FREE_STRUCT(h);
}
