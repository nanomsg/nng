//
// Copyright 2016 Garrett D'Amore <garrett@damore.org>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "core/nng_impl.h"
#include "core/objhash.h"

#include <string.h>

// The details of the nni_objhash are "private".
struct nni_objhash {
	size_t			oh_cap;
	size_t			oh_count;
	size_t			oh_load;
	size_t			oh_minload; // considers placeholders
	size_t			oh_maxload;
	uint32_t		oh_minval;
	uint32_t		oh_maxval;
	uint32_t		oh_dynval;
	nni_mtx			oh_lock;
	nni_cv			oh_cv;
	nni_objhash_node *	oh_nodes;
	nni_objhash_ctor	oh_ctor;
	nni_objhash_dtor	oh_dtor;
};

struct nni_objhash_node {
	uint32_t	on_id;          // the key
	uint32_t	on_skips;       // indicates
	uint32_t	on_refcnt;      // reference count
	void *		on_val;         // pointer to user data
};

int
nni_objhash_init(nni_objhash **ohp, nni_objhash_ctor ctor,
    nni_objhash_dtor dtor)
{
	nni_objhash *oh;
	int rv;

	if ((ctor == NULL) || (dtor == NULL)) {
		return (NNG_EINVAL);
	}

	if ((oh = NNI_ALLOC_STRUCT(oh)) == NULL) {
		return (NNG_ENOMEM);
	}

	if ((rv = nni_mtx_init(&oh->oh_lock)) != 0) {
		NNI_FREE_STRUCT(oh);
		return (rv);
	}

	if ((rv = nni_cv_init(&oh->oh_cv, &oh->oh_lock)) != 0) {
		nni_mtx_fini(&oh->oh_lock);
		NNI_FREE_STRUCT(oh);
		return (rv);
	}

	oh->oh_nodes = NULL;
	oh->oh_count = 0;
	oh->oh_load = 0;
	oh->oh_cap = 0;
	oh->oh_maxload = 0;
	oh->oh_minload = 0; // never shrink below this
	oh->oh_minval = 1;
	oh->oh_maxval = 0x7fffffff;
	oh->oh_dynval = nni_random() %
	    (oh->oh_maxval - oh->oh_minval) + oh->oh_minval;
	oh->oh_ctor = ctor;
	oh->oh_dtor = dtor;
	*ohp = oh;

	return (0);
}


void
nni_objhash_fini(nni_objhash *oh)
{
	if (oh == NULL) {
		return;
	}
	if (oh->oh_nodes != NULL) {
		nni_free(oh->oh_nodes, oh->oh_cap * sizeof (nni_objhash_node));
		oh->oh_nodes = NULL;
		oh->oh_cap = oh->oh_count = 0;
		oh->oh_load = oh->oh_minload = oh->oh_maxload = 0;
	}
	nni_cv_fini(&oh->oh_cv);
	nni_mtx_fini(&oh->oh_lock);
	NNI_FREE_STRUCT(oh);
}


// Inspired by Python dict implementation.  This probe will visit every
// cell.  We always hash consecutively assigned IDs.
#define NNI_OBJHASH_NEXTPROBE(h, j) \
	((((j) * 5) + 1)& (h->oh_cap - 1))


// nni_objhash_find_node finds the object hash node associated with a given id.
// The object hash lock must be held by the caller.
static nni_objhash_node *
nni_objhash_find_node(nni_objhash *oh, uint32_t id)
{
	uint32_t index;
	nni_objhash_node *node;

	if (oh->oh_count == 0) {
		return (NULL);
	}

	index = id & (oh->oh_cap - 1);

	for (;;) {
		node = &oh->oh_nodes[index];

		if ((node->on_val == NULL) && (node->on_skips == 0)) {
			return (NULL);
		}
		if (node->on_id == id) {
			return (node);
		}
		index = NNI_OBJHASH_NEXTPROBE(oh, index);
	}
}


// nni_objhash_find looks up the object, and bumps the reference on it.
// The caller should drop the reference when done by calling nni_objhash_unref.
int
nni_objhash_find(nni_objhash *oh, uint32_t id, void **valp)
{
	uint32_t index;
	nni_objhash_node *node;
	int rv;

	nni_mtx_lock(&oh->oh_lock);
	node = nni_objhash_find_node(oh, id);

	if ((node != NULL) && (node->on_val != NULL)) {
		if (valp != NULL) {
			*valp = node->on_val;
		}
		node->on_refcnt++;
		rv = 0;
	} else {
		rv = NNG_ENOENT;
	}
	nni_mtx_unlock(&oh->oh_lock);
	return (rv);
}


// Resize the object hash.  This is called internally with the lock
// for the object hash held.  Grow indicates that this is being called
// from a function that intends to add data, so extra space is needed.
static int
nni_objhash_resize(nni_objhash *oh, int grow)
{
	size_t newsize;
	size_t oldsize;
	nni_objhash_node *newnodes;
	nni_objhash_node *oldnodes;
	uint32_t i;

	if ((!grow) && (oh->oh_count == 0) && (oh->oh_cap != 0)) {
		// Table is empty, and we are unrefing.  Lets reclaim the
		// space.  Note that this means that allocations which
		// fluctuate between one and zero are going to bang on the
		// allocator a bit.  Since such cases should not be very
		// performance sensitive, this is probably okay.
		nni_free(oh->oh_nodes, oh->oh_cap * sizeof (nni_objhash_node));
		oh->oh_cap = 0;
		oh->oh_nodes = NULL;
		oh->oh_minload = 0;
		oh->oh_maxload = 0;
		return (0);
	}

	if ((oh->oh_load < oh->oh_maxload) && (oh->oh_load >= oh->oh_minload)) {
		// No resize needed.
		return (0);
	}

	oldsize = oh->oh_cap;
	newsize = oh->oh_cap;

	newsize = 8;
	while (newsize < (oh->oh_count * 2)) {
		newsize *= 2;
	}

	oldnodes = oh->oh_nodes;
	newnodes = nni_alloc(sizeof (nni_objhash_node) * newsize);
	if (newnodes == NULL) {
		return (NNG_ENOMEM);
	}
	memset(newnodes, 0, sizeof (nni_objhash_node) * newsize);

	oh->oh_nodes = newnodes;
	oh->oh_cap = newsize;
	if (newsize > 8) {
		oh->oh_minload = newsize / 8;
		oh->oh_maxload = newsize * 2 / 3;
	} else {
		oh->oh_minload = 0;
		oh->oh_maxload = 5;
	}
	for (i = 0; i < oldsize; i++) {
		uint32_t index;
		if (oldnodes[i].on_val == NULL) {
			continue;
		}
		index = oldnodes[i].on_id & (newsize - 1);
		for (;;) {
			if (newnodes[index].on_val == NULL) {
				oh->oh_load++;
				newnodes[index].on_val = oldnodes[i].on_val;
				newnodes[index].on_id = oldnodes[i].on_id;
				newnodes[index].on_refcnt =
				    oldnodes[i].on_refcnt;
				break;
			}
			newnodes[index].on_skips++;
			index = NNI_OBJHASH_NEXTPROBE(oh, index);
		}
	}
	if (oldsize != 0) {
		nni_free(oldnodes, sizeof (nni_objhash_node) * oldsize);
	}
	return (0);
}


void
nni_objhash_unref(nni_objhash *oh, uint32_t id)
{
	int rv;
	void *val;
	uint32_t index;
	nni_objhash_node *node;
	nni_objhash_dtor dtor;

	nni_mtx_lock(&oh->oh_lock);

	dtor = oh->oh_dtor;

	node = nni_objhash_find_node(oh, id);
	NNI_ASSERT(node != NULL);
	val = node->on_val;

	NNI_ASSERT(node->on_refcnt > 0);
	NNI_ASSERT(node->on_refcnt < 1000000); // reasonable limit, debug only
	node->on_refcnt--;
	if (node->on_refcnt != 0) {
		if (node->on_refcnt == 1) {
			nni_cv_wake(&oh->oh_cv);
		}
		// Still busy/referenced?
		nni_mtx_unlock(&oh->oh_lock);
		return;
	}

	index = id & (oh->oh_cap - 1);
	for (;;) {
		node = &oh->oh_nodes[index];
		if (node->on_id == id) {
			break;
		}

		NNI_ASSERT(node->on_skips != 0);
		node->on_skips--;
		if ((node->on_val == NULL) && (node->on_skips == 0)) {
			oh->oh_load--;
		}
		index = NNI_OBJHASH_NEXTPROBE(oh, index);
	}

	NNI_ASSERT(node->on_val != NULL);
	NNI_ASSERT(node->on_refcnt == 0);
	NNI_ASSERT(node->on_id == id);

	node->on_val = NULL;
	oh->oh_count--;
	if (node->on_skips == 0) {
		oh->oh_load--;
	}
	// Reclaim the buffer if we want, but preserve the limits.
	nni_objhash_resize(oh, 0);

	nni_mtx_unlock(&oh->oh_lock);

	// Now run the destructor.
	dtor(val);
}


void
nni_objhash_unref_wait(nni_objhash *oh, uint32_t id)
{
	int rv;
	void *val;
	uint32_t index;
	nni_objhash_node *node;
	nni_objhash_dtor dtor;

	nni_mtx_lock(&oh->oh_lock);

	dtor = oh->oh_dtor;

	node = nni_objhash_find_node(oh, id);
	NNI_ASSERT(node != NULL);
	val = node->on_val;

	while (node->on_refcnt != 1) {
		nni_cv_wait(&oh->oh_cv);
	}
	node->on_refcnt--;
	if (node->on_refcnt != 0) {
		if (node->on_refcnt == 1) {
			nni_cv_wake(&oh->oh_cv);
		}
		// Still busy/referenced?
		nni_mtx_unlock(&oh->oh_lock);
		return;
	}

	index = id & (oh->oh_cap - 1);
	for (;;) {
		node = &oh->oh_nodes[index];
		if (node->on_id == id) {
			break;
		}

		NNI_ASSERT(node->on_skips != 0);
		node->on_skips--;
		if ((node->on_val == NULL) && (node->on_skips == 0)) {
			oh->oh_load--;
		}
		index = NNI_OBJHASH_NEXTPROBE(oh, index);
	}

	NNI_ASSERT(node->on_val != NULL);
	NNI_ASSERT(node->on_refcnt == 0);
	NNI_ASSERT(node->on_id == id);

	node->on_val = NULL;
	oh->oh_count--;
	if (node->on_skips == 0) {
		oh->oh_load--;
	}
	// Reclaim the buffer if we want, but preserve the limits.
	nni_objhash_resize(oh, 0);

	nni_mtx_unlock(&oh->oh_lock);

	// Now run the destructor.
	dtor(val);
}


// Allocate a new object hash entry.  Note that this will execute the
// constructor with the object hash lock held.  Consequently, code that
// runs the constructor must not run for long periods of time, since that
// can block all other uses of the object hash.
int
nni_objhash_alloc(nni_objhash *oh, uint32_t *idp, void **valp)
{
	uint32_t id;
	uint32_t index;
	nni_objhash_node *node;

	nni_mtx_lock(&oh->oh_lock);

	if (oh->oh_count > (oh->oh_maxval - oh->oh_minval)) {
		// Really more like ENOSPC.. the table is filled to max.
		nni_mtx_unlock(&oh->oh_lock);
		return (NNG_ENOMEM);
	}

	nni_objhash_resize(oh, 1);

	for (;;) {
		id = oh->oh_dynval;
		oh->oh_dynval++;
		if ((oh->oh_dynval > oh->oh_maxval) ||
		    (oh->oh_dynval < oh->oh_minval)) {
			oh->oh_dynval = oh->oh_minval;
		}

		if (nni_objhash_find_node(oh, id) == NULL) {
			// We can use this ID, great!
			break;
		}
	}

	// We know the ID we're going to use, but we have to walk again,
	// because we need to note whether we had to skip (probe), and mark
	// them so they don't get nuked along the way.
	// check to see if anything is located there.
	index = id & (oh->oh_cap - 1);
	for (;;) {
		node = &oh->oh_nodes[index];
		if (node->on_val == NULL) {
			break;
		}
		NNI_ASSERT(node->on_id != id);
		node->on_skips++;
		index = NNI_OBJHASH_NEXTPROBE(oh, index);
	}

	node->on_id = id;
	node->on_refcnt++;

	node->on_val = oh->oh_ctor(id);

	if (node->on_val == NULL) {
		// Constructor failed; walk *again* to undo the skip increments.
		node->on_refcnt--;
		index = id & (oh->oh_cap - 1);
		for (;;) {
			node = &oh->oh_nodes[index];
			if (node->on_val == NULL) {
				NNI_ASSERT(node->on_id == id);
				break;
			}
			NNI_ASSERT(node->on_skips != 0);
			node->on_skips--;
			index = NNI_OBJHASH_NEXTPROBE(oh, index);
		}

		nni_mtx_unlock(&oh->oh_lock);
		return (NNG_ENOMEM);    // no other return from ctor
	}

	oh->oh_count++;
	if (node->on_skips == 0) {
		oh->oh_load++;
	}
	*valp = node->on_val;
	*idp = id;
	nni_mtx_unlock(&oh->oh_lock);
	return (0);
}


size_t
nni_objhash_count(nni_objhash *oh)
{
	return (oh->oh_count);
}
