//
// Copyright 2016 Garrett D'Amore <garrett@damore.org>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#ifndef CORE_OBJHASH_H
#define CORE_OBJHASH_H

#include "core/nng_impl.h"

// Object Hash.  This is a generic object manager, which lets us deal
// with reference counting of objects, and provides a unique ID for
// objects that will not generally be reused.  Object Hash manages it's
// own locking.  Object IDs start from a random positive value, and
// generally increment.  The ID assigned to an object will always be
// positive.
//
// Similar to our linked lists, consumers must supply a node structure
// in their object.  The implementation uses this for reference counting
// and so forth.
//
// In terms of implementation, the underlying hash uses open addressing,
// combined with an improved probe (taken from Python) to avoid collisions.
// Our algorithm just uses the low order bits, and we use table sizes that
// are powers of two to make the modulo dirt cheap.
//

typedef struct nni_objhash      nni_objhash;
typedef struct nni_objhash_node nni_objhash_node;

// Object constructor function.  This is  expected to allocate an object.
// It takes the generated object ID as an argument, which it can store on
// the object itself.  It should return NULL if resources cannot be allocated;
// there are no other valid reasons for this to fail.
typedef void *(*nni_objhash_ctor)(uint32_t);

// Object destructor function.  This should release any resources and perform
// any other deinitialization.
typedef void (*nni_objhash_dtor)(void *);

// nni_objhash_init initializes the object hash; the constructor and and
// destructor functions are supplied.
extern int nni_objhash_init(
    nni_objhash **, nni_objhash_ctor, nni_objhash_dtor);

extern void nni_objhash_fini(nni_objhash *);

extern int    nni_objhash_find(nni_objhash *, uint32_t, void **);
extern void   nni_objhash_unref(nni_objhash *, uint32_t);
extern void   nni_objhash_unref_wait(nni_objhash *, uint32_t);
extern int    nni_objhash_alloc(nni_objhash *, uint32_t *, void **);
extern size_t nni_objhash_count(nni_objhash *);

#endif // CORE_OBJHASH_H
