//
// Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#ifndef CORE_FILE_H
#define CORE_FILE_H

// File/Store Support
//
// Some transports require a persistent storage for things like configs,
// key material, etc.  Generally, these are all going to be relatively
// small objects (such as certificates), so we only require a synchronous
// implementation from platforms.  We provide a very limited and simple
// file API for these purposes; basic CRUD operations only, plus a way
// to iterate over names.  These are adequate for NNG's internal uses;
// applications should use normal platform-specific APIs or those in the
// standard C library.

// nni_file_put writes the named file, with the provided data,
// and the given size.  If the file already exists it is overwritten.
// The permissions on the file will allow the application to read and
// write the file, but may (should) restrict anything else beyond that
// where they can.  If the name contains platform specific directory
// separators, then any missing parent directories will be created if
// possible.
extern int nni_file_put(const char *, const void *, size_t);

// nni_plat_file_get reads the entire named file, allocating storage
// to receive the data and returning the data and the size in the
// reference arguments.  The data pointer should be freed with nni_free
// using the supplied size when no longer needed.
extern int nni_file_get(const char *, void **, size_t *);

// nni_file_delete deletes the named file.
extern int nni_file_delete(const char *);

enum nni_file_type_val {
	NNI_FILE_TYPE_FILE,
	NNI_FILE_TYPE_DIR,
	NNI_FILE_TYPE_OTHER,
};

// nni_file_exists checks if the named file exists.
extern int nni_file_type(const char *, int *);

// nni_file_walk walks a list of files.
enum nni_file_walk_result {
	NNI_FILE_WALK_CONTINUE,
	NNI_FILE_WALK_STOP,
	NNI_FILE_WALK_PRUNE_SIB,
	NNI_FILE_WALK_PRUNE_CHILD,
};

enum nni_file_walk_flags {
	NNI_FILE_WALK_DEPTH_FIRST   = 0, // get children first
	NNI_FILE_WALK_BREADTH_FIRST = 1, // get siblings first (later)
	NNI_FILE_WALK_SHALLOW       = 2, // do not descend into subdirectories
	NNI_FILE_WALK_FILES_ONLY    = 4, // directory names are not reported
};

typedef int (*nni_file_walker)(const char *, void *);
extern int nni_file_walk(const char *, nni_file_walker, void *, int);

// nni_file_join joins two path components to make a path name.
// For example. on UNIX systems nni_file_join("/tmp", "a") returns
// "/tmp/a".  The pathname returned should be freed with nni_strfree().
extern char *nni_file_join(const char *, const char *);

// nni_file_basename returns the "file" name, without the parent directory.
// The returned value generally is within the supplied path name.
extern const char *nni_file_basename(const char *);

// nni_file_is_file returns true if the path references a file.  It returns
// false if an error occurs, or the path references something else.
extern bool nni_file_is_file(const char *);

// nni_file_is_dir returns true if the path references a directroy.  It returns
// false if an error occurs, or the path references something else.
extern bool nni_file_is_dir(const char *);

typedef struct nni_file_lockh nni_file_lockh;

extern int nni_file_lock(const char *, nni_file_lockh **);

extern void nni_file_unlock(nni_file_lockh *);

#endif // CORE_FILE_H
