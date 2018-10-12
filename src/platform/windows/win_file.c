//
// Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
// Copyright 2018 QXSoftware <lh563566994@126.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "core/nng_impl.h"

#ifdef NNG_PLATFORM_WINDOWS

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>

// File support.

static char *
nni_plat_find_pathsep(char *path)
{
	char *p;
	// Legal path separators are "\\" and "/" under Windows.
	// This is sort of a poormans strchr, but with the two specific
	// separator characters instead.
	for (p = path; *p != '\0'; p++) {
		if ((*p == '/') || (*p == '\\')) {
			return (p);
		}
	}
	return (NULL);
}

static int
nni_plat_make_parent_dirs(const char *path)
{
	char *dup;
	char *p;

	// creates everything up until the last component.
	if ((dup = nni_strdup(path)) == NULL) {
		return (NNG_ENOMEM);
	}

	// Skip past C:, C:\, \\ and \ style prefixes, because we cannot
	// create those things as directories -- they should already exist.
	p = dup;
	if (isalpha(p[0]) && (p[1] == ':')) {
		p += 2;
		if ((p[0] == '\\') || (p[0] == '/')) {
			p++;
		}
	} else if ((p[0] == '\\') && (p[1] == '\\')) {
		p += 2;
	} else if ((p[0] == '\\') || (p[0] == '/')) {
		p++;
	}

	while ((p = nni_plat_find_pathsep(p)) != NULL) {
		*p = '\0';

		if (!CreateDirectory(dup, NULL)) {
			int rv = GetLastError();
			if (rv != ERROR_ALREADY_EXISTS) {
				nni_strfree(dup);
				return (nni_win_error(rv));
			}
		}
		*p = '\\'; // Windows prefers this though.

		// collapse grouped pathsep characters
		while ((*p == '/') || (*p == '\\')) {
			p++;
		}
	}
	nni_strfree(dup);
	return (0);
}

// nni_plat_file_put writes the named file, with the provided data,
// and the given size.  If the file already exists it is overwritten.
// The permissions on the file should be limited to read and write
// access by the entity running the application only.
int
nni_plat_file_put(const char *name, const void *data, size_t len)
{
	HANDLE h;
	int    rv = 0;
	DWORD  nwrite;

	if ((rv = nni_plat_make_parent_dirs(name)) != 0) {
		return (rv);
	}

	h = CreateFile(name, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
	    FILE_ATTRIBUTE_NORMAL, NULL);
	if (h == INVALID_HANDLE_VALUE) {
		return (nni_win_error(GetLastError()));
	}

	if (!WriteFile(h, data, (DWORD) len, &nwrite, NULL)) {
		rv = nni_win_error(GetLastError());
		(void) DeleteFile(name);
		goto done;
	}
	// These are regular files, synchronous operations.  If we got a
	// short write, then we should have gotten an error!
	NNI_ASSERT(nwrite == len);

done:
	(void) CloseHandle(h);
	return (rv);
}

// nni_plat_file_get reads the entire named file, allocating storage
// to receive the data and returning the data and the size in the
// reference arguments.
int
nni_plat_file_get(const char *name, void **datap, size_t *lenp)
{
	int    rv = 0;
	void * data;
	DWORD  sz;
	DWORD  nread;
	HANDLE h;

	h = CreateFile(name, GENERIC_READ, 0, NULL, OPEN_EXISTING,
	    FILE_ATTRIBUTE_NORMAL, NULL);
	if (h == INVALID_HANDLE_VALUE) {
		return (nni_win_error(GetLastError()));
	}
	// We choose not to support extraordinarily large files (>4GB)
	if ((sz = GetFileSize(h, NULL)) == INVALID_FILE_SIZE) {
		rv = nni_win_error(GetLastError());
		goto done;
	}
	if (sz > 0) {
		if ((data = nni_alloc((size_t) sz)) == NULL) {
			rv = NNG_ENOMEM;
			goto done;
		}
		if (!ReadFile(h, data, sz, &nread, NULL)) {
			rv = nni_win_error(GetLastError());
			nni_free(data, sz);
			goto done;
		}
	} else {
		data  = NULL;
		nread = 0;
	}

	// We can get a short read, indicating end of file.  We return
	// the actual number of bytes read.  The fact that the data buffer
	// is larger than this is ok, because our nni_free() routine just
	// uses HeapFree(), which doesn't need a matching size.

	*datap = data;
	*lenp  = (size_t) nread;
done:
	(void) CloseHandle(h);
	return (rv);
}

// nni_plat_file_delete deletes the named file.
int
nni_plat_file_delete(const char *name)
{
	int rv;
	if (RemoveDirectory(name)) {
		return (0);
	}
	if (DeleteFile(name)) {
		return (0);
	}
	if ((rv = nni_win_error(GetLastError())) == NNG_ENOENT) {
		return (0);
	}
	return (rv);
}

static int
nni_plat_file_walk_inner(const char *name, nni_plat_file_walker walkfn,
    void *arg, int flags, bool *stop)
{
	char            path[MAX_PATH + 1];
	int             rv;
	int             walkrv;
	HANDLE          dirh;
	WIN32_FIND_DATA data;

	_snprintf(path, sizeof(path), "%s\\%s", name, "*");
	if ((dirh = FindFirstFile(path, &data)) == INVALID_HANDLE_VALUE) {
		rv = nni_win_error(GetLastError());
		return (rv);
	}

	for (;;) {
		// We never return hidden files.
		if ((data.dwFileAttributes & FILE_ATTRIBUTE_HIDDEN) ||
		    (strcmp(data.cFileName, ".") == 0) ||
		    (strcmp(data.cFileName, "..") == 0)) {
			goto next_file;
		}
		_snprintf(path, sizeof(path), "%s\\%s", name, data.cFileName);
		walkrv = NNI_PLAT_FILE_WALK_CONTINUE;
		if (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
			if ((flags & NNI_PLAT_FILE_WALK_FILES_ONLY) == 0) {
				walkrv = walkfn(path, arg);
			}

			if (((flags & NNI_PLAT_FILE_WALK_SHALLOW) == 0) &&
			    (walkrv != NNI_PLAT_FILE_WALK_STOP) &&
			    (walkrv != NNI_PLAT_FILE_WALK_PRUNE_CHILD)) {
				rv = nni_plat_file_walk_inner(
				    path, walkfn, arg, flags, stop);
				if (rv != 0) {
					if (rv == NNG_ENOENT) {
						rv = 0; // File deleted.
					}
					FindClose(dirh);
					return (rv);
				}
			}
		} else if (data.dwFileAttributes & FILE_ATTRIBUTE_DEVICE) {
			if ((flags & NNI_PLAT_FILE_WALK_FILES_ONLY) == 0) {
				walkrv = walkfn(path, arg);
			}
		} else {
			walkrv = walkfn(path, arg);
		}

		if (*stop) {
			walkrv = NNI_PLAT_FILE_WALK_STOP;
		}

		switch (walkrv) {
		case NNI_PLAT_FILE_WALK_STOP:
			*stop = true;
			FindClose(dirh);
			return (0);
		case NNI_PLAT_FILE_WALK_PRUNE_SIB:
			FindClose(dirh);
			return (0);
		}

	next_file:
		if (!FindNextFile(dirh, &data)) {
			rv = GetLastError();
			FindClose(dirh);
			if (rv == ERROR_NO_MORE_FILES) {
				break;
			}
			return (nni_win_error(rv));
		}
	}

	return (0);
}

int
nni_plat_file_walk(
    const char *name, nni_plat_file_walker walkfn, void *arg, int flags)
{
	bool stop = false;
	return (nni_plat_file_walk_inner(name, walkfn, arg, flags, &stop));
}

char *
nni_plat_temp_dir(void)
{
	char path[MAX_PATH + 1];

	if (!GetTempPath(MAX_PATH + 1, path)) {
		return (NULL);
	}
	return (nni_strdup(path));
}

int
nni_plat_file_type(const char *name, int *typep)
{
	DWORD attrs;

	if ((attrs = GetFileAttributes(name)) == INVALID_FILE_ATTRIBUTES) {
		return (nni_win_error(GetLastError()));
	}
	if (attrs & FILE_ATTRIBUTE_DIRECTORY) {
		*typep = NNI_PLAT_FILE_TYPE_DIR;
	} else if (attrs & FILE_ATTRIBUTE_DEVICE) {
		*typep = NNI_PLAT_FILE_TYPE_OTHER;
	} else if (attrs & FILE_ATTRIBUTE_HIDDEN) {
		*typep = NNI_PLAT_FILE_TYPE_OTHER;
	} else {
		*typep = NNI_PLAT_FILE_TYPE_FILE;
	}
	return (0);
}

char *
nni_plat_join_dir(const char *prefix, const char *suffix)
{
	char *result;

	if (nni_asprintf(&result, "%s\\%s", prefix, suffix) == 0) {
		return (result);
	}
	return (NULL);
}

const char *
nni_plat_file_basename(const char *name)
{
	const char *s;

	// skip over drive designator if present
	if (isalpha(name[0]) && (name[1] == ':')) {
		name += 2;
	}
	s = name + strlen(name);
	while (s > name) {
		if ((*s == '\\') || (*s == '/')) {
			return (s + 1);
		}
		s--;
	}
	return (name);
}

int
nni_plat_file_lock(const char *path, nni_plat_flock *lk)
{
	HANDLE h;

	// On Windows we do not have to explicitly lock the file, the
	// dwShareMode being set to zeor effectively prevents it.
	h = CreateFile(path, GENERIC_WRITE, 0, NULL, OPEN_ALWAYS,
	    FILE_ATTRIBUTE_NORMAL, NULL);
	if (h == INVALID_HANDLE_VALUE) {
		return (nni_win_error(GetLastError()));
	}
	lk->h = h;
	return (0);
}

void
nni_plat_file_unlock(nni_plat_flock *lk)
{
	HANDLE h = lk->h;
	(void) CloseHandle(h);
	lk->h = INVALID_HANDLE_VALUE;
}

#endif // NNG_PLATFORM_WINDOWS
