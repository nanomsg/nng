//
// Copyright 2017 Garrett D'Amore <garrett@damore.org>
// Copyright 2017 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "core/nng_impl.h"

#ifdef NNG_PLATFORM_WINDOWS

#include <stdio.h>
#include <stdlib.h>

// File support.

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
	if ((data = nni_alloc((size_t) sz)) == NULL) {
		rv = NNG_ENOMEM;
		goto done;
	}
	if (!ReadFile(h, data, sz, &nread, NULL)) {
		rv = nni_win_error(GetLastError());
		nni_free(data, sz);
		goto done;
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
	if (!DeleteFile(name)) {
		return (nni_win_error(GetLastError()));
	}
	return (0);
}

// nni_plat_dir_open attempts to "open a directory" for listing.  The
// handle for further operations is returned in the first argument, and
// the directory name is supplied in the second.
struct dirhandle {
	HANDLE          dirh;
	WIN32_FIND_DATA data;
	int             cont; // zero on first read, 1 thereafter.
};

int
nni_plat_dir_open(void **dhp, const char *name)
{
	struct dirhandle *dh;
	char              fullpath[MAX_PATH + 1];

	if ((dh = NNI_ALLOC_STRUCT(dh)) == NULL) {
		return (NNG_ENOMEM);
	}

	// Append wildcard to directory name
	_snprintf(fullpath, sizeof(fullpath), "%s\\*", name);

	if ((dh->dirh = FindFirstFile(fullpath, &dh->data)) ==
	    INVALID_HANDLE_VALUE) {
		int rv;
		rv = nni_win_error(GetLastError());
		NNI_FREE_STRUCT(dh);
		return (rv);
	}
	dh->cont = 0;
	*dhp     = dh;

	return (0);
}

// nni_plat_dir_next gets the next directory entry.  Each call returns
// a new entry (arbitrary order).  When no more entries exist, it returns
// NNG_ENOENT.
int
nni_plat_dir_next(void *dir, const char **namep)
{
	struct dirhandle *dh = dir;
	int               rv;

	if (dh->dirh == INVALID_HANDLE_VALUE) {
		return (NNG_ENOENT);
	}
	if (dh->cont) {
		// We need to read another entry
		if (!FindNextFile(dh->dirh, &dh->data)) {
			rv = GetLastError();
			FindClose(dh->dirh);
			dh->dirh = INVALID_HANDLE_VALUE;
			if (rv == ERROR_NO_MORE_FILES) {
				return (NNG_ENOENT);
			}
			return (nni_win_error(rv));
		}
	}
	dh->cont = 1;

	// Skip over directories.
	while (dh->data.dwFileAttributes &
	    (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_HIDDEN)) {
		if (!FindNextFile(dh->dirh, &dh->data)) {
			rv = GetLastError();
			FindClose(dh->dirh);
			dh->dirh = INVALID_HANDLE_VALUE;
			if (rv == ERROR_NO_MORE_FILES) {
				return (NNG_ENOENT);
			}
			return (nni_win_error(rv));
		}
	}

	// Got a good entry.
	*namep = dh->data.cFileName;
	return (0);
}

// nni_plat_dir_close closes the directory handle, freeing all
// resources associated with it.
void
nni_plat_dir_close(void *dir)
{
	struct dirhandle *dh = dir;
	if (dh->dirh != INVALID_HANDLE_VALUE) {
		FindClose(dh->dirh);
	}
	NNI_FREE_STRUCT(dh);
}

int
nni_plat_dir_create(const char *name)
{
	char parent[MAX_PATH + 1];
	int  len;

	nni_strlcpy(parent, name, sizeof(parent));
	len = strlen(parent);
	while (len > 0) {
		if ((parent[len - 1] == '/') || (parent[len - 1] == '\\')) {
			parent[len - 1] = '\0';
			break;
		}
		len--;
	}

	if (!CreateDirectoryEx(parent, name, NULL)) {
		int rv = GetLastError();
		if (rv == ERROR_ALREADY_EXISTS) {
			return (0);
		}
		return (nni_win_error(rv));
	}
	return (0);
}

int
nni_plat_dir_remove(const char *name)
{
	if (!RemoveDirectory(name)) {
		int rv = GetLastError();
		if (rv == ERROR_PATH_NOT_FOUND) {
			return (0);
		}
		return (nni_win_error(rv));
	}
	return (0);
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

char *
nni_plat_home_dir(void)
{
	char *homedrv;
	char *homedir;
	char  stuff[MAX_PATH + 1];

	if (((homedrv = getenv("HOMEDRIVE")) == NULL) ||
	    ((homedir = getenv("HOMEPATH")) == NULL)) {
		return (NULL);
	}
	_snprintf(stuff, sizeof(stuff), "%s%s", homedrv, homedir);
	return (nni_strdup(stuff));
}

char *
nni_plat_join_dir(const char *prefix, const char *suffix)
{
	char stuff[MAX_PATH + 1];

	_snprintf(stuff, sizeof(stuff), "%s\\%s", prefix, suffix);
	return (nni_strdup(stuff));
}
#endif // NNG_PLATFORM_WINDOWS