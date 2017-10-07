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

#ifdef NNG_PLATFORM_POSIX

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

// File support.

// nni_plat_file_put writes the named file, with the provided data,
// and the given size.  If the file already exists it is overwritten.
// The permissions on the file should be limited to read and write
// access by the entity running the application only.
int
nni_plat_file_put(const char *name, const void *data, size_t len)
{
	FILE *f;
	int   rv = 0;

	if ((f = fopen(name, "wb")) == NULL) {
		return (nni_plat_errno(errno));
	}
	if (fwrite(data, 1, len, f) != len) {
		rv = nni_plat_errno(errno);
		(void) unlink(name);
	}
	(void) fclose(f);
	return (rv);
}

// nni_plat_file_get reads the entire named file, allocating storage
// to receive the data and returning the data and the size in the
// reference arguments.
int
nni_plat_file_get(const char *name, void **datap, size_t *lenp)
{
	FILE *      f;
	struct stat st;
	int         rv = 0;
	int         len;
	void *      data;

	if ((f = fopen(name, "rb")) == NULL) {
		return (nni_plat_errno(errno));
	}

	if (stat(name, &st) != 0) {
		rv = nni_plat_errno(errno);
		(void) fclose(f);
		return (rv);
	}

	len = st.st_size;
	if ((data = nni_alloc(len)) == NULL) {
		rv = NNG_ENOMEM;
		goto done;
	}
	if (fread(data, 1, len, f) != len) {
		rv = nni_plat_errno(errno);
		nni_free(data, len);
		goto done;
	}
	*datap = data;
	*lenp  = len;
done:
	(void) fclose(f);
	return (rv);
}

// nni_plat_file_delete deletes the named file.
int
nni_plat_file_delete(const char *name)
{
	if (unlink(name) < 0) {
		return (nni_plat_errno(errno));
	}
	return (0);
}

// nni_plat_dir_open attempts to "open a directory" for listing.  The
// handle for further operations is returned in the first argument, and
// the directory name is supplied in the second.
int
nni_plat_dir_open(void **dirp, const char *name)
{
	DIR *dir;

	if ((dir = opendir(name)) == NULL) {
		return (nni_plat_errno(errno));
	}
	*dirp = dir;
	return (0);
}

int
nni_plat_dir_create(const char *name)
{
	if (mkdir(name, S_IRWXU) != 0) {
		if (errno == EEXIST) {
			return (0);
		}
		return (nni_plat_errno(errno));
	}
	return (0);
}

int
nni_plat_dir_remove(const char *name)
{
	if (rmdir(name) != 0) {
		if (errno == ENOENT) {
			return (0);
		}
		return (nni_plat_errno(errno));
	}
	return (0);
}

// nni_plat_dir_next gets the next directory entry.  Each call returns
// a new entry (arbitrary order).  When no more entries exist, it returns
// NNG_ENOENT.
int
nni_plat_dir_next(void *dir, const char **namep)
{
	for (;;) {
		struct dirent *ent;

		if ((ent = readdir((DIR *) dir)) == NULL) {
			return (NNG_ENOENT);
		}
		// Skip "." and ".."  -- we would like to skip all
		// directories, but that would require checking full
		// paths.
		if ((strcmp(ent->d_name, ".") == 0) ||
		    (strcmp(ent->d_name, "..") == 0)) {
			continue;
		}
		*namep = ent->d_name;
		return (0);
	}
}

// nni_plat_dir_close closes the directory handle, freeing all
// resources associated with it.
void
nni_plat_dir_close(void *dir)
{
	(void) closedir((DIR *) dir);
}

char *
nni_plat_temp_dir(void)
{
	char *temp;

	// POSIX says $TMPDIR is required.
	if ((temp = getenv("TMPDIR")) != NULL) {
		return (nni_strdup(temp));
	}
	return (nni_strdup("/tmp"));
}

char *
nni_plat_home_dir(void)
{
	char *home;

	// POSIX says that $HOME is *REQUIRED*.  We could look in getpwuid,
	// but realistically this is simply not required.
	if ((home = getenv("HOME")) != NULL) {
		return (nni_strdup(home));
	}
	return (NULL);
}

char *
nni_plat_join_dir(const char *prefix, const char *suffix)
{
	char * newdir;
	size_t len;

	len    = strlen(prefix) + strlen(suffix) + 2;
	newdir = nni_alloc(strlen(prefix) + strlen(suffix) + 2);
	if (newdir != NULL) {
		(void) snprintf(newdir, len, "%s/%s", prefix, suffix);
	}
	return (newdir);
}

#endif // NNG_PLATFORM_POSIX
