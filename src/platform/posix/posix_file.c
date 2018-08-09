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

// Some systems -- Android -- have BSD flock but not POSIX lockf.
#if defined(NNG_HAVE_FLOCK) && !defined(NNG_HAVE_LOCKF)
#include <sys/file.h>
#endif

// File support.

static int
nni_plat_make_parent_dirs(const char *path)
{
	char *dup;
	char *p;
	int   rv;

	// creates everything up until the last component.
	if ((dup = nni_strdup(path)) == NULL) {
		return (NNG_ENOMEM);
	}
	p = dup;
	while ((p = strchr(p, '/')) != NULL) {
		if (p != dup) {
			*p = '\0';
			rv = mkdir(dup, S_IRWXU);
			*p = '/';
			if ((rv != 0) && (errno != EEXIST)) {
				rv = nni_plat_errno(errno);
				nni_strfree(dup);
				return (rv);
			}
		}

		// collapse grouped "/" characters
		while (*p == '/') {
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
	FILE *f;
	int   rv = 0;

	// It is possible that the name contains a directory path
	// that does not exist.  In this case we try to create the
	// entire tree.
	if (strchr(name, '/') != NULL) {
		if ((rv = nni_plat_make_parent_dirs(name)) != 0) {
			return (rv);
		}
	}

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
	size_t      len;
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
	if (len > 0) {
		if ((data = nni_alloc(len)) == NULL) {
			rv = NNG_ENOMEM;
			goto done;
		}
		if (fread(data, 1, len, f) != len) {
			rv = nni_plat_errno(errno);
			nni_free(data, len);
			goto done;
		}
	} else {
		data = NULL;
	}
	*datap = data;
	*lenp  = len;
done:
	(void) fclose(f);
	return (rv);
}

// nni_plat_file_delete deletes the named file or directory.
int
nni_plat_file_delete(const char *name)
{
	if (rmdir(name) == 0) {
		return (0);
	}
	if ((errno == ENOTDIR) && (unlink(name) == 0)) {
		return (0);
	}
	if (errno == ENOENT) {
		return (0);
	}
	return (nni_plat_errno(errno));
}

int
nni_plat_file_type(const char *name, int *typep)
{
	struct stat sbuf;

	if (stat(name, &sbuf) != 0) {
		return (nni_plat_errno(errno));
	}
	switch (sbuf.st_mode & S_IFMT) {
	case S_IFREG:
		*typep = NNI_PLAT_FILE_TYPE_FILE;
		break;
	case S_IFDIR:
		*typep = NNI_PLAT_FILE_TYPE_DIR;
		break;
	default:
		*typep = NNI_PLAT_FILE_TYPE_OTHER;
		break;
	}
	return (0);
}

static int
nni_plat_file_walk_inner(const char *name, nni_plat_file_walker walkfn,
    void *arg, int flags, bool *stop)
{
	DIR *dir;

	if ((dir = opendir(name)) == NULL) {
		return (nni_plat_errno(errno));
	}
	for (;;) {
		int            rv;
		struct dirent *ent;
		struct stat    sbuf;
		char *         path;
		int            walkrv;

		if ((ent = readdir(dir)) == NULL) {
			closedir(dir);
			return (0);
		}
		// Skip "." and ".."  -- we would like to skip all
		// directories, but that would require checking full
		// paths.
		if ((strcmp(ent->d_name, ".") == 0) ||
		    (strcmp(ent->d_name, "..") == 0)) {
			continue;
		}
		if ((rv = nni_asprintf(&path, "%s/%s", name, ent->d_name)) !=
		    0) {
			closedir(dir);
			return (rv);
		}
		if (stat(path, &sbuf) != 0) {
			if (errno == ENOENT) { // deleted while walking
				continue;
			}
			rv = nni_plat_errno(errno);
			nni_strfree(path);
			closedir(dir);
			return (rv);
		}
		if (flags & NNI_PLAT_FILE_WALK_FILES_ONLY) {
			if ((sbuf.st_mode & S_IFMT) == S_IFREG) {
				walkrv = walkfn(path, arg);
			} else {
				walkrv = NNI_PLAT_FILE_WALK_CONTINUE;
			}
		} else {
			walkrv = walkfn(path, arg);
		}

		if (walkrv == NNI_PLAT_FILE_WALK_STOP) {
			*stop = true;
		}

		if ((!*stop) && (rv != NNI_PLAT_FILE_WALK_PRUNE_CHILD) &&
		    ((flags & NNI_PLAT_FILE_WALK_SHALLOW) == 0) &&
		    ((sbuf.st_mode & S_IFMT) == S_IFDIR)) {
			rv = nni_plat_file_walk_inner(
			    path, walkfn, arg, flags, stop);
			if (rv != 0) {
				nni_strfree(path);
				closedir(dir);
				return (rv);
			}
		}

		nni_strfree(path);

		if ((walkrv == NNI_PLAT_FILE_WALK_PRUNE_SIB) || (*stop)) {
			break;
		}
	}
	closedir(dir);
	return (0);
}

int
nni_plat_file_walk(
    const char *name, nni_plat_file_walker walkfn, void *arg, int flags)
{
	bool stop = false;

	return (nni_plat_file_walk_inner(name, walkfn, arg, flags, &stop));
}

const char *
nni_plat_file_basename(const char *path)
{
	const char *end;
	if ((end = strrchr(path, '/')) != NULL) {
		return (end + 1);
	}
	return (path);
}

int
nni_plat_file_lock(const char *path, nni_plat_flock *lk)
{
	int fd;
	int rv;
	if ((fd = open(path, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR)) < 0) {
		return (nni_plat_errno(errno));
	}
#ifdef NNG_HAVE_LOCKF
	rv = lockf(fd, F_TLOCK, 0);
#elif defined NNG_HAVE_FLOCK
	rv = flock(fd, LOCK_EX | LOCK_NB);
#else
	// We don't have locking support.  This means you live dangerously.
	// For example, ZeroTier cannot be sure that nothing else is using
	// the same configuration file.  If you're here, its probably an
	// embedded scenario, and we can live with it.
	rv = 0;
#endif
	if (rv < 0) {
		int rv = errno;
		close(fd);
		if (rv == EAGAIN) {
			return (NNG_EBUSY);
		}
		return (nni_plat_errno(rv));
	}
	lk->fd = fd;
	return (0);
}

void
nni_plat_file_unlock(nni_plat_flock *lk)
{
	int fd = lk->fd;
	lk->fd = -1;
	(void) close(fd);
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
