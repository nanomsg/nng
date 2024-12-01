//
// Copyright 2024 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "core/nng_impl.h"
#include <nuts.h>

#include <stdio.h>
#include <string.h>

#ifdef NNG_PLATFORM_POSIX
#include <sys/stat.h>
#include <unistd.h>
#endif

static void
test_permissions(void)
{
#ifdef NNG_PLATFORM_POSIX
	char  *temp;
	char  *file;
	void  *data;
	size_t n;
	temp = nni_plat_temp_dir();
	NUTS_TRUE(temp != NULL);
	file = nni_file_join(temp, "nng_files_perms_test");
	if (geteuid() == 0) {
		NUTS_SKIP("Cannot test permissions as root");
		return;
	}
	NUTS_PASS(nni_file_put(file, "abc", 4));
	chmod(file, 0);
	NUTS_FAIL(nni_file_get(file, &data, &n), NNG_EPERM);
	NUTS_FAIL(nni_file_put(file, "def", 4), NNG_EPERM);
	nni_file_delete(file);
	nni_strfree(file);
	nni_strfree(temp);
#else
	NUTS_SKIP("Not a POSIX platform");
#endif
}

struct walkarg {
	int a;
	int b;
	int c;
	int d;
	int seen;
};

static int
walker(const char *name, void *arg)
{
	struct walkarg *wa = arg;
	const char     *bn;

	bn = nni_file_basename(name);
	if (wa != NULL) {
		wa->seen++;
		if (strcmp(bn, "a") == 0) {
			wa->a++;
		} else if (strcmp(bn, "b") == 0) {
			wa->b++;
		} else if (strcmp(bn, "c") == 0) {
			wa->c++;
		} else if (strcmp(bn, "d") == 0) {
			wa->d++;
		}
	}
	if (strcmp(bn, "stop") == 0) {
		return (NNI_FILE_WALK_STOP);
	}
	if (strcmp(bn, "prunechild") == 0) {
		return (NNI_FILE_WALK_PRUNE_CHILD);
	}
	if (strcmp(bn, "prunesib") == 0) {
		return (NNI_FILE_WALK_PRUNE_SIB);
	}
	return (NNI_FILE_WALK_CONTINUE);
}

static void
test_directory_names(void)
{
	char *d;

	NUTS_TRUE((d = nni_plat_temp_dir()) != NULL);
	nni_strfree(d);

	NUTS_TRUE((d = nni_file_join("a", "b")) != NULL);
	NUTS_TRUE(d[0] == 'a');
	NUTS_TRUE(d[2] == 'b');
	NUTS_TRUE(d[3] == '\0');
	NUTS_TRUE((d[1] == '/') || (d[1] == '\\'));
	nni_strfree(d);
}

static void
test_create_file_in_absent_dir(void)
{
	int   rv;
	char *tmp;
	char *d1;
	char *d2;
	NUTS_TRUE((tmp = nni_plat_temp_dir()) != NULL);
	NUTS_TRUE((d1 = nni_file_join(tmp, "bogusdir")) != NULL);
	NUTS_TRUE((d2 = nni_file_join(d1, "a")) != NULL);
	NUTS_TRUE((rv = nni_plat_file_put(d2, "", 0)) == 0);
	NUTS_PASS(nni_file_delete(d2));
	NUTS_PASS(nni_file_delete(d1));
	nni_strfree(d2);
	nni_strfree(d1);
	nni_strfree(tmp);
}

static void
test_cannot_read_missing_file(void)
{
	void  *data;
	size_t n;
	NUTS_FAIL(nni_file_get("/bogus/dir/a", &data, &n), NNG_ENOENT);
}

static void
test_delete_missing_file(void)
{
	NUTS_PASS(nni_file_delete("/bogus/dir/a"));
}

static void
test_walk_missing_dir(void)
{
	NUTS_FAIL(nni_file_walk("/bogus/dir/a", walker, NULL, 0), NNG_ENOENT);
}

struct scratch {
	char *temp;
	char *mydir;
	char *a;
	char *b;
	char *c;
	char *d;
};

static void
make_scratch(struct scratch *s)
{
	s->temp = nni_plat_temp_dir();
	NUTS_TRUE(s->temp != NULL);
	s->mydir = nni_file_join(s->temp, "nng_files_test");
	NUTS_TRUE(s->mydir != NULL);
	s->a = nni_file_join(s->mydir, "a");
	NUTS_TRUE(s->a != NULL);
	s->b = nni_file_join(s->mydir, "b");
	NUTS_TRUE(s->b != NULL);
	s->c = nni_file_join(s->mydir, "c");
	NUTS_TRUE(s->c != NULL);
	s->d = nni_file_join(s->c, "d");
	NUTS_TRUE(s->d != NULL);

	NUTS_PASS(nni_file_put(s->a, "alpha", 6));
	NUTS_PASS(nni_file_put(s->b, "bravo", 6));
	NUTS_PASS(nni_file_put(s->d, "delta", 6));
}

static void
clean_scratch(struct scratch *s)
{
	nni_strfree(s->temp);
	nni_file_delete(s->a);
	nni_file_delete(s->b);
	nni_file_delete(s->d);
	nni_file_delete(s->c);
	nni_file_delete(s->mydir);
	nni_strfree(s->a);
	nni_strfree(s->b);
	nni_strfree(s->c);
	nni_strfree(s->d);
	nni_strfree(s->mydir);
}

static void
test_directory_walk(void)
{
	struct scratch s  = { 0 };
	struct walkarg wa = { 0 };

	make_scratch(&s);
	memset(&wa, 0, sizeof(wa));
	NUTS_PASS(nni_file_walk(s.mydir, walker, &wa, 0));
	NUTS_TRUE(wa.a == 1);
	NUTS_TRUE(wa.b == 1);
	NUTS_TRUE(wa.c == 1);
	NUTS_TRUE(wa.d == 1);
	NUTS_TRUE(wa.seen == 4);

	memset(&wa, 0, sizeof(wa));
	NUTS_PASS(
	    nni_file_walk(s.mydir, walker, &wa, NNI_FILE_WALK_FILES_ONLY));
	NUTS_TRUE(wa.a == 1);
	NUTS_TRUE(wa.b == 1);
	NUTS_TRUE(wa.c == 0);
	NUTS_TRUE(wa.d == 1);
	NUTS_TRUE(wa.seen == 3);

	memset(&wa, 0, sizeof(wa));
	NUTS_PASS(nni_file_walk(s.mydir, walker, &wa, NNI_FILE_WALK_SHALLOW));
	NUTS_TRUE(wa.a == 1);
	NUTS_TRUE(wa.b == 1);
	NUTS_TRUE(wa.c == 1);
	NUTS_TRUE(wa.d == 0);
	NUTS_TRUE(wa.seen == 3);

	memset(&wa, 0, sizeof(wa));
	NUTS_PASS(nni_file_walk(s.mydir, walker, &wa,
	    NNI_FILE_WALK_SHALLOW | NNI_FILE_WALK_FILES_ONLY));
	NUTS_TRUE(wa.a == 1);
	NUTS_TRUE(wa.b == 1);
	NUTS_TRUE(wa.c == 0);
	NUTS_TRUE(wa.d == 0);
	NUTS_TRUE(wa.seen == 2);

	clean_scratch(&s);
}

static void
test_file_contents(void)
{
	void          *data;
	size_t         len;
	struct scratch s = { 0 };

	make_scratch(&s);

	NUTS_PASS(nni_file_get(s.a, &data, &len));
	NUTS_TRUE(len == 6);
	NUTS_MATCH(data, "alpha");
	nni_free(data, len);
	clean_scratch(&s);
}

static void
test_empty_files(void)
{
	char  *temp;
	char  *empty;
	void  *data;
	size_t n;
	temp = nni_plat_temp_dir();
	NUTS_TRUE(temp != NULL);
	empty = nni_file_join(temp, "nng_files_test1");
	NUTS_TRUE(empty != NULL);
	NUTS_PASS(nni_file_put(empty, "", 0));
	NUTS_PASS(nni_file_get(empty, &data, &n));
	nni_free(data, n);
	NUTS_TRUE(n == 0);
	nni_file_delete(empty);
	nni_strfree(empty);
	nni_strfree(temp);
}

NUTS_TESTS = {
	{ "permissions", test_permissions },
	{ "directory names", test_directory_names },
	{ "create file absent dir", test_create_file_in_absent_dir },
	{ "cannot read missing file", test_cannot_read_missing_file },
	{ "delete missing file", test_delete_missing_file },
	{ "walk missing dir", test_walk_missing_dir },
	{ "walk directory", test_directory_walk },
	{ "file contents", test_file_contents },
	{ "empty files", test_empty_files },
	{ NULL, NULL },
};
