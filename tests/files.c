//
// Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "convey.h"
#include "core/nng_impl.h"
#include "stubs.h"

#include <stdio.h>
#include <string.h>

#ifdef NNG_PLATFORM_POSIX
#include <sys/stat.h>
#include <unistd.h>
#endif

void
test_permissions(void)
{
#ifdef NNG_PLATFORM_POSIX
	Convey("Permissions work", {
		int    rv;
		char * temp;
		char * file;
		void * data;
		size_t n;
		temp = nni_plat_temp_dir();
		So(temp != NULL);
		file = nni_file_join(temp, "nng_files_perms_test");
		if (geteuid() == 0) {
			ConveySkip("Cannot test permissions as root");
		}
		So(nni_file_put(file, "abc", 4) == 0);
		Reset({
			nni_file_delete(file);
			nni_strfree(file);
			nni_strfree(temp);
		});
		chmod(file, 0);
		So((rv = nni_file_get(file, &data, &n)) != 0);
		So(rv == NNG_EPERM);
		So(nni_file_put(file, "def", 4) == NNG_EPERM);
	});
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
	const char *    bn;

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

TestMain("Platform File Support", {
	Convey("Directory names work", {
		char *d;

		So((d = nni_plat_temp_dir()) != NULL);
		nni_strfree(d);

		So((d = nni_file_join("a", "b")) != NULL);
		So(d[0] == 'a');
		So(d[2] == 'b');
		So(d[3] == '\0');
		So((d[1] == '/') || (d[1] == '\\'));
		nni_strfree(d);
	});

	Convey("Can create file in non-existent directory", {
		int   rv;
		char *tmp;
		char *d1;
		char *d2;
		So((tmp = nni_plat_temp_dir()) != NULL);
		So((d1 = nni_file_join(tmp, "bogusdir")) != NULL);
		So((d2 = nni_file_join(d1, "a")) != NULL);
		So((rv = nni_plat_file_put(d2, "", 0)) == 0);
		So(nni_file_delete(d2) == 0);
		So(nni_file_delete(d1) == 0);
		nni_strfree(d2);
		nni_strfree(d1);
		nni_strfree(tmp);
	});
	Convey("Cannot read missing file", {
		int    rv;
		void * data;
		size_t n;
		So((rv = nni_file_get("/bogus/dir/a", &data, &n)) != 0);
		So(rv == NNG_ENOENT);
	});

	Convey("Delete of missing file passes",
	    { So(nni_file_delete("/bogus/dir/a") == 0); });

	Convey("Walk of missing directory fails", {
		int rv = nni_file_walk("/bogus/dir/a", walker, NULL, 0);
		So(rv == NNG_ENOENT);
	});

	Convey("Remove missing directory works",
	    { So(nni_file_delete("/bogus/nng_does_not_exist") == 0); });

	Convey("We can create a pair of files", {
		char *temp;
		char *mydir;
		char *a;
		char *b;
		char *c;
		char *d;
		temp = nni_plat_temp_dir();
		So(temp != NULL);
		mydir = nni_file_join(temp, "nng_files_test");
		So(mydir != NULL);
		a = nni_file_join(mydir, "a");
		So(a != NULL);
		b = nni_file_join(mydir, "b");
		So(b != NULL);
		c = nni_file_join(mydir, "c");
		So(c != NULL);
		d = nni_file_join(c, "d");
		So(d != NULL);

		So(nni_file_put(a, "alpha", 6) == 0);
		So(nni_file_put(b, "bravo", 6) == 0);
		So(nni_file_put(d, "delta", 6) == 0);

		Reset({
			nni_strfree(temp);
			nni_file_delete(a);
			nni_file_delete(b);
			nni_file_delete(d);
			nni_file_delete(c);
			nni_file_delete(mydir);
			nni_strfree(a);
			nni_strfree(b);
			nni_strfree(c);
			nni_strfree(d);
			nni_strfree(mydir);
		});

		Convey("Directory walk works", {
			struct walkarg wa;
			int            rv;

			memset(&wa, 0, sizeof(wa));
			rv = nni_file_walk(mydir, walker, &wa, 0);
			So(rv == 0);
			So(wa.a == 1);
			So(wa.b == 1);
			So(wa.c == 1);
			So(wa.d == 1);
			So(wa.seen == 4);

			memset(&wa, 0, sizeof(wa));
			rv = nni_file_walk(
			    mydir, walker, &wa, NNI_FILE_WALK_FILES_ONLY);
			So(rv == 0);
			So(wa.a == 1);
			So(wa.b == 1);
			So(wa.c == 0);
			So(wa.d == 1);
			So(wa.seen == 3);

			memset(&wa, 0, sizeof(wa));
			rv = nni_file_walk(
			    mydir, walker, &wa, NNI_FILE_WALK_SHALLOW);
			So(rv == 0);
			So(wa.a == 1);
			So(wa.b == 1);
			So(wa.c == 1);
			So(wa.d == 0);
			So(wa.seen == 3);

			memset(&wa, 0, sizeof(wa));
			rv = nni_file_walk(mydir, walker, &wa,
			    NNI_FILE_WALK_SHALLOW | NNI_FILE_WALK_FILES_ONLY);
			So(rv == 0);
			So(wa.a == 1);
			So(wa.b == 1);
			So(wa.c == 0);
			So(wa.d == 0);
			So(wa.seen == 2);
		});

		Convey("Contents work", {
			void * data;
			size_t len;

			So(nni_file_get(a, &data, &len) == 0);
			So(len == 6);
			So(strcmp(data, "alpha") == 0);
			nni_free(data, len);
		});
	});

	Convey("Zero length files work", {
		char * temp;
		char * empty;
		void * data;
		size_t n;
		temp = nni_plat_temp_dir();
		So(temp != NULL);
		empty = nni_file_join(temp, "nng_files_test1");
		So(empty != NULL);
		So(nni_file_put(empty, "", 0) == 0);
		Reset({
			nni_file_delete(empty);
			nni_strfree(empty);
			nni_strfree(temp);
		});
		So(nni_file_get(empty, &data, &n) == 0);
		nni_free(data, n);
		So(n == 0);
	});

	test_permissions();
})
