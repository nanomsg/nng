//
// Copyright 2017 Garrett D'Amore <garrett@damore.org>
// Copyright 2017 Capitar IT Group BV <info@capitar.com>
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
		file = nni_plat_join_dir(temp, "nng_files_perms_test");
		So(nni_plat_file_put(file, "abc", 4) == 0);
		Reset({
			nni_plat_file_delete(file);
			nni_strfree(file);
			nni_strfree(temp);
		});
		chmod(file, 0);
		So((rv = nni_plat_file_get(file, &data, &n)) != 0);
		So(rv == NNG_EPERM);
		So(nni_plat_file_put(file, "def", 4) == NNG_EPERM);
	});
#endif
}

TestMain("Platform File Support", {
	Convey("Directory names work", {
		char *d;

		So((d = nni_plat_temp_dir()) != NULL);
		nni_strfree(d);

		So((d = nni_plat_home_dir()) != NULL);
		nni_strfree(d);

		So((d = nni_plat_join_dir("a", "b")) != NULL);
		So(d[0] == 'a');
		So(d[2] == 'b');
		So(d[3] == '\0');
		So((d[1] == '/') || (d[1] == '\\'));
		nni_strfree(d);
	});

	Convey("Cannot create file in non-extant directory", {
		int rv;
		So((rv = nni_plat_file_put("/bogus/dir/a", "", 0)) != 0);
		So(rv == NNG_ENOENT);
	});
	Convey("Cannot read missing file", {
		int    rv;
		void * data;
		size_t n;
		So((rv = nni_plat_file_get("/bogus/dir/a", &data, &n)) != 0);
		So(rv == NNG_ENOENT);
	});
	Convey("Cannot delete missing file", {
		int rv;
		So((rv = nni_plat_file_delete("/bogus/dir/a")) != 0);
		So(rv == NNG_ENOENT);
	});
	Convey("Cannot open missing directory", {
		int   rv;
		void *dir;
		So((rv = nni_plat_dir_open(
		        &dir, "/bogus/nng_does_not_exist")) != 0);
		So(rv == NNG_ENOENT);
	});
	Convey("Cannot create directory in non-existing subdir", {
		int rv;
		So((rv = nni_plat_dir_create(
		        "/bogus/nng_does_not_exist/subdir")) != 0);
		So(rv == NNG_ENOENT);
	});
	Convey("Remove missing directory works",
	    { So(nni_plat_dir_remove("/bogus/nng_does_not_exist") == 0); });

	Convey("Create existing directory works", {
		char *tmp;
		tmp = nni_plat_temp_dir();
		So(nni_plat_dir_create(tmp) == 0);
		nni_strfree(tmp);
	});
	Convey("We can create a pair of files", {

		char *temp;
		char *mydir;
		char *a;
		char *b;
		char *c;
		temp = nni_plat_temp_dir();
		So(temp != NULL);
		mydir = nni_plat_join_dir(temp, "nng_files_test");
		So(mydir != NULL);
		a = nni_plat_join_dir(mydir, "a");
		So(a != NULL);
		b = nni_plat_join_dir(mydir, "b");
		So(b != NULL);
		c = nni_plat_join_dir(mydir, "c");
		So(c != NULL);

		So(nni_plat_dir_create(mydir) == 0);
		So(nni_plat_file_put(a, "alpha", 6) == 0);
		So(nni_plat_file_put(b, "bravo", 6) == 0);

		Reset({
			nni_strfree(temp);
			nni_plat_file_delete(a);
			nni_plat_file_delete(b);
			nni_strfree(a);
			nni_strfree(b);
			nni_strfree(c);
			nni_plat_dir_remove(mydir);
			nni_strfree(mydir);
		});

		Convey("Directory list works", {
			int         seen_a    = 0;
			int         seen_b    = 0;
			int         seen_what = 0;
			int         rv;
			void *      dirh;
			const char *name;

			So(nni_plat_dir_open(&dirh, mydir) == 0);
			while ((rv = nni_plat_dir_next(dirh, &name)) == 0) {
				if (strcmp(name, "a") == 0) {
					seen_a++;
				} else if (strcmp(name, "b") == 0) {
					seen_b++;
				} else {
					seen_what++;
				}
			}
			So(rv == NNG_ENOENT);
			So(seen_a == 1);
			So(seen_b == 1);
			So(seen_what == 0);
			nni_plat_dir_close(dirh);
		});

		Convey("Contents work", {
			void * data;
			size_t len;

			So(nni_plat_file_get(a, &data, &len) == 0);
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
		empty = nni_plat_join_dir(temp, "nng_files_test1");
		So(empty != NULL);
		So(nni_plat_file_put(empty, "", 0) == 0);
		Reset({
			nni_plat_file_delete(empty);
			nni_strfree(empty);
			nni_strfree(temp);
		});
		So(nni_plat_file_get(empty, &data, &n) == 0);
		So(n == 0);
	});

	test_permissions();
});
