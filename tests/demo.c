#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include "test.h"

test_main_group({
	test_group("Things work", {
	int x;
	int y;
	x = 1;
	y = 2;
	test_convey("X is one", {
		test_debugf("A logged message.");
		test_assert(x == 1);
	});
	test_convey("Y is two", {
		test_so(y == 2);
		y = 3;
		test_so(y == 3);
	});

	test_convey("Operations (Outer)", {
		test_convey("Arithmetic", {
			test_so(y == 2);
			test_convey("Addition", {
				test_so(x + y == 3);
				test_so(x + y + y == 5);
				test_so(x == 9);
				y = 5;
				test_so(x + y == 6);
			});
			test_convey("Subtraction", {
				test_so(x - y == -1);
				test_so(y - x == 1);
			});
		});
	});

	test_convey("Middle test is skipped", {
		test_convey("Start", {
			test_so(1 == 1);
		});
		test_convey("Middle (Skip?)", {
			test_so(9 - 1 == 8);
			test_skip("forced skip");
			test_so(0 == 1);
		});
		test_convey("Ending", {
			test_so(2 == 2);
		});
	});

	});

	test_group("Second group", {
		int x = 1;
		static int y  =1;
		test_convey("x is 1", {
#ifndef	_WIN32
			sleep(1);
#endif
			test_so(x == 1);
		});
	});

	test_group("Reset group", {
		static int x = 0;
		static int y = 0;
		test_reset({
			x = 20;
		});
		test_convey("Add one to both y and x", {
			x++;
			y++;
			test_so(x == 1);	/* no reset yet */
			test_so(y == 1);
		});
		test_convey("Again", {
			x++;
			y++;
			test_so(x == 21);
			test_so(y == 2);
		});
		test_convey("Third time", {
			x++;
			y++;
			test_so(x == 21);
			test_so(y == 3);
		});

		test_so(x == 20);
		test_so(y == 3);
	});
})
