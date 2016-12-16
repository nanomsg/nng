#include <stdio.h>
#include "test.h"

test_main("Things work", {
	int x;
	int y;
	x = 1;
	y = 2;
	test_convey("X is one", {
		test_assert(x == 1);
	});
	test_convey("Y is two", {
		test_so(y == 2);
		y = 3;
		test_so(y == 3);
	});

test_convey("Bounce", {
	test_convey("Arithmetic", {
		test_so(y == 2);
		test_convey("Addition", {
			test_so(x + y == 3);
			test_so(x + y + y == 5);
			y = 5;
			test_so(x + y == 6);
		});
		test_convey("Subtraction", {
			test_so(x - y == -1);
			test_so(y - x == 1);
		});
	});
});
})
