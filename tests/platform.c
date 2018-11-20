//
// Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <nng/nng.h>
#include <nng/supplemental/util/platform.h>

#include "convey.h"
#include "stubs.h"

struct addarg {
	int      cnt;
	nng_mtx *mx;
	nng_cv * cv;
};

void
add(void *arg)
{
	struct addarg *aa = arg;

	nng_mtx_lock(aa->mx);
	aa->cnt++;
	nng_cv_wake(aa->cv);
	nng_mtx_unlock(aa->mx);
}

TestMain("Platform Operations", {
	// This is required for anything else to work
	Convey("The clock works", {
		uint64_t now = getms();

		Convey("usleep works", {
			nng_msleep(100);

			So((getms() - now) >= 100); // cannot be *shorter*!!
			So((getms() - now) < 200);  // crummy clock resolution?
		});
		Convey("times work", {
			uint64_t msend;
			int      usdelta;
			int      msdelta;
			nng_time usend;
			nng_time usnow = nng_clock();
			nng_msleep(200);
			usend = nng_clock();
			msend = getms();

			So(usend > usnow);
			So(msend > now);
			usdelta = (int) (usend - usnow);
			msdelta = (int) (msend - now);
			So(usdelta >= 200);
			So(usdelta < 250); // increased tolerance for CIs
			So(abs(msdelta - usdelta) < 50);
		});
	});
	Convey("Mutexes work", {
		static nng_mtx *mx;

		So(nng_mtx_alloc(&mx) == 0);
		Reset({ nng_mtx_free(mx); });

		Convey("We can lock and unlock mutex", {
			nng_mtx_lock(mx);
			So(1);
			nng_mtx_unlock(mx);
			So(1);
			Convey("And then lock it again", {
				nng_mtx_lock(mx);
				So(1);
				nng_mtx_unlock(mx);
				So(1);
			});
		});
	});

	Convey("Threads work", {
		static nng_thread *thr;
		int                rv;
		struct addarg      aa;

		So(nng_mtx_alloc(&aa.mx) == 0);
		So(nng_cv_alloc(&aa.cv, aa.mx) == 0);
		Reset({
			nng_mtx_free(aa.mx);
			nng_cv_free(aa.cv);
		});
		aa.cnt = 0;

		Convey("We can create threads", {
			rv = nng_thread_create(&thr, add, &aa);
			So(rv == 0);

			Reset({ nng_thread_destroy(thr); });

			Convey("It ran", {
				int val;
				nng_mtx_lock(aa.mx);
				while ((val = aa.cnt) == 0) {
					nng_cv_wait(aa.cv);
				}
				nng_mtx_unlock(aa.mx);
				So(val == 1);
			});
		});
	});
})
