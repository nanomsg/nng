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
#include "nng.h"
#include "stubs.h"

// Add is for testing threads.
void
add(void *arg)
{
	*(int *) arg += 1;
}

// Notify tests for verifying condvars.
struct notifyarg {
	int          did;
	nng_duration when;
	nni_mtx      mx;
	nni_cv       cv;
};

void
notifyafter(void *arg)
{
	struct notifyarg *na = arg;

	nng_msleep(na->when);
	nni_mtx_lock(&na->mx);
	na->did = 1;
	nni_cv_wake(&na->cv);
	nni_mtx_unlock(&na->mx);
}

TestMain("Platform Operations", {

	nni_init();

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
			nni_time usend;
			nni_time usnow = nni_clock();
			nng_msleep(200);
			usend = nni_clock();
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
		static nni_mtx mx;

		nni_mtx_init(&mx);

		Convey("We can lock a mutex", {
			nni_mtx_lock(&mx);
			So(1);
			Convey("And we can unlock it", {
				nni_mtx_unlock(&mx);
				So(1);
				Convey("And then lock it again", {
					nni_mtx_lock(&mx);
					So(1);
					nni_mtx_unlock(&mx);
					So(1);
				});
			});
		});
		Convey("We can finalize it", { nni_mtx_fini(&mx); });
	});

	Convey("Threads work", {
		static nni_thr thr;
		int            val = 0;
		int            rv;

		Convey("We can create threads", {
			rv = nni_thr_init(&thr, add, &val);
			So(rv == 0);
			nni_thr_run(&thr);

			Reset({ nni_thr_fini(&thr); });

			Convey("It ran", {
				nng_msleep(50); // for context switch
				So(val == 1);
			});
		});
	});
	Convey("Condition variables work", {
		static struct notifyarg arg;
		static nni_thr          thr;

		nni_mtx_init(&arg.mx);
		nni_cv_init(&arg.cv, &arg.mx);
		So(nni_thr_init(&thr, notifyafter, &arg) == 0);

		Reset({
			nni_cv_fini(&arg.cv);
			nni_mtx_fini(&arg.mx);
			nni_thr_fini(&thr);
		});

		Convey("Notification works", {
			arg.did  = 0;
			arg.when = 10;
			nni_thr_run(&thr);

			nni_mtx_lock(&arg.mx);
			if (!arg.did) {
				nni_cv_wait(&arg.cv);
			}
			nni_mtx_unlock(&arg.mx);
			nni_thr_wait(&thr);
			So(arg.did == 1);
		});

		Convey("Timeout works", {
			arg.did  = 0;
			arg.when = 200;
			nni_thr_run(&thr);
			nni_mtx_lock(&arg.mx);
			if (!arg.did) {
				nni_cv_until(&arg.cv, nni_clock() + 10);
			}
			So(arg.did == 0);
			nni_mtx_unlock(&arg.mx);
			nni_thr_wait(&thr);
		});
		Convey("Not running works", {
			arg.did  = 0;
			arg.when = 1;
			nni_mtx_lock(&arg.mx);
			if (!arg.did) {
				nni_cv_until(&arg.cv, nni_clock() + 10);
			}
			So(arg.did == 0);
			nni_mtx_unlock(&arg.mx);
		});
	});
})
