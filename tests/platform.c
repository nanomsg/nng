//
// Copyright 2016 Garrett D'Amore <garrett@damore.org>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "convey.h"
#include "nng.h"
#include "core/nng_impl.h"

#ifndef	_WIN32
#include <sys/time.h>
#endif

uint64_t
getms(void)
{
#ifdef	_WIN32
	return (GetTickCount())	;
#else
	static time_t epoch;
	struct timeval tv;

	if (epoch == 0) {
		epoch = time(NULL);
	}
	gettimeofday(&tv, NULL);

	if (tv.tv_sec < epoch) {
		// Broken clock.
		// This will force all other timing tests to fail
		return (0);
	}
	tv.tv_sec -= epoch;
	return (((uint64_t)(tv.tv_sec ) * 1000) + (tv.tv_usec / 1000));
#endif
}

// Add is for testing threads.
void
add(void *arg)
{
	*(int *)arg += 1;
}

// Notify tests for verifying condvars.
struct notifyarg {
	int did;
	int when;
	nni_mtx mx;
	nni_cv cv;
};

void
notifyafter(void *arg)
{
	struct notifyarg *na = arg;

	nni_usleep(na->when);
	nni_mtx_lock(&na->mx);
	na->did = 1;
	nni_cv_wake(&na->cv);
	nni_mtx_unlock(&na->mx);
}

TestMain("Platform Operations", {

	int rv = nni_init();	// This is required for anything else to work
	Convey("Platform init worked", {
		So(rv == 0);
	})
	Convey("The clock works", {
		uint64_t now = getms();

		Convey("usleep works", {
			nni_usleep(100000);

			So((getms() - now) >= 100);	// cannot be *shorter*!!
			So((getms() - now) < 150);	// crummy clock resolution?
		})
		Convey("times work", {
			uint64_t msend;
			int usdelta;
			int msdelta;
			nni_time usend;
			nni_time usnow = nni_clock();
			nni_usleep(200000);
			usend = nni_clock();
			msend = getms();

			So(usend > usnow);
			So(msend > now);
			usdelta = (int)((usend - usnow) / 1000);
			msdelta = (int)((msend - now));
			So(usdelta >= 200);
			So(usdelta < 220);
			So(abs(msdelta - usdelta) < 20);
		})
	})
	Convey("Mutexes work", {
		static nni_mtx mx;
		int rv;

		rv = nni_mtx_init(&mx);
		So(rv == 0);

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
				})
			})
		})
		Convey("We can finalize it", {
			nni_mtx_fini(&mx);
		})
	})

	Convey("Threads work", {
		static nni_thr thr;
		int val = 0;
		int rv;

		Convey("We can create threads", {
			rv = nni_thr_init(&thr, add, &val);
			So(rv == 0);
			nni_thr_run(&thr);

			Reset({
				nni_thr_fini(&thr);
			})

			Convey("It ran", {
				nni_usleep(50000);	// for context switch
				So(val == 1);
			})
		})
	})
	Convey("Condition variables work", {
		static struct notifyarg arg;
		static nni_thr thr;

		So(nni_mtx_init(&arg.mx) == 0);
		So(nni_cv_init(&arg.cv, &arg.mx) == 0);
		So(nni_thr_init(&thr, notifyafter, &arg) == 0);

		Reset({
			nni_cv_fini(&arg.cv);
			nni_mtx_fini(&arg.mx);
			nni_thr_fini(&thr);
		});

		Convey("Notification works", {
			arg.did = 0;
			arg.when = 10000;
			nni_thr_run(&thr);

			nni_mtx_lock(&arg.mx);
			if (!arg.did) {
				nni_cv_wait(&arg.cv);
			}
			nni_mtx_unlock(&arg.mx);
			nni_thr_wait(&thr);
			So(arg.did == 1);
		})

		Convey("Timeout works", {
			arg.did = 0;
			arg.when = 200000;
			nni_thr_run(&thr);
			nni_mtx_lock(&arg.mx);
			if (!arg.did) {
				nni_cv_until(&arg.cv, nni_clock() + 10000);
			}
			So(arg.did == 0);
			nni_mtx_unlock(&arg.mx);
			nni_thr_wait(&thr);
		})

		Convey("Not running works", {
			arg.did = 0;
			arg.when = 1;
			nni_mtx_lock(&arg.mx);
			if (!arg.did) {
				nni_cv_until(&arg.cv, nni_clock() + 10000);
			}
			So(arg.did == 0);
			nni_mtx_unlock(&arg.mx);
		})
	})
})
