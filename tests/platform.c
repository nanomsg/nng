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
	nni_mutex mx;
	nni_cond cv;
};

void
notifyafter(void *arg)
{
	struct notifyarg *na = arg;

	nni_usleep(na->when);
	nni_mutex_enter(&na->mx);
	na->did = 1;
	nni_cond_signal(&na->cv);
	nni_mutex_exit(&na->mx);
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
		nni_mutex mx;
		int rv;

		rv = nni_mutex_init(&mx);
		So(rv == 0);

		Convey("We can lock a mutex", {
			nni_mutex_enter(&mx);
			So(1);
			Convey("And cannot recursively lock", {
				rv = nni_mutex_tryenter(&mx);
				So(rv != 0);
			})
			Convey("And we can unlock it", {
				nni_mutex_exit(&mx);
				So(1);
				Convey("And then lock it again", {
					rv = nni_mutex_tryenter(&mx);
					So(rv == 0);
				})
			})
		})
		Convey("We can finalize it", {
			nni_mutex_fini(&mx);
		})
	})

	Convey("Threads work", {
		nni_thread *thr;
		int val = 0;
		int rv;

		Convey("We can create threads", {
			rv = nni_thread_create(&thr, add, &val);
			So(rv == 0);
			So(thr != NULL);

			Convey("It ran", {
				nni_usleep(50000);	// for context switch
				So(val == 1);
			})
			Convey("We can reap it", {
				nni_thread_reap(thr);
			})
		})
	})
	Convey("Condition variables work", {
		struct notifyarg arg;
		nni_thread *thr = NULL;

		So(nni_mutex_init(&arg.mx) == 0);
		So(nni_cond_init(&arg.cv, &arg.mx) == 0);
		Reset({
			if (thr != NULL) {
				nni_thread_reap(thr);
				thr = NULL;
			}
			nni_cond_fini(&arg.cv);
			nni_mutex_fini(&arg.mx);
		});

		Convey("Notification works", {
			arg.did = 0;
			arg.when = 10000;
			So(nni_thread_create(&thr, notifyafter, &arg) == 0);

			nni_mutex_enter(&arg.mx);
			if (!arg.did) {
				nni_cond_wait(&arg.cv);
			}
			nni_mutex_exit(&arg.mx);
			So(arg.did == 1);
		})

		Convey("Timeout works", {
			arg.did = 0;
			arg.when = 200000;
			So(nni_thread_create(&thr, notifyafter, &arg) == 0);
			nni_mutex_enter(&arg.mx);
			if (!arg.did) {
				nni_cond_waituntil(&arg.cv, nni_clock() + 10000);
			}
			So(arg.did == 0);
			nni_mutex_exit(&arg.mx);
		})
	})
})