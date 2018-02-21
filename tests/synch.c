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
//#include "core/nng_impl.h"
#include "nng.h"
#include "supplemental/util/platform.h"

// Notify tests for verifying condvars.
struct notifyarg {
	int          did;
	nng_duration when;
	nng_mtx *    mx;
	nng_cv *     cv;
};

#ifdef NNG_PLATFORM_POSIX
#ifndef NDEBUG
#define SYNC_FALLBACK 1
#endif
#endif

void
notifyafter(void *arg)
{
	struct notifyarg *na = arg;

	nng_msleep(na->when);
	nng_mtx_lock(na->mx);
	na->did = 1;
	nng_cv_wake(na->cv);
	nng_mtx_unlock(na->mx);
}

struct notifyarg arg;
nng_thread *     thr;

static void
test_sync(void)
{
	Convey("Mutexes work", {
		nng_mtx *mx;

		So(nng_mtx_alloc(&mx) == 0);
		Reset({ nng_mtx_free(mx); });

		Convey("We can lock a mutex", {
			nng_mtx_lock(mx);
			So(1);
			Convey("And we can unlock it", {
				nng_mtx_unlock(mx);
				So(1);
				Convey("And then lock it again", {
					nng_mtx_lock(mx);
					So(1);
					nng_mtx_unlock(mx);
					So(1);
				});
			});
			Convey("Things block properly", {

				So(nng_mtx_alloc(&arg.mx) == 0);
				So(nng_cv_alloc(&arg.cv, arg.mx) == 0);
				arg.did  = 0;
				arg.when = 0;
				nng_mtx_lock(arg.mx);
				So(nng_thread_create(
				       &thr, notifyafter, &arg) == 0);
				nng_msleep(10);
				So(arg.did == 0);
				nng_mtx_unlock(arg.mx);
				nng_msleep(10);
				nng_mtx_lock(arg.mx);
				while (!arg.did) {
					nng_cv_wait(arg.cv);
				}
				So(arg.did != 0);
				nng_mtx_unlock(arg.mx);
				nng_thread_destroy(thr);
				nng_cv_free(arg.cv);
				nng_mtx_free(arg.mx);
			})
		});
	});

	Convey("Condition variables work", {

		So(nng_mtx_alloc(&arg.mx) == 0);
		So(nng_cv_alloc(&arg.cv, arg.mx) == 0);

		Reset({
			nng_cv_free(arg.cv);
			nng_mtx_free(arg.mx);
		});

		Convey("Notification works", {
			arg.did  = 0;
			arg.when = 10;
			So(nng_thread_create(&thr, notifyafter, &arg) == 0);

			nng_mtx_lock(arg.mx);
			if (!arg.did) {
				nng_cv_wait(arg.cv);
			}
			nng_mtx_unlock(arg.mx);
			nng_thread_destroy(thr);
			So(arg.did == 1);
		});

		Convey("Timeout works", {
			arg.did  = 0;
			arg.when = 200;
			So(nng_thread_create(&thr, notifyafter, &arg) == 0);
			nng_mtx_lock(arg.mx);
			if (!arg.did) {
				nng_cv_until(arg.cv, nng_clock() + 10);
			}
			So(arg.did == 0);
			nng_mtx_unlock(arg.mx);
			nng_thread_destroy(thr);
		});

		Convey("Empty timeout is EAGAIN", {
			nng_mtx_lock(arg.mx);
			So(nng_cv_until(arg.cv, 0) == NNG_EAGAIN);
			nng_mtx_unlock(arg.mx);
		});

		Convey("Not running works", {
			arg.did  = 0;
			arg.when = 1;
			nng_mtx_lock(arg.mx);
			if (!arg.did) {
				nng_cv_until(arg.cv, nng_clock() + 10);
			}
			So(arg.did == 0);
			nng_mtx_unlock(arg.mx);
		});
	});
}

#if SYNC_FALLBACK
extern int nni_plat_sync_fallback;

#define ConveyFB(x, y) Convey(x, y)

static void
test_sync_fallback(void)
{
	nni_plat_sync_fallback = 1;
	Convey("Mutexes work", {
		nng_mtx *mx;

		So(nng_mtx_alloc(&mx) == 0);
		Reset({ nng_mtx_free(mx); });

		Convey("We can lock a mutex", {
			nng_mtx_lock(mx);
			So(1);
			Convey("And we can unlock it", {
				nng_mtx_unlock(mx);
				So(1);
				Convey("And then lock it again", {
					nng_mtx_lock(mx);
					So(1);
					nng_mtx_unlock(mx);
					So(1);
				});
			});
			Convey("Things block properly", {

				So(nng_mtx_alloc(&arg.mx) == 0);
				So(nng_cv_alloc(&arg.cv, arg.mx) == 0);
				arg.did  = 0;
				arg.when = 0;
				nng_mtx_lock(arg.mx);
				So(nng_thread_create(
				       &thr, notifyafter, &arg) == 0);
				nng_msleep(10);
				So(arg.did == 0);
				nng_mtx_unlock(arg.mx);
				nng_msleep(10);
				nng_mtx_lock(arg.mx);
				while (!arg.did) {
					nng_cv_wait(arg.cv);
				}
				So(arg.did != 0);
				nng_mtx_unlock(arg.mx);
				nng_thread_destroy(thr);
				nng_cv_free(arg.cv);
				nng_mtx_free(arg.mx);
			})
		});
	});

	Convey("Condition variables work", {

		So(nng_mtx_alloc(&arg.mx) == 0);
		So(nng_cv_alloc(&arg.cv, arg.mx) == 0);

		Reset({
			nng_cv_free(arg.cv);
			nng_mtx_free(arg.mx);
		});

		Convey("Notification works", {
			arg.did  = 0;
			arg.when = 10;
			So(nng_thread_create(&thr, notifyafter, &arg) == 0);

			nng_mtx_lock(arg.mx);
			if (!arg.did) {
				nng_cv_wait(arg.cv);
			}
			nng_mtx_unlock(arg.mx);
			nng_thread_destroy(thr);
			So(arg.did == 1);
		});

		Convey("Timeout works", {
			arg.did  = 0;
			arg.when = 200;
			So(nng_thread_create(&thr, notifyafter, &arg) == 0);
			nng_mtx_lock(arg.mx);
			if (!arg.did) {
				nng_cv_until(arg.cv, nng_clock() + 10);
			}
			So(arg.did == 0);
			nng_mtx_unlock(arg.mx);
			nng_thread_destroy(thr);
		});

		Convey("Empty timeout is EAGAIN", {
			nng_mtx_lock(arg.mx);
			So(nng_cv_until(arg.cv, 0) == NNG_EAGAIN);
			nng_mtx_unlock(arg.mx);
		});

		Convey("Not running works", {
			arg.did  = 0;
			arg.when = 1;
			nng_mtx_lock(arg.mx);
			if (!arg.did) {
				nng_cv_until(arg.cv, nng_clock() + 10);
			}
			So(arg.did == 0);
			nng_mtx_unlock(arg.mx);
		});
	});
}
#else
#define ConveyFB(x, y)
#endif

TestMain("Synchronization", {

	Convey("Synchronization works", { test_sync(); });

	ConveyFB("Fallback synchronization works", { test_sync_fallback(); });

	ConveyFB("Transform works", {
		nni_plat_sync_fallback = 0;
		So(nng_mtx_alloc(&arg.mx) == 0);
		nni_plat_sync_fallback = 1;
		So(nng_cv_alloc(&arg.cv, arg.mx) == 0);

		arg.did  = 0;
		arg.when = 10;
		So(nng_thread_create(&thr, notifyafter, &arg) == 0);

		nng_mtx_lock(arg.mx);
		if (!arg.did) {
			nng_cv_wait(arg.cv);
		}
		nng_mtx_unlock(arg.mx);
		nng_thread_destroy(thr);
		So(arg.did == 1);
		nng_cv_free(arg.cv);
		nng_mtx_free(arg.mx);
	});
})
