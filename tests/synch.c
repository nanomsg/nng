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

// Notify tests for verifying condvars.
struct notifyarg {
	int          did;
	nng_duration when;
	nni_mtx      mx;
	nni_cv       cv;
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

	nni_msleep(na->when);
	nni_mtx_lock(&na->mx);
	na->did = 1;
	nni_cv_wake(&na->cv);
	nni_mtx_unlock(&na->mx);
}

struct notifyarg arg;
nni_thr          thr;

static void
test_sync(void)
{
	Convey("Mutexes work", {
		nni_mtx mx;

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
			Convey("Things block properly", {

				nni_mtx_init(&arg.mx);
				nni_cv_init(&arg.cv, &arg.mx);
				So(nni_thr_init(&thr, notifyafter, &arg) == 0);
				arg.did  = 0;
				arg.when = 0;
				nni_mtx_lock(&arg.mx);
				nni_thr_run(&thr);
				nng_msleep(10);
				So(arg.did == 0);
				nni_mtx_unlock(&arg.mx);
				nng_msleep(10);
				nni_mtx_lock(&arg.mx);
				while (!arg.did) {
					nni_cv_wait(&arg.cv);
				}
				So(arg.did != 0);
				nni_mtx_unlock(&arg.mx);
				nni_thr_fini(&thr);
				nni_cv_fini(&arg.cv);
				nni_mtx_fini(&arg.mx);
			})
		});
		Convey("We can finalize it", { nni_mtx_fini(&mx); });
	});

	Convey("Condition variables work", {

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

		Convey("Empty timeout is EAGAIN", {
			nni_mtx_lock(&arg.mx);
			So(nni_cv_until(&arg.cv, 0) == NNG_EAGAIN);
			nni_mtx_unlock(&arg.mx);
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
}

#if SYNC_FALLBACK
extern int nni_plat_sync_fallback;

#define ConveyFB(x, y) Convey(x, y)

static void
test_sync_fallback(void)
{
	nni_plat_sync_fallback = 1;
	Convey("Mutexes work", {
		nni_mtx mx;
		int     rv;

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
			Convey("Things block properly", {

				nni_mtx_init(&arg.mx);
				nni_cv_init(&arg.cv, &arg.mx);
				So(nni_thr_init(&thr, notifyafter, &arg) == 0);
				arg.did  = 0;
				arg.when = 0;
				nni_mtx_lock(&arg.mx);
				nni_thr_run(&thr);
				nng_msleep(10);
				So(arg.did == 0);
				nni_mtx_unlock(&arg.mx);
				nng_msleep(10);
				nni_mtx_lock(&arg.mx);
				while (!arg.did) {
					nni_cv_wait(&arg.cv);
				}
				So(arg.did != 0);
				nni_mtx_unlock(&arg.mx);
				nni_thr_fini(&thr);
				nni_cv_fini(&arg.cv);
				nni_mtx_fini(&arg.mx);
			})
		});
		Convey("We can finalize it", { nni_mtx_fini(&mx); });
	});

	Convey("Condition variables work", {

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

		Convey("Empty timeout is EAGAIN", {
			nni_mtx_lock(&arg.mx);
			So(nni_cv_until(&arg.cv, 0) == NNG_EAGAIN);
			nni_mtx_unlock(&arg.mx);
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
}
#else
#define ConveyFB(x, y)
#endif

TestMain("Synchronization", {
	nni_init();

	Convey("Synchronization works", { test_sync(); });

	ConveyFB("Fallback synchronization works", { test_sync_fallback(); });

	ConveyFB("Transform works", {
		nni_plat_sync_fallback = 0;
		nni_mtx_init(&arg.mx);
		nni_plat_sync_fallback = 1;
		nni_cv_init(&arg.cv, &arg.mx);
		So(nni_thr_init(&thr, notifyafter, &arg) == 0);

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
})
