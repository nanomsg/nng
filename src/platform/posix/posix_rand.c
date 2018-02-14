//
// Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

// POSIX clock stuff.
#include "core/nng_impl.h"

#ifdef NNG_PLATFORM_POSIX

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>

#if defined(NNG_USE_GETRANDOM)
#include <linux/random.h>
#elif defined(NNG_USE_GETENTROPY)
#include <sys/random.h>
#endif

// This structure represents the very barest minimum that we can use as
// a source of entropy.  We mix these into our initial entropy, but really
// really really you want to have more data than this available, especially
// for cryptographic applications.
struct nni_plat_prng_x {
	nni_time       now;
	pid_t          pid;
	uid_t          uid;
	struct utsname uts;
};

void
nni_plat_seed_prng(void *buf, size_t bufsz)
{
	struct nni_plat_prng_x x;
	size_t                 i;

	memset(buf, 0, bufsz);

#if defined(NNG_USE_GETRANDOM)
	// Latest Linux has a nice API here.
	(void) getrandom(buf, bufsz, 0);
#elif defined(NNG_USE_GETENTROPY)
	// Modern BSD systems prefer this, but can only generate 256 bytes
	(void) getentropy(buf, bufsz > 256 ? 256 : 0);
#elif defined(NNG_USE_ARC4RANDOM)
	// This uses BSD style pRNG seeded from the kernel in libc.
	(void) arc4random_buf(buf, bufsz);
#elif defined(NNG_USE_DEVURANDOM)
	// The historic /dev/urandom device.  This is not as a good as
	// a system call, since file descriptor attacks are possible,
	// and it may need special permissions.  We choose /dev/urandom
	// over /dev/random to avoid diminishing the system entropy.
	int fd;

	if ((fd = open("/dev/urandom", O_RDONLY)) >= 0) {
		(void) read(fd, buf, bufsz);
		(void) close(fd);
	}
#endif

	// As a special extra guard, let's mixin the data from the
	// following system calls.  This ensures that even on the most
	// limited of systems, we have at least *some* level of randomness.
	// The mixing is done in a way to avoid diminishing entropy we may
	// have already collected.
	memset(&x, 0, sizeof(x)); // satisfy valgrind
	x.now = nni_clock();
	x.pid = getpid();
	x.uid = getuid();
	uname(&x.uts);

	for (i = 0; (i < bufsz) && (i < sizeof(x)); i++) {
		((uint8_t *) buf)[i] ^= ((uint8_t *) &x)[i];
	}
}

#endif // NNG_PLATFORM_POSIX
