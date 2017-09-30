//
// Copyright 2017 Garrett D'Amore <garrett@damore.org>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#ifndef CORE_RANDOM_H
#define CORE_RANDOM_H

// nni_random_sys_init initializes the pRNG subsystem.  This includes obtaining
// suitable seeding material from the platform.
extern int nni_random_sys_init(void);

// nni_random_sys_fini destroys the pRNG subsystem.
extern void nni_random_sys_fini(void);

// nni_random returns a random 32-bit integer.  Note that this routine is
// thread-safe/reentrant.  The pRNG is very robust, should be of crypto
// quality.  However, its usefulness for cryptography will be determined
// by the quality of the seeding material provided by the platform.
extern uint32_t nni_random(void);

#endif // CORE_RANDOM_H
