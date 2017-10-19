//
// Copyright 2017 Garrett D'Amore <garrett@damore.org>
// Copyright 2017 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#ifndef CORE_CLOCK_H
#define CORE_CLOCK_H

#include "core/nng_impl.h"

extern nni_time nni_clock(void);

extern void nni_msleep(nni_duration);

#endif // CORE_CLOCK_H
