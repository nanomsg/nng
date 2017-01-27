//
// Copyright 2017 Garrett D'Amore <garrett@damore.org>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#ifndef CORE_DEVICE_H
#define CORE_DEVICE_H

// Device takes messages from one side, and forwards them to the other.
// It works in both directions.  Arguably we should build versions of this
// that are unidirectional, and we could extend this API with user-defined
// filtering functions.
extern int nni_device(nni_sock *, nni_sock *);

#endif // CORE_DEVICE_H
