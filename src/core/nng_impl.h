//
// Copyright 2017 Garrett D'Amore <garrett@damore.org>
// Copyright 2017 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//
#ifndef CORE_NNG_IMPL_H
#define CORE_NNG_IMPL_H

#include "nng.h"

// Internal implementation things for NNG, common definitions, etc.
// All internal modules wind up including this file to avoid having
// to figure out which header(s) to include.
//
// Hopefully it should be clear by the name that this file and its contents
// are *NOT* for use outside of this library.
//
// Symbols that are private to the library begin with the nni_ prefix, whereas
// those starting with nng_ are intended for external consumption.  The latter
// symbols should be found in the toplevel nng.h header.
#include "core/defs.h"

#include "core/platform.h"

#include "core/aio.h"
#include "core/clock.h"
#include "core/device.h"
#include "core/idhash.h"
#include "core/init.h"
#include "core/list.h"
#include "core/message.h"
#include "core/msgqueue.h"
#include "core/options.h"
#include "core/panic.h"
#include "core/protocol.h"
#include "core/random.h"
#include "core/strs.h"
#include "core/taskq.h"
#include "core/thread.h"
#include "core/timer.h"
#include "core/transport.h"

// These have to come after the others - particularly transport.h
#include "core/endpt.h"
#include "core/pipe.h"
#include "core/socket.h"

#endif // CORE_NNG_IMPL_H
