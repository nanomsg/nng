//
// Copyright 2025 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2017 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//
#ifndef CORE_NNG_IMPL_H
#define CORE_NNG_IMPL_H

#include "../../include/nng/nng.h"

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
#include "defs.h"

#include "platform.h"

#include "aio.h"
#include "device.h"
#include "file.h"
#include "idhash.h"
#include "init.h"
#include "list.h"
#include "lmq.h"
#include "message.h"
#include "msgqueue.h"
#include "options.h"
#include "panic.h"
#include "pollable.h"
#include "protocol.h"
#include "reap.h"
#include "refcnt.h"
#include "stats.h"

#include "stream.h"
#include "strs.h"
#include "taskq.h"
#include "thread.h"
#include "url.h"

// transport needs to come after url
#include "../sp/transport.h"

// These have to come after the others - particularly transport.h

#include "dialer.h"
#include "listener.h"
#include "pipe.h"
#include "socket.h"

#endif // CORE_NNG_IMPL_H
