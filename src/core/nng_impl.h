/*
 * Copyright 2016 Garrett D'Amore <garrett@damore.org>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom
 * the Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#ifndef CORE_NNG_IMPL_H
#define CORE_NNG_IMPL_H

#include "nng.h"

/*
 * Internal implementation things for NNG, common definitions, etc.
 * All internal modules wind up including this file to avoid having
 * to figure out which header(s) to include.
 *
 * Hopefully it should be clear by the name that this file and its contents
 * are *NOT* for use outside of this library.
 *
 * Symbols that are private to the library begin with the nni_ prefix, whereas
 * those starting with nng_ are intended for external consumption.  The latter
 * symbols should be found in the toplevel nng.h header.
 */

#include "core/defs.h"
#include "core/list.h"
#include "core/init.h"
#include "core/message.h"
#include "core/msgqueue.h"
#include "core/panic.h"
#include "core/pipe.h"
#include "core/snprintf.h"
#include "core/platform.h"
#include "core/protocol.h"
#include "core/socket.h"
#include "core/transport.h"

#endif	/* CORE_NNG_IMPL_H */
