= nng_aio_abort(3)
//
// Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This document is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

== NAME

nng_aio_abort - abort asynchronous I/O operation

== SYNOPSIS

[source, c]
----
#include <nng/nng.h>

void nng_aio_abort(nng_aio *aio, int err);
----

== DESCRIPTION

The `nng_aio_abort()` function aborts an operation previously started
with the handle _aio_.
If the operation is aborted, then the callback
for the handle will be called, and the function
xref:nng_aio_result.3.adoc[`nng_aio_result()`] will return the error _err_.

This function does not wait for the operation to be fully aborted, but
returns immediately.

If no operation is currently in progress (either because it has already
finished, or no operation has been started yet), then this function
has no effect.

== RETURN VALUES

None.

== ERRORS

None.

== SEE ALSO

[.text-left]
xref:nng_aio_alloc.3.adoc[nng_aio_alloc(3)],
xref:nng_aio_cancel.3.adoc[nng_aio_cancel(3)],
xref:nng_aio_result.3.adoc[nng_aio_result(3)],
xref:nng_aio.5.adoc[nng_aio(5)],
xref:nng.7.adoc[nng(7)]
