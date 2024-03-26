= nng_random(3supp)
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

nng_random - get random number

== SYNOPSIS

[source, c]
----
#include <nng/nng.h>
#include <nng/supplemental/util/platform.h>

uint32_t nng_random(void);
----

== DESCRIPTION

The `nng_random()` returns a random number.
The value returned is suitable for use with cryptographic functions such as
key generation.
The value is obtained using platform specific cryptographically strong random
number facilities when available.

== RETURN VALUES

Random number.

== ERRORS

None.

== SEE ALSO

[.text-left]
xref:nng.7.adoc[nng(7)]
