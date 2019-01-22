#
# Copyright 2018 Capitar IT Group BV <info@capitar.com>
# Copyright 2019 Staysail Systems, Inc. <info@staysail.tech>
#
# This software is supplied under the terms of the MIT License, a
# copy of which should be located in the distribution where this
# file was obtained (LICENSE.txt).  A copy of the license may also be
# found online at https://opensource.org/licenses/MIT.
#

set(_SRCS supplemental/tcp/tcp.c)

set(NNG_SRCS ${NNG_SRCS} ${_SRCS} PARENT_SCOPE)
