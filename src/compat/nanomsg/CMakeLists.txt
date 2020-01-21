#
# Copyright 2020 Staysail Systems, Inc. <info@staysail.tech>
#
# This software is supplied under the terms of the MIT License, a
# copy of which should be located in the distribution where this
# file was obtained (LICENSE.txt).  A copy of the license may also be
# found online at https://opensource.org/licenses/MIT.
#

#set(COMPAT_SOURCES compat/nanomsg/nn.c)
nng_sources(nn.c)

#set(NNG_SRCS ${NNG_SRCS} ${COMPAT_SOURCES} PARENT_SCOPE)

nng_test(compat_tcp_test)