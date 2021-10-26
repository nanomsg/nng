#
# Copyright 2021 Staysail Systems, Inc. <info@staystail.tech>
#
# This software is supplied under the terms of the MIT License, a
# copy of which should be located in the distribution where this
# file was obtained (LICENSE.txt).  A copy of the license may also be
# found online at https://opensource.org/licenses/MIT.
#

#  Core.
nng_directory(mqtt)

nng_check_sym(strlcpy string.h NNG_HAVE_STRLCPY)
nng_check_sym(strnlen string.h NNG_HAVE_STRNLEN)
nng_check_sym(strcasecmp string.h NNG_HAVE_STRCASECMP)
nng_check_sym(strncasecmp string.h NNG_HAVE_STRNCASECMP)

nng_sources(
   mqtt.c     
   mqtt.h
   mqtt_codec.c
   mqtt_codec.h
)

