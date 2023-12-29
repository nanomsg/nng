#
# Copyright 2020 Staysail Systems, Inc. <info@staysail.tech>
# Copyright 2018 Capitar IT Group BV <info@capitar.com>
#
# This software is supplied under the terms of the MIT License, a
# copy of which should be located in the distribution where this
# file was obtained (LICENSE.txt).  A copy of the license may also be
# found online at https://opensource.org/licenses/MIT.
#

# TCP protocol
nng_directory(mqtts)

nng_sources_if(NNG_TRANSPORT_MQTT_TLS mqtt_tls.c)
nng_headers_if(NNG_TRANSPORT_MQTT_TLS nng/mqtt/transport/tls/mqtt_tls.h)
nng_defines_if(NNG_TRANSPORT_MQTT_TLS NNG_TRANSPORT_MQTT_TLS)
