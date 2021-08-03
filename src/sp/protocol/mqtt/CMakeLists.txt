#
# Jaylin EMQ
# https://opensource.org/licenses/MIT.
#

#   static mqtt parser

option(NNG_PROTO_REQ0 "Enable REQv0 protocol." ON)
mark_as_advanced(NNG_PROTO_REQ0)

option(NNG_PROTO_REP0 "Enable REPv0 protocol." ON)
mark_as_advanced(NNG_PROTO_REP0)

nng_sources_if(NNG_PROTO_REQ0 mqtt_parser.c)
nng_headers_if(NNG_PROTO_REQ0 nng/protocol/mqtt/mqtt_parser.h)
nng_defines_if(NNG_PROTO_REQ0 NNG_HAVE_MQTT)

