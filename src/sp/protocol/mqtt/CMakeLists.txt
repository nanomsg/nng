#
# Jaylin EMQ
# https://opensource.org/licenses/MIT.
#
nng_directory(mqtt)

nng_sources_if(NNG_PROTO_BROKER mqtt_parser.c nmq_mqtt.c)
nng_headers_if(NNG_PROTO_BROKER nng/protocol/mqtt/mqtt_parser.h nng/protocol/mqtt/nmq_mqtt.h)
nng_defines_if(NNG_PROTO_BROKER NNG_HAVE_MQTT_BROKER)


#nng_sources_if(NNG_PROTO_MQTT_CLIENT mqtt_client.c)
#nng_headers_if(NNG_PROTO_MQTT_CLIENT nng/protocol/mqtt/mqtt_parser.h nng/mqtt/mqtt_client.h)
#nng_defines_if(NNG_PROTO_MQTT_CLIENT NNG_HAVE_MQTT_CLIENT)
