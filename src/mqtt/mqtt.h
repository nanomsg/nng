#ifndef MQTT_MQTT_H
#define MQTT_MQTT_H

#include "core/nng_impl.h"
#include "mqtt-codec/include/mqtt_codec.h"

typedef mqtt_msg           nni_mqtt_proto_data;
typedef mqtt_packet_type   nni_mqtt_packet_type;
typedef union mqtt_payload nni_mqtt_payload;
typedef mqtt_topic         nni_mqtt_topic;
typedef mqtt_buf_t         nni_mqtt_buffer;

// nni_msg proto_data alloc/free
extern int  nni_mqtt_msg_proto_data_alloc(nni_msg *);
extern void nni_mqtt_msg_proto_data_free(nni_msg *);

// mqtt message encode/decode
extern int nni_mqtt_msg_encode(nni_msg *);
extern int nni_mqtt_msg_decode(nni_msg *);

// mqtt packet_type
extern int nni_mqtt_msg_set_packet_type(
    nni_msg *, nni_mqtt_packet_type packet_type);
extern nni_mqtt_packet_type nni_mqtt_msg_get_packet_type(nni_msg *);

// mqtt connect
extern void     nni_mqtt_msg_set_connect_proto_version(nni_msg *, uint8_t);
extern void     nni_mqtt_msg_set_connect_keep_alive(nni_msg *, uint16_t);
extern void     nni_mqtt_msg_set_connect_client_id(nni_msg *, const char *);
extern void     nni_mqtt_msg_set_connect_will_topic(nni_msg *, const char *);
extern void     nni_mqtt_msg_set_connect_will_msg(nni_msg *, const char *);
extern void     nni_mqtt_msg_set_connect_user_name(nni_msg *, const char *);
extern void     nni_mqtt_msg_set_connect_password(nni_msg *, const char *);
extern uint8_t  nni_mqtt_msg_get_connect_proto_version(nni_msg *);
extern uint16_t nni_mqtt_msg_get_connect_keep_alive(nni_msg *);
extern const char *nni_mqtt_msg_get_connect_client_id(nni_msg *);
extern const char *nni_mqtt_msg_get_connect_will_topic(nni_msg *);
extern const char *nni_mqtt_msg_get_connect_will_msg(nni_msg *);
extern const char *nni_mqtt_msg_get_connect_user_name(nni_msg *);
extern const char *nni_mqtt_msg_get_connect_password(nni_msg *);

// mqtt conack
extern void    nni_mqtt_msg_set_conack_return_code(nni_msg *, uint8_t);
extern void    nni_mqtt_msg_set_conack_flags(nni_msg *, uint8_t);
extern uint8_t nni_mqtt_msg_get_conack_return_code(nni_msg *);
extern uint8_t nni_mqtt_msg_get_conack_flags(nni_msg *);

// mqtt publish
extern void     nni_mqtt_msg_set_publish_qos(nni_msg *, uint8_t);
extern uint8_t  nni_mqtt_msg_get_publish_qos(nni_msg *);
extern void     nni_mqtt_msg_set_publish_retain(nni_msg *, bool);
extern bool     nni_mqtt_msg_get_publish_retain(nni_msg *);
extern void     nni_mqtt_msg_set_publish_dup(nni_msg *, bool);
extern bool     nni_mqtt_msg_get_publish_dup(nni_msg *);
extern void     nni_mqtt_msg_set_publish_packet_id(nni_msg *, uint16_t);
extern uint16_t nni_mqtt_msg_get_publish_packet_id(nni_msg *);
extern void nni_mqtt_msg_set_publish_payload(nni_msg *, uint8_t *, uint32_t);
extern uint8_t *nni_mqtt_msg_get_publish_payload(nni_msg *, uint32_t *);

// mqtt puback
extern uint16_t nni_mqtt_msg_get_puback_packet_id(nni_msg *);
extern void     nni_mqtt_msg_set_puback_packet_id(nni_msg *, uint16_t);

// mqtt pubrec
extern uint16_t nni_mqtt_msg_get_pubrec_packet_id(nni_msg *);
extern void     nni_mqtt_msg_set_pubrec_packet_id(nni_msg *, uint16_t);

// mqtt pubrel
extern uint16_t nni_mqtt_msg_get_pubrel_packet_id(nni_msg *);
extern void     nni_mqtt_msg_set_pubrel_packet_id(nni_msg *, uint16_t);

// mqtt pubcomp
extern uint16_t nni_mqtt_msg_get_pubcomp_packet_id(nni_msg *);
extern void     nni_mqtt_msg_set_pubcomp_packet_id(nni_msg *, uint16_t);

// mqtt subscribe
extern uint16_t nni_mqtt_msg_get_subscribe_packet_id(nni_msg *);
extern void     nni_mqtt_msg_set_subscribe_packet_id(nni_msg *, uint16_t);
extern void     nni_mqtt_msg_set_subscribe_topics(
        nni_msg *, nni_mqtt_topic *, uint32_t);
extern nni_mqtt_topic *nni_mqtt_msg_get_subscribe_topics(
    nni_msg *, uint32_t *);

// mqtt suback
extern uint16_t nni_mqtt_msg_get_suback_packet_id(nni_msg *);
extern void     nni_mqtt_msg_set_suback_packet_id(nni_msg *, uint16_t);
extern void     nni_mqtt_msg_set_suback_return_codes(
        nni_msg *, uint8_t *, uint32_t);
extern uint8_t *nni_mqtt_msg_get_suback_return_codes(nni_msg *, uint32_t *);

// mqtt unsubscribe
extern uint16_t nni_mqtt_msg_get_unsubscribe_packet_id(nni_msg *);
extern void     nni_mqtt_msg_set_unsubscribe_packet_id(nni_msg *, uint16_t);
extern void     nni_mqtt_msg_set_unsubscribe_topics(
        nni_msg *, nni_mqtt_buffer *, uint32_t);
extern nni_mqtt_buffer *nni_mqtt_msg_get_unsubscribe_topics(
    nni_msg *, uint32_t *);

// mqtt unsuback
extern void     nni_mqtt_msg_set_unsuback_packet_id(nni_msg *, uint16_t);
extern uint16_t nni_mqtt_msg_get_unsuback_packet_id(nni_msg *);

#endif