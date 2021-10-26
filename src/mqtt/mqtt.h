#ifndef MQTT_MQTT_H
#define MQTT_MQTT_H

#include "core/nng_impl.h"
#include "nng/nng.h"

typedef mqtt_msg                nni_mqtt_proto_data;
typedef mqtt_packet_type        nni_mqtt_packet_type;
typedef union mqtt_payload      nni_mqtt_payload;
typedef struct mqtt_topic_qos_t nni_mqtt_topic_qos;
typedef struct mqtt_buf_t       nni_mqtt_buffer;
typedef struct mqtt_buf_t       nni_mqtt_topic;

// nni_msg proto_data alloc/free
extern int  nni_mqtt_msg_proto_data_alloc(nni_msg *);
extern void nni_mqtt_msg_proto_data_free(nni_msg *);

// mqtt message alloc/encode/decode
extern int nni_mqtt_msg_alloc(nni_msg **, size_t);
extern int nni_mqtt_msg_encode(nni_msg *);
extern int nni_mqtt_msg_decode(nni_msg *);

// mqtt packet_type
extern void nni_mqtt_msg_set_packet_type(
    nni_msg *, nni_mqtt_packet_type packet_type);
extern nni_mqtt_packet_type nni_mqtt_msg_get_packet_type(nni_msg *);

// mqtt connect
extern void     nni_mqtt_msg_set_connect_clean_session(nni_msg *, bool);
extern void     nni_mqtt_msg_set_connect_will_retain(nni_msg *, bool);
extern void     nni_mqtt_msg_set_connect_proto_version(nni_msg *, uint8_t);
extern void     nni_mqtt_msg_set_connect_keep_alive(nni_msg *, uint16_t);
extern void     nni_mqtt_msg_set_connect_client_id(nni_msg *, const char *);
extern void     nni_mqtt_msg_set_connect_will_topic(nni_msg *, const char *);
extern void     nni_mqtt_msg_set_connect_will_msg(nni_msg *, const char *);
extern void     nni_mqtt_msg_set_connect_user_name(nni_msg *, const char *);
extern void     nni_mqtt_msg_set_connect_password(nni_msg *, const char *);
extern bool     nni_mqtt_msg_get_connect_clean_session(nni_msg *);
extern bool     nni_mqtt_msg_get_connect_will_retain(nni_msg *);
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
extern void        nni_mqtt_msg_set_publish_qos(nni_msg *, uint8_t);
extern uint8_t     nni_mqtt_msg_get_publish_qos(nni_msg *);
extern void        nni_mqtt_msg_set_publish_retain(nni_msg *, bool);
extern bool        nni_mqtt_msg_get_publish_retain(nni_msg *);
extern void        nni_mqtt_msg_set_publish_dup(nni_msg *, bool);
extern bool        nni_mqtt_msg_get_publish_dup(nni_msg *);
extern void        nni_mqtt_msg_set_publish_topic(nni_msg *, const char *);
extern const char *nni_mqtt_msg_get_publish_topic(nni_msg *);
extern void        nni_mqtt_msg_set_publish_packet_id(nni_msg *, uint16_t);
extern uint16_t    nni_mqtt_msg_get_publish_packet_id(nni_msg *);
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
        nni_msg *, nni_mqtt_topic_qos *, uint32_t);
extern nni_mqtt_topic_qos *nni_mqtt_msg_get_subscribe_topics(
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
        nni_msg *, nni_mqtt_topic *, uint32_t);
extern nni_mqtt_topic *nni_mqtt_msg_get_unsubscribe_topics(
    nni_msg *, uint32_t *);

// mqtt unsuback
extern void     nni_mqtt_msg_set_unsuback_packet_id(nni_msg *, uint16_t);
extern uint16_t nni_mqtt_msg_get_unsuback_packet_id(nni_msg *);

extern void nni_mqtt_msg_dump(
    nni_msg *msg, uint8_t *buffer, uint32_t len, bool print_bytes);
// mqtt topic create/free
extern nni_mqtt_topic *nni_mqtt_topic_array_create(size_t n);
extern void nni_mqtt_topic_array_set(nni_mqtt_topic *, size_t, const char *);
extern void nni_mqtt_topic_array_free(nni_mqtt_topic *, size_t);

// mqtt topic_qos create/free/set
extern nni_mqtt_topic_qos *nni_mqtt_topic_qos_array_create(size_t);
extern void                nni_mqtt_topic_qos_array_set(
                   nni_mqtt_topic_qos *, size_t, const char *, uint8_t);
extern void nni_mqtt_topic_qos_array_free(nni_mqtt_topic_qos *, size_t);

#endif