#ifndef NNG_SUPPLEMENTAL_MQTT_MQTT_MSG_H
#define NNG_SUPPLEMENTAL_MQTT_MQTT_MSG_H

// #include "mqtt_codec.h"
#ifdef __cplusplus
extern "C" {
#endif

#ifdef WIN32
#include <stdint.h>
#else
#include <inttypes.h>
#endif

#include "core/nng_impl.h"
#include "nng/mqtt/mqtt_client.h"
#include "nng/nng.h"

#define MQTT_VERSION_3_1 3
#define MQTT_VERSION_3_1_1 4
#define MQTT_VERSION_5_0 5

#define MQTT_PROTOCOL_NAME "MQTT"

#define MQTT_MAX_MSG_LEN 268435455

#define MQTT_MAX_LENGTH_BYTES 4
#define MQTT_LENGTH_VALUE_MASK 0x7F
#define MQTT_LENGTH_CONTINUATION_BIT 0x80
#define MQTT_LENGTH_SHIFT 7

typedef struct mqtt_msg_t    nni_mqtt_proto_data;
typedef nng_mqtt_packet_type nni_mqtt_packet_type;
typedef union mqtt_payload   nni_mqtt_payload;
typedef nng_mqtt_topic_qos   nni_mqtt_topic_qos;
typedef nng_mqtt_buffer      nni_mqtt_buffer;
typedef nng_mqtt_topic       nni_mqtt_topic;

/* Quality of Service types. */
#define MQTT_QOS_0_AT_MOST_ONCE 0
#define MQTT_QOS_1_AT_LEAST_ONCE 1
#define MQTT_QOS_2_EXACTLY_ONCE 2

/* CONNACK codes */
#define MQTT_CONNACK_ACCEPTED 0
#define MQTT_CONNACK_REFUSED_PROTOCOL_VERSION 1
#define MQTT_CONNACK_REFUSED_IDENTIFIER_REJECTED 2
#define MQTT_CONNACK_REFUSED_SERVER_UNAVAILABLE 3
#define MQTT_CONNACK_REFUSED_BAD_USERNAME_PASSWORD 4
#define MQTT_CONNACK_REFUSED_NOT_AUTHORIZED 5

/* Function return codes */
#define MQTT_SUCCESS 0
#define MQTT_ERR_NOMEM 1
#define MQTT_ERR_PROTOCOL 2
#define MQTT_ERR_INVAL 3
#define MQTT_ERR_PAYLOAD_SIZE 4
#define MQTT_ERR_NOT_SUPPORTED 5
#define MQTT_ERR_NOT_FOUND 6
#define MQTT_ERR_MALFORMED 7

struct pos_buf {
	uint8_t *curpos;
	uint8_t *endpos;
};

/* CONNECT flags */
typedef struct conn_flags_t {
	uint8_t reserved : 1;
	uint8_t clean_session : 1;
	uint8_t will_flag : 1;
	uint8_t will_qos : 2;
	uint8_t will_retain : 1;
	uint8_t password_flag : 1;
	uint8_t username_flag : 1;
} conn_flags;

/*****************************************************************************
 * Variable header parts
 ****************************************************************************/
typedef struct mqtt_connect_vhdr_t {
	mqtt_buf   protocol_name;
	uint8_t    protocol_version;
	conn_flags conn_flags;
	uint16_t   keep_alive;
} mqtt_connect_vhdr;

typedef struct mqtt_connack_vhdr_t {
	uint8_t connack_flags;
	uint8_t conn_return_code;
} mqtt_connack_vhdr;

typedef struct mqtt_publish_vhdr_t {
	mqtt_buf topic_name;
	uint16_t packet_id;
} mqtt_publish_vhdr;

typedef struct mqtt_puback_vhdr_t {
	uint16_t packet_id;
} mqtt_puback_vhdr;

typedef struct mqtt_pubrec_vhdr_t {
	uint16_t packet_id;
} mqtt_pubrec_vhdr;

typedef struct mqtt_pubrel_vhdr_t {
	uint16_t packet_id;
} mqtt_pubrel_vhdr;

typedef struct mqtt_pubcomp_vhdr_t {
	uint16_t packet_id;
} mqtt_pubcomp_vhdr;

typedef struct mqtt_subscribe_vhdr_t {
	uint16_t packet_id;
} mqtt_subscribe_vhdr;

typedef struct mqtt_suback_vhdr_t {
	uint16_t packet_id;
} mqtt_suback_vhdr;

typedef struct mqtt_unsubscribe_vhdr_t {
	uint16_t packet_id;
} mqtt_unsubscribe_vhdr;

typedef struct mqtt_unsuback_vhdr_t {
	uint16_t packet_id;
} mqtt_unsuback_vhdr;

/*****************************************************************************
 * Union to cover all Variable Header types
 ****************************************************************************/
union mqtt_variable_header {
	mqtt_connect_vhdr     connect;
	mqtt_connack_vhdr     connack;
	mqtt_publish_vhdr     publish;
	mqtt_puback_vhdr      puback;
	mqtt_pubrec_vhdr      pubrec;
	mqtt_pubrel_vhdr      pubrel;
	mqtt_pubcomp_vhdr     pubcomp;
	mqtt_subscribe_vhdr   subscribe;
	mqtt_suback_vhdr      suback;
	mqtt_unsubscribe_vhdr unsubscribe;
	mqtt_unsuback_vhdr    unsuback;
};

/*****************************************************************************
 * Payloads
 ****************************************************************************/
typedef struct {
	mqtt_buf client_id;
	mqtt_buf will_topic;
	mqtt_buf will_msg;
	mqtt_buf user_name;
	mqtt_buf password;
} mqtt_connect_payload;

typedef struct {
	mqtt_buf payload;
} mqtt_publish_payload;

typedef struct {
	mqtt_topic_qos *topic_arr; /* array of mqtt_topic_qos instances
	                              continuous in memory */
	uint32_t topic_count;      /* not included in the message itself */
} mqtt_subscribe_payload;

typedef struct {
	uint8_t *ret_code_arr; /* array of return codes continuous in memory */
	uint32_t ret_code_count; /* not included in the message itself */
} mqtt_suback_payload;

typedef struct {
	mqtt_buf *topic_arr;   /* array of topic_arr continuous in memory */
	uint32_t  topic_count; /* not included in the message itself */
} mqtt_unsubscribe_payload;

/*****************************************************************************
 * Union to cover all Payload types
 ****************************************************************************/
union mqtt_payload {
	mqtt_connect_payload     connect;
	mqtt_publish_payload     publish;
	mqtt_subscribe_payload   subscribe;
	mqtt_suback_payload      suback;
	mqtt_unsubscribe_payload unsubscribe;
};

typedef struct {
	uint8_t bit_0 : 1;
	uint8_t bit_1 : 1;
	uint8_t bit_2 : 1;
	uint8_t bit_3 : 1;
	uint8_t packet_type : 4;
} mqtt_common_hdr;

typedef struct {
	uint8_t retain : 1;
	uint8_t qos : 2;
	uint8_t dup : 1;
	uint8_t packet_type : 4;
} mqtt_pub_hdr;

typedef struct mqtt_fixed_hdr_t {
	union {
		mqtt_common_hdr common;
		mqtt_pub_hdr    publish;
	};

	uint32_t remaining_length; /* up to 268,435,455 (256 MB) */
} mqtt_fixed_hdr;

typedef struct mqtt_msg_t {
	/* Fixed header part */
	nni_aio * aio;  //QoS AIO
	mqtt_fixed_hdr             fixed_header;
	union mqtt_variable_header var_header;
	union mqtt_payload         payload;

	uint8_t used_bytes : 4; /* byte count for used remainingLength
	                         representation This information (combined with
	                         packetType and packetFlags)  may be used to
	                         jump the point where the actual data starts */
	bool is_decoded : 1; /* message is obtained from decoded or encoded */
	bool is_copied : 1;  /* indicates string or array members are copied */
	uint8_t _unused : 2;

} mqtt_msg;

extern int mqtt_get_remaining_length(
    uint8_t *, uint32_t, uint32_t *, uint8_t *);
extern int byte_number_for_variable_length(uint32_t);
extern int write_variable_length_value(uint32_t, struct pos_buf *);
extern int write_byte(uint8_t, struct pos_buf *);
extern int write_uint16(uint16_t, struct pos_buf *);
extern int write_byte_string(mqtt_buf *, struct pos_buf *);

extern int read_byte(struct pos_buf *, uint8_t *);
extern int read_uint16(struct pos_buf *, uint16_t *);
extern int read_utf8_str(struct pos_buf *, mqtt_buf *);
extern int read_str_data(struct pos_buf *, mqtt_buf *);
extern int read_packet_length(struct pos_buf *, uint32_t *);

extern int  mqtt_buf_create(mqtt_buf *, const uint8_t *, uint32_t);
extern int  mqtt_buf_dup(mqtt_buf *, const mqtt_buf *);
extern void mqtt_buf_free(mqtt_buf *);
extern nni_aio *nni_mqtt_msg_get_aio(nni_msg *);
extern void     nni_mqtt_msg_set_aio(nni_msg *, nni_aio *);

extern mqtt_msg *mqtt_msg_create(nni_mqtt_packet_type);

extern int mqtt_msg_dump(mqtt_msg *, mqtt_buf *, mqtt_buf *, bool);

// nni_msg proto_data alloc/free
extern int  nni_mqtt_msg_proto_data_alloc(nni_msg *);
extern void nni_mqtt_msg_proto_data_free(nni_msg *);
extern int  nni_mqtt_msg_free(void *self);
extern int  nni_mqtt_msg_dup(void **dest, const void *src);

// mqtt message alloc/encode/decode
extern int nni_mqtt_msg_alloc(nni_msg **, size_t);
extern int nni_mqtt_msg_encode(nni_msg *);
extern int nni_mqtt_msg_decode(nni_msg *);

// mqtt packet_type
extern void nni_mqtt_msg_set_packet_type(nni_msg *, nni_mqtt_packet_type);
extern nni_mqtt_packet_type nni_mqtt_msg_get_packet_type(nni_msg *);

// mqtt packet id
// NOTE: not all packet have a packet id field
extern void     nni_mqtt_msg_set_packet_id(nni_msg *, uint16_t);
extern uint16_t nni_mqtt_msg_get_packet_id(nni_msg *);

// mqtt connect
extern void nni_mqtt_msg_set_connect_clean_session(nni_msg *, bool);
extern void nni_mqtt_msg_set_connect_proto_version(nni_msg *, uint8_t);
extern void nni_mqtt_msg_set_connect_keep_alive(nni_msg *, uint16_t);
extern void nni_mqtt_msg_set_connect_client_id(nni_msg *, const char *);
extern void nni_mqtt_msg_set_connect_user_name(nni_msg *, const char *);
extern void nni_mqtt_msg_set_connect_password(nni_msg *, const char *);
extern void nni_mqtt_msg_set_connect_will_retain(nni_msg *, bool);
extern void nni_mqtt_msg_set_connect_will_topic(nni_msg *, const char *);
extern void nni_mqtt_msg_set_connect_will_msg(nni_msg *, uint8_t *, uint32_t);
extern void nni_mqtt_msg_set_connect_will_qos(nni_msg *, uint8_t);
extern bool nni_mqtt_msg_get_connect_clean_session(nni_msg *);
extern uint8_t     nni_mqtt_msg_get_connect_proto_version(nni_msg *);
extern uint16_t    nni_mqtt_msg_get_connect_keep_alive(nni_msg *);
extern const char *nni_mqtt_msg_get_connect_user_name(nni_msg *);
extern const char *nni_mqtt_msg_get_connect_password(nni_msg *);
extern const char *nni_mqtt_msg_get_connect_client_id(nni_msg *);
extern const char *nni_mqtt_msg_get_connect_will_topic(nni_msg *);
extern bool        nni_mqtt_msg_get_connect_will_retain(nni_msg *);
extern uint8_t *   nni_mqtt_msg_get_connect_will_msg(nni_msg *, uint32_t *);
extern uint8_t     nni_mqtt_msg_get_connect_will_qos(nni_msg *);

// mqtt conack
extern void    nni_mqtt_msg_set_connack_return_code(nni_msg *, uint8_t);
extern void    nni_mqtt_msg_set_connack_flags(nni_msg *, uint8_t);
extern uint8_t nni_mqtt_msg_get_connack_return_code(nni_msg *);
extern uint8_t nni_mqtt_msg_get_connack_flags(nni_msg *);

// mqtt publish
extern void        nni_mqtt_msg_set_publish_qos(nni_msg *, uint8_t);
extern uint8_t     nni_mqtt_msg_get_publish_qos(nni_msg *);
extern void        nni_mqtt_msg_set_publish_retain(nni_msg *, bool);
extern bool        nni_mqtt_msg_get_publish_retain(nni_msg *);
extern void        nni_mqtt_msg_set_publish_dup(nni_msg *, bool);
extern bool        nni_mqtt_msg_get_publish_dup(nni_msg *);
extern void        nni_mqtt_msg_set_publish_topic(nni_msg *, const char *);
extern const char *nni_mqtt_msg_get_publish_topic(nni_msg *, uint32_t *);
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

extern void nni_mqtt_msg_dump(nni_msg *, uint8_t *, uint32_t, bool);
// mqtt topic create/free
extern nni_mqtt_topic *nni_mqtt_topic_array_create(size_t n);
extern void nni_mqtt_topic_array_set(nni_mqtt_topic *, size_t, const char *);
extern void nni_mqtt_topic_array_free(nni_mqtt_topic *, size_t);

// mqtt topic_qos create/free/set
extern nni_mqtt_topic_qos *nni_mqtt_topic_qos_array_create(size_t);
extern void                nni_mqtt_topic_qos_array_set(
                   nni_mqtt_topic_qos *, size_t, const char *, uint8_t);
extern void nni_mqtt_topic_qos_array_free(nni_mqtt_topic_qos *, size_t);

#ifdef __cplusplus
}
#endif

#endif
