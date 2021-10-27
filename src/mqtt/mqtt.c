#include "mqtt.h"
#include <stdlib.h>
#include <string.h>

static void nni_mqtt_msg_append_u8(nni_msg *, uint8_t);
static void nni_mqtt_msg_append_u16(nni_msg *, uint16_t);
static void nni_mqtt_msg_append_byte_str(nni_msg *, nni_mqtt_buffer *);
static void nni_mqtt_msg_encode_fixed_header(nni_msg *, nni_mqtt_proto_data *);
static int  nni_mqtt_msg_encode_connect(nni_msg *);
static int  nni_mqtt_msg_encode_connack(nni_msg *);
static int  nni_mqtt_msg_encode_subscribe(nni_msg *);
static int  nni_mqtt_msg_encode_suback(nni_msg *);
static int  nni_mqtt_msg_encode_publish(nni_msg *);
static int  nni_mqtt_msg_encode_puback(nni_msg *);
static int  nni_mqtt_msg_encode_pubrec(nni_msg *);
static int  nni_mqtt_msg_encode_pubrel(nni_msg *);
static int  nni_mqtt_msg_encode_pubcomp(nni_msg *);
static int  nni_mqtt_msg_encode_unsubscribe(nni_msg *);
static int  nni_mqtt_msg_encode_unsuback(nni_msg *);
static int  nni_mqtt_msg_encode_base(nni_msg *);

static int nni_mqtt_msg_free(void *);
static int nni_mqtt_msg_dup(void **, const void *);

typedef struct {
	nni_mqtt_packet_type packet_type;
	int (*encode)(nni_msg *);
} mqtt_msg_encode_handler;

static mqtt_msg_encode_handler encode_funcs[] = {
	{ NNG_MQTT_CONNECT, nni_mqtt_msg_encode_connect },
	{ NNG_MQTT_CONNACK, nni_mqtt_msg_encode_connack },
	{ NNG_MQTT_PUBLISH, nni_mqtt_msg_encode_publish },
	{ NNG_MQTT_PUBACK, nni_mqtt_msg_encode_puback },
	{ NNG_MQTT_PUBREC, nni_mqtt_msg_encode_pubrec },
	{ NNG_MQTT_PUBREL, nni_mqtt_msg_encode_pubrel },
	{ NNG_MQTT_PUBCOMP, nni_mqtt_msg_encode_pubcomp },
	{ NNG_MQTT_SUBSCRIBE, nni_mqtt_msg_encode_subscribe },
	{ NNG_MQTT_SUBACK, nni_mqtt_msg_encode_suback },
	{ NNG_MQTT_UNSUBSCRIBE, nni_mqtt_msg_encode_unsubscribe },
	{ NNG_MQTT_UNSUBACK, nni_mqtt_msg_encode_unsuback },
	{ NNG_MQTT_PINGREQ, nni_mqtt_msg_encode_base },
	{ NNG_MQTT_PINGRESP, nni_mqtt_msg_encode_base },
	{ NNG_MQTT_DISCONNECT, nni_mqtt_msg_encode_base }
};

static nni_proto_msg_ops proto_msg_ops = {

	.msg_free = nni_mqtt_msg_free,

	.msg_dup = nni_mqtt_msg_dup
};

static int
nni_mqtt_msg_free(void *self)
{
	if (self) {
		free(self);
		return (0);
	}
	return (1);
}

static int
nni_mqtt_msg_dup(void **dest, const void *src)
{
	nni_mqtt_proto_data *mqtt;

	mqtt = NNI_ALLOC_STRUCT(mqtt);
	memcpy(mqtt, (nni_mqtt_proto_data *) src, sizeof(nni_mqtt_proto_data));
	*dest = mqtt;

	return (0);
}

int
nni_mqtt_msg_proto_data_alloc(nni_msg *msg)
{
	nni_mqtt_proto_data *proto_data;

	if ((proto_data = NNI_ALLOC_STRUCT(proto_data)) == NULL) {
		return NNG_ENOMEM;
	}

	nni_msg_set_proto_data(msg, &proto_msg_ops, proto_data);

	return 0;
}

void
nni_mqtt_msg_proto_data_free(nni_msg *msg)
{
	nni_mqtt_proto_data *proto_data = nni_msg_get_proto_data(msg);
	NNI_FREE_STRUCT(proto_data);
}

int
nni_mqtt_msg_alloc(nni_msg **msg, size_t sz)
{
	int rv;

	if ((rv = nni_msg_alloc(msg, sz)) != 0) {
		return rv;
	}

	if ((rv = nni_mqtt_msg_proto_data_alloc(*msg)) != 0) {
		return rv;
	}

	return (0);
}

int
nni_mqtt_msg_encode(nni_msg *msg)
{
	nni_msg_clear(msg);
	nni_msg_header_clear(msg);

	nni_mqtt_proto_data *mqtt = nni_msg_get_proto_data(msg);

	for (size_t i = 0;
	     i < sizeof(encode_funcs) / sizeof(mqtt_msg_encode_handler); i++) {
		if (encode_funcs[i].packet_type ==
		    mqtt->fixed_header.common.packet_type) {
			return encode_funcs[i].encode(msg);
		}
	}

	return MQTT_ERR_PROTOCOL;
}

int
nni_mqtt_msg_decode(nni_msg *msg)
{
	uint8_t *packet = nni_msg_body(msg);
	size_t   len    = nni_msg_len(msg);
	uint32_t result;

	nni_mqtt_proto_data *proto_data =
	    mqtt_msg_decode_raw_packet(packet, len, &result, 0);

	if (result != MQTT_SUCCESS) {
		return result;
	}

	nni_msg_set_proto_data(msg, &proto_msg_ops, proto_data);

	return (0);
}

void
nni_mqtt_msg_set_packet_type(nni_msg *msg, nni_mqtt_packet_type packet_type)
{
	nni_mqtt_proto_data *proto_data = nni_msg_get_proto_data(msg);

	proto_data->fixed_header.common.packet_type = packet_type;
}

nni_mqtt_packet_type
nni_mqtt_msg_get_packet_type(nni_msg *msg)
{
	nni_mqtt_proto_data *proto_data = nni_msg_get_proto_data(msg);

	return proto_data->fixed_header.common.packet_type;
}

void
nni_mqtt_msg_set_publish_qos(nni_msg *msg, uint8_t qos)
{
	nni_mqtt_proto_data *proto_data = nni_msg_get_proto_data(msg);

	proto_data->fixed_header.publish.qos = qos;
}

uint8_t
nni_mqtt_msg_get_publish_qos(nni_msg *msg)
{
	nni_mqtt_proto_data *proto_data = nni_msg_get_proto_data(msg);

	return proto_data->fixed_header.publish.qos;
}

void
nni_mqtt_msg_set_publish_retain(nni_msg *msg, bool retain)
{
	nni_mqtt_proto_data *proto_data         = nni_msg_get_proto_data(msg);
	proto_data->fixed_header.publish.retain = (uint8_t) retain;
}

bool
nni_mqtt_msg_get_publish_retain(nni_msg *msg)
{
	nni_mqtt_proto_data *proto_data = nni_msg_get_proto_data(msg);
	return proto_data->fixed_header.publish.retain;
}

void
nni_mqtt_msg_set_publish_dup(nni_msg *msg, bool dup)
{
	nni_mqtt_proto_data *proto_data      = nni_msg_get_proto_data(msg);
	proto_data->fixed_header.publish.dup = (uint8_t) dup;
}

bool
nni_mqtt_msg_get_publish_dup(nni_msg *msg)
{
	nni_mqtt_proto_data *proto_data = nni_msg_get_proto_data(msg);
	return proto_data->fixed_header.publish.dup;
}

void
nni_mqtt_msg_set_publish_topic(nni_msg *msg, const char *topic)
{
	nni_mqtt_proto_data *proto_data = nni_msg_get_proto_data(msg);
	proto_data->var_header.publish.topic_name.buf    = (uint8_t *) topic;
	proto_data->var_header.publish.topic_name.length = strlen(topic);
}

const char *
nni_mqtt_msg_get_publish_topic(nni_msg *msg)
{
	nni_mqtt_proto_data *proto_data = nni_msg_get_proto_data(msg);
	return (const char *) proto_data->var_header.publish.topic_name.buf;
}

void
nni_mqtt_msg_set_publish_payload(nni_msg *msg, uint8_t *payload, uint32_t len)
{
	nni_mqtt_proto_data *proto_data         = nni_msg_get_proto_data(msg);
	proto_data->payload.publish.payload.buf = payload;
	proto_data->payload.publish.payload.length = len;
}

uint8_t *
nni_mqtt_msg_get_publish_payload(nni_msg *msg, uint32_t *outlen)
{
	nni_mqtt_proto_data *proto_data = nni_msg_get_proto_data(msg);
	*outlen = proto_data->payload.publish.payload.length;
	return proto_data->payload.publish.payload.buf;
}

void
nni_mqtt_msg_set_publish_packet_id(nni_msg *msg, uint16_t packet_id)
{
	nni_mqtt_proto_data *proto_data          = nni_msg_get_proto_data(msg);
	proto_data->var_header.publish.packet_id = packet_id;
}

uint16_t
nni_mqtt_msg_get_publish_packet_id(nni_msg *msg)
{
	nni_mqtt_proto_data *proto_data = nni_msg_get_proto_data(msg);
	return proto_data->var_header.publish.packet_id;
}

void
nni_mqtt_msg_set_puback_packet_id(nni_msg *msg, uint16_t packet_id)
{
	nni_mqtt_proto_data *proto_data         = nni_msg_get_proto_data(msg);
	proto_data->var_header.puback.packet_id = packet_id;
}

uint16_t
nni_mqtt_msg_get_puback_packet_id(nni_msg *msg)
{
	nni_mqtt_proto_data *proto_data = nni_msg_get_proto_data(msg);
	return proto_data->var_header.puback.packet_id;
}

uint16_t
nni_mqtt_msg_get_pubrec_packet_id(nni_msg *msg)
{
	nni_mqtt_proto_data *proto_data = nni_msg_get_proto_data(msg);
	return proto_data->var_header.pubrec.packet_id;
}

void
nni_mqtt_msg_set_pubrec_packet_id(nni_msg *msg, uint16_t packet_id)
{
	nni_mqtt_proto_data *proto_data         = nni_msg_get_proto_data(msg);
	proto_data->var_header.pubrec.packet_id = packet_id;
}

uint16_t
nni_mqtt_msg_get_pubrel_packet_id(nni_msg *msg)
{
	nni_mqtt_proto_data *proto_data = nni_msg_get_proto_data(msg);
	return proto_data->var_header.pubrel.packet_id;
}

void
nni_mqtt_msg_set_pubrel_packet_id(nni_msg *msg, uint16_t packet_id)
{
	nni_mqtt_proto_data *proto_data         = nni_msg_get_proto_data(msg);
	proto_data->var_header.pubrel.packet_id = packet_id;
}

uint16_t
nni_mqtt_msg_get_pubcomp_packet_id(nni_msg *msg)
{
	nni_mqtt_proto_data *proto_data = nni_msg_get_proto_data(msg);
	return proto_data->var_header.pubcomp.packet_id;
}

void
nni_mqtt_msg_set_pubcomp_packet_id(nni_msg *msg, uint16_t packet_id)
{
	nni_mqtt_proto_data *proto_data          = nni_msg_get_proto_data(msg);
	proto_data->var_header.pubcomp.packet_id = packet_id;
}

uint16_t
nni_mqtt_msg_get_subscribe_packet_id(nni_msg *msg)
{
	nni_mqtt_proto_data *proto_data = nni_msg_get_proto_data(msg);
	return proto_data->var_header.subscribe.packet_id;
}

void
nni_mqtt_msg_set_subscribe_packet_id(nni_msg *msg, uint16_t packet_id)
{
	nni_mqtt_proto_data *proto_data = nni_msg_get_proto_data(msg);
	proto_data->var_header.subscribe.packet_id = packet_id;
}

void
nni_mqtt_msg_set_subscribe_topics(
    nni_msg *msg, nni_mqtt_topic_qos *topic, uint32_t topic_count)
{
	nni_mqtt_proto_data *proto_data         = nni_msg_get_proto_data(msg);
	proto_data->payload.subscribe.topic_arr = topic;
	proto_data->payload.subscribe.topic_count = topic_count;
}

nni_mqtt_topic_qos *
nni_mqtt_msg_get_subscribe_topics(nni_msg *msg, uint32_t *topic_count)
{
	nni_mqtt_proto_data *proto_data = nni_msg_get_proto_data(msg);
	*topic_count = proto_data->payload.subscribe.topic_count;
	return proto_data->payload.subscribe.topic_arr;
}

uint16_t
nni_mqtt_msg_get_suback_packet_id(nni_msg *msg)
{
	nni_mqtt_proto_data *proto_data = nni_msg_get_proto_data(msg);
	return proto_data->var_header.suback.packet_id;
}

void
nni_mqtt_msg_set_suback_packet_id(nni_msg *msg, uint16_t packet_id)
{
	nni_mqtt_proto_data *proto_data         = nni_msg_get_proto_data(msg);
	proto_data->var_header.suback.packet_id = packet_id;
}

void
nni_mqtt_msg_set_suback_return_codes(
    nni_msg *msg, uint8_t *ret_codes, uint32_t ret_codes_count)
{
	nni_mqtt_proto_data *proto_data         = nni_msg_get_proto_data(msg);
	proto_data->payload.suback.ret_code_arr = ret_codes;
	proto_data->payload.suback.ret_code_count = ret_codes_count;
}

uint8_t *
nni_mqtt_msg_get_suback_return_codes(nni_msg *msg, uint32_t *ret_codes_count)
{
	nni_mqtt_proto_data *proto_data = nni_msg_get_proto_data(msg);
	*ret_codes_count = proto_data->payload.suback.ret_code_count;
	return proto_data->payload.suback.ret_code_arr;
}

uint16_t
nni_mqtt_msg_get_unsubscribe_packet_id(nni_msg *msg)
{
	nni_mqtt_proto_data *proto_data = nni_msg_get_proto_data(msg);
	return proto_data->var_header.unsubscribe.packet_id;
}

void
nni_mqtt_msg_set_unsubscribe_packet_id(nni_msg *msg, uint16_t packet_id)
{
	nni_mqtt_proto_data *proto_data = nni_msg_get_proto_data(msg);
	proto_data->var_header.unsubscribe.packet_id = packet_id;
}

void
nni_mqtt_msg_set_unsubscribe_topics(
    nni_msg *msg, nni_mqtt_topic *topic, uint32_t topic_count)
{
	nni_mqtt_proto_data *proto_data = nni_msg_get_proto_data(msg);
	proto_data->payload.unsubscribe.topic_arr   = (nni_mqtt_topic *) topic;
	proto_data->payload.unsubscribe.topic_count = topic_count;
}

nni_mqtt_topic *
nni_mqtt_msg_get_unsubscribe_topics(nni_msg *msg, uint32_t *topic_count)
{
	nni_mqtt_proto_data *proto_data = nni_msg_get_proto_data(msg);
	*topic_count = proto_data->payload.unsubscribe.topic_count;
	return (nni_mqtt_topic *) proto_data->payload.unsubscribe.topic_arr;
}

void
nni_mqtt_msg_set_unsuback_packet_id(nni_msg *msg, uint16_t packet_id)
{
	nni_mqtt_proto_data *proto_data = nni_msg_get_proto_data(msg);
	proto_data->var_header.unsuback.packet_id = packet_id;
}

uint16_t
nni_mqtt_msg_get_unsuback_packet_id(nni_msg *msg)
{
	nni_mqtt_proto_data *proto_data = nni_msg_get_proto_data(msg);
	return proto_data->var_header.unsuback.packet_id;
}

void
nni_mqtt_msg_set_connect_clean_session(nni_msg *msg, bool clean_session)
{
	nni_mqtt_proto_data *proto_data = nni_msg_get_proto_data(msg);
	proto_data->var_header.connect.conn_flags.clean_session =
	    clean_session;
}

void
nni_mqtt_msg_set_connect_will_retain(nni_msg *msg, bool will_retain)
{
	nni_mqtt_proto_data *proto_data = nni_msg_get_proto_data(msg);
	proto_data->var_header.connect.conn_flags.will_retain = will_retain;
}

void
nni_mqtt_msg_set_connect_proto_version(nni_msg *msg, uint8_t version)
{
	nni_mqtt_proto_data *proto_data = nni_msg_get_proto_data(msg);
	proto_data->var_header.connect.protocol_version = version;
}

void
nni_mqtt_msg_set_connect_keep_alive(nni_msg *msg, uint16_t keep_alive)
{
	nni_mqtt_proto_data *proto_data = nni_msg_get_proto_data(msg);
	proto_data->var_header.connect.keep_alive = keep_alive;
}

bool
nni_mqtt_msg_get_connect_clean_session(nni_msg *msg)
{
	nni_mqtt_proto_data *proto_data = nni_msg_get_proto_data(msg);
	return proto_data->var_header.connect.conn_flags.clean_session;
}

bool
nni_mqtt_msg_get_connect_will_retain(nni_msg *msg)
{
	nni_mqtt_proto_data *proto_data = nni_msg_get_proto_data(msg);
	return proto_data->var_header.connect.conn_flags.will_retain;
}

uint8_t
nni_mqtt_msg_get_connect_proto_version(nni_msg *msg)
{
	nni_mqtt_proto_data *proto_data = nni_msg_get_proto_data(msg);
	return proto_data->var_header.connect.protocol_version;
}

uint16_t
nni_mqtt_msg_get_connect_keep_alive(nni_msg *msg)
{
	nni_mqtt_proto_data *proto_data = nni_msg_get_proto_data(msg);
	return proto_data->var_header.connect.keep_alive;
}

void
nni_mqtt_msg_set_connect_client_id(nni_msg *msg, const char *client_id)
{
	nni_mqtt_proto_data *proto_data = nni_msg_get_proto_data(msg);
	proto_data->payload.connect.client_id.buf    = (uint8_t *) client_id;
	proto_data->payload.connect.client_id.length = strlen(client_id);
}

void
nni_mqtt_msg_set_connect_will_topic(nni_msg *msg, const char *will_topic)
{
	nni_mqtt_proto_data *proto_data = nni_msg_get_proto_data(msg);
	proto_data->payload.connect.will_topic.buf    = (uint8_t *) will_topic;
	proto_data->payload.connect.will_topic.length = strlen(will_topic);
}

void
nni_mqtt_msg_set_connect_will_msg(nni_msg *msg, const char *will_msg)
{
	nni_mqtt_proto_data *proto_data          = nni_msg_get_proto_data(msg);
	proto_data->payload.connect.will_msg.buf = (uint8_t *) will_msg;
	proto_data->payload.connect.will_msg.length = strlen(will_msg);
}

void
nni_mqtt_msg_set_connect_user_name(nni_msg *msg, const char *user_name)
{
	nni_mqtt_proto_data *proto_data = nni_msg_get_proto_data(msg);
	proto_data->payload.connect.user_name.buf    = (uint8_t *) user_name;
	proto_data->payload.connect.user_name.length = strlen(user_name);
}

void
nni_mqtt_msg_set_connect_password(nni_msg *msg, const char *password)
{
	nni_mqtt_proto_data *proto_data          = nni_msg_get_proto_data(msg);
	proto_data->payload.connect.password.buf = (uint8_t *) password;
	proto_data->payload.connect.password.length = strlen(password);
}

const char *
nni_mqtt_msg_get_connect_client_id(nni_msg *msg)
{
	nni_mqtt_proto_data *proto_data = nni_msg_get_proto_data(msg);
	return (const char *) proto_data->payload.connect.client_id.buf;
}

const char *
nni_mqtt_msg_get_connect_will_topic(nni_msg *msg)
{
	nni_mqtt_proto_data *proto_data = nni_msg_get_proto_data(msg);
	return (const char *) proto_data->payload.connect.will_topic.buf;
}

const char *
nni_mqtt_msg_get_connect_will_msg(nni_msg *msg)
{
	nni_mqtt_proto_data *proto_data = nni_msg_get_proto_data(msg);
	return (const char *) proto_data->payload.connect.will_msg.buf;
}

const char *
nni_mqtt_msg_get_connect_user_name(nni_msg *msg)
{
	nni_mqtt_proto_data *proto_data = nni_msg_get_proto_data(msg);
	return (const char *) proto_data->payload.connect.user_name.buf;
}

const char *
nni_mqtt_msg_get_connect_password(nni_msg *msg)
{
	nni_mqtt_proto_data *proto_data = nni_msg_get_proto_data(msg);
	return (const char *) proto_data->payload.connect.password.buf;
}

void
nni_mqtt_msg_set_conack_return_code(nni_msg *msg, uint8_t code)
{
	nni_mqtt_proto_data *proto_data = nni_msg_get_proto_data(msg);
	proto_data->var_header.connack.conn_return_code = code;
}

void
nni_mqtt_msg_set_conack_flags(nni_msg *msg, uint8_t flags)
{
	nni_mqtt_proto_data *proto_data = nni_msg_get_proto_data(msg);
	proto_data->var_header.connack.connack_flags = flags;
}

uint8_t
nni_mqtt_msg_get_conack_return_code(nni_msg *msg)
{
	nni_mqtt_proto_data *proto_data = nni_msg_get_proto_data(msg);
	return proto_data->var_header.connack.conn_return_code;
}

uint8_t
nni_mqtt_msg_get_conack_flags(nni_msg *msg)
{
	nni_mqtt_proto_data *proto_data = nni_msg_get_proto_data(msg);
	return proto_data->var_header.connack.connack_flags;
}

void
nni_mqtt_msg_dump(
    nni_msg *msg, uint8_t *buffer, uint32_t len, bool print_bytes)
{
	nni_mqtt_proto_data *proto_data = nni_msg_get_proto_data(msg);

	mqtt_buf mqbuf;
	mqbuf.buf    = buffer;
	mqbuf.length = len;

	mqtt_msg_dump(proto_data, &mqbuf, print_bytes);
}

nni_mqtt_topic *
nni_mqtt_topic_array_create(size_t n)
{
	nni_mqtt_topic *topic;
	topic = (nni_mqtt_topic *) NNI_ALLOC_STRUCTS(topic, n);
	return topic;
}

void
nni_mqtt_topic_array_set(
    nni_mqtt_topic *topic, size_t index, const char *topic_name)
{
	topic[index].buf    = (uint8_t *) nni_strdup(topic_name);
	topic[index].length = strlen(topic_name);
}

void
nni_mqtt_topic_array_free(nni_mqtt_topic *topic, size_t n)
{
	for (size_t i = 0; i < n; i++) {
		nni_strfree((char *) topic[i].buf);
		topic[i].length = 0;
	}
	NNI_FREE_STRUCTS(topic, n);
}

nni_mqtt_topic_qos *
nni_mqtt_topic_qos_array_create(size_t n)
{
	nni_mqtt_topic_qos *tq;
	tq = NNI_ALLOC_STRUCTS(tq, n);
	return tq;
}

void
nni_mqtt_topic_qos_array_set(nni_mqtt_topic_qos *topic_qos, size_t index,
    const char *topic_name, uint8_t qos)
{
	topic_qos[index].topic.buf    = (uint8_t *) nni_strdup(topic_name);
	topic_qos[index].topic.length = strlen(topic_name);
	topic_qos[index].qos          = qos;
}

void
nni_mqtt_topic_qos_array_free(nni_mqtt_topic_qos *topic_qos, size_t n)
{
	for (size_t i = 0; i < n; i++) {
		nni_strfree((char *) topic_qos[i].topic.buf);
	}
	NNI_FREE_STRUCTS(topic_qos, n);
}

static void
nni_mqtt_msg_append_u8(nni_msg *msg, uint8_t val)
{
	nni_msg_append(msg, &val, 1);
}

static void
nni_mqtt_msg_append_u16(nni_msg *msg, uint16_t val)
{
	uint8_t buf[2] = { 0 };
	NNI_PUT16(buf, val);
	nni_msg_append(msg, buf, 2);
}

static void
nni_mqtt_msg_append_byte_str(nni_msg *msg, nni_mqtt_buffer *str)
{
	nni_mqtt_msg_append_u16(msg, (uint16_t) str->length);
	nni_msg_append(msg, str->buf, str->length);
}

static void
nni_mqtt_msg_encode_fixed_header(nni_msg *msg, nni_mqtt_proto_data *data)
{
	uint8_t        rlen[4] = { 0 };
	struct pos_buf buf     = { .curpos = &rlen[0],
                .endpos = &rlen[sizeof(rlen) / sizeof(rlen[0]) - 1] };

	nni_msg_header_clear(msg);
	uint8_t header = *(uint8_t *) &data->fixed_header.common;

	nni_msg_header_append_u32(msg, (uint32_t) header);

	int len = write_variable_length_value(
	    data->fixed_header.remaining_length, &buf);

	for (int i = 0; i < len; i++) {
		nni_msg_header_append_u32(msg, rlen[i]);
	}
}

static int
nni_mqtt_msg_encode_connect(nni_msg *msg)
{
	nni_mqtt_proto_data *mqtt = nni_msg_get_proto_data(msg);

	nni_msg_clear(msg);

	int poslength = 6;

	mqtt_connect_vhdr *var_header = &mqtt->var_header.connect;

	/* length of protocol-name (consider "MQTT" by default */
	poslength += (var_header->protocol_name.length == 0)
	    ? 4
	    : var_header->protocol_name.length;

	/* add the length of payload part */
	mqtt_connect_payload *payload = &mqtt->payload.connect;

	/* Will Topic */
	if (payload->will_topic.length > 0) {
		poslength += 2 + payload->will_topic.length;
		var_header->conn_flags.will_flag = 1;
	}
	/* Will Message */
	if (payload->will_msg.length > 0) {
		poslength += 2 + payload->will_msg.length;
		var_header->conn_flags.will_flag = 1;
	}
	/* User Name */
	if (payload->user_name.length > 0) {
		poslength += 2 + payload->user_name.length;
		var_header->conn_flags.username_flag = 1;
	}
	/* Password */
	if (payload->password.length > 0) {
		poslength += 2 + payload->password.length;
		var_header->conn_flags.password_flag = 1;
	}

	mqtt->fixed_header.remaining_length = poslength;
	if (mqtt->fixed_header.remaining_length > MQTT_MAX_MSG_LEN) {
		return MQTT_ERR_PAYLOAD_SIZE;
	}

	nni_mqtt_msg_append_byte_str(msg, &var_header->protocol_name);

	nni_mqtt_msg_append_u8(msg, var_header->protocol_version);

	/* Connect Flags */
	nni_mqtt_msg_append_u8(msg, *(uint8_t *) &var_header->conn_flags);

	/* Keep Alive */
	nni_mqtt_msg_append_u16(msg, var_header->keep_alive);

	/* Now we are in payload part */

	/* Client Identifier */
	/* Client Identifier is mandatory */
	nni_mqtt_msg_append_byte_str(msg, &payload->client_id);

	/* Will Topic */
	if (payload->will_topic.length) {
		if (!(var_header->conn_flags.will_flag)) {
			return MQTT_ERR_PROTOCOL;
		}
		nni_mqtt_msg_append_byte_str(msg, &payload->will_topic);
	} else {
		if (var_header->conn_flags.will_flag) {
			return MQTT_ERR_PROTOCOL;
		}
	}

	/* Will Message */
	if (payload->will_msg.length) {
		if (!(var_header->conn_flags.will_flag)) {
			return MQTT_ERR_PROTOCOL;
		}
		nni_mqtt_msg_append_byte_str(msg, &payload->will_msg);
	} else {
		if (var_header->conn_flags.will_flag) {
			return MQTT_ERR_PROTOCOL;
		}
	}

	/* User-Name */
	if (payload->user_name.length) {
		if (!(var_header->conn_flags.username_flag)) {
			return MQTT_ERR_PROTOCOL;
		}
		nni_mqtt_msg_append_byte_str(msg, &payload->user_name);
	} else {
		if (var_header->conn_flags.username_flag) {
			return MQTT_ERR_PROTOCOL;
		}
	}

	/* Password */
	if (payload->password.length) {
		if (!(var_header->conn_flags.password_flag)) {
			return MQTT_ERR_PROTOCOL;
		}
		nni_mqtt_msg_append_byte_str(msg, &payload->password);
	} else {
		if (var_header->conn_flags.password_flag) {
			return MQTT_ERR_PROTOCOL;
		}
	}

	// Append mqtt fixed header to nng_msg header
	nni_mqtt_msg_encode_fixed_header(msg, mqtt);

	return MQTT_SUCCESS;
}

static int
nni_mqtt_msg_encode_connack(nni_msg *msg)
{
	nni_mqtt_proto_data *mqtt = nni_msg_get_proto_data(msg);
	nni_msg_clear(msg);

	int poslength = 2; /* ConnAck Flags(1) + Connect Return Code(1) */

	mqtt_connack_vhdr *var_header = &mqtt->var_header.connack;

	mqtt->fixed_header.remaining_length = poslength;

	/* Connect Acknowledge Flags */
	nni_mqtt_msg_append_u8(msg, *(uint8_t *) &var_header->connack_flags);

	/* Connect Return Code */
	nni_mqtt_msg_append_u8(
	    msg, *(uint8_t *) &var_header->conn_return_code);

	nni_mqtt_msg_encode_fixed_header(msg, mqtt);

	return MQTT_SUCCESS;
}

static int
nni_mqtt_msg_encode_subscribe(nni_msg *msg)
{
	nni_mqtt_proto_data *mqtt = nni_msg_get_proto_data(msg);
	nni_msg_clear(msg);

	int poslength = 0;

	poslength += 2; /* for Packet Identifier */

	mqtt_subscribe_payload *spld = &mqtt->payload.subscribe;

	/* Go through topic filters to calculate length information */
	for (size_t i = 0; i < spld->topic_count; i++) {
		mqtt_topic_qos *topic = &spld->topic_arr[i];
		poslength += topic->topic.length;
		poslength += 1; // for 'options' byte
		poslength += 2; // for 'length' field of Topic Filter, which is
		                // encoded as UTF-8 encoded strings */
	}

	mqtt->fixed_header.remaining_length = poslength;
	mqtt->fixed_header.common.bit_1     = 1;

	mqtt_subscribe_vhdr *var_header = &mqtt->var_header.subscribe;
	/* Packet Id */
	nni_mqtt_msg_append_u16(msg, var_header->packet_id);

	/* Subscribe topic_arr */
	for (size_t i = 0; i < spld->topic_count; i++) {
		mqtt_topic_qos *topic = &spld->topic_arr[i];
		nni_mqtt_msg_append_byte_str(msg, &topic->topic);
		nni_mqtt_msg_append_u8(msg, topic->qos);
	}

	nni_mqtt_msg_encode_fixed_header(msg, mqtt);

	return MQTT_SUCCESS;
}

static int
nni_mqtt_msg_encode_suback(nni_msg *msg)
{
	nni_mqtt_proto_data *mqtt = nni_msg_get_proto_data(msg);
	nni_msg_clear(msg);

	int poslength = 2; /* for Packet Identifier */

	mqtt_suback_vhdr *   var_header = &mqtt->var_header.suback;
	mqtt_suback_payload *spld       = &mqtt->payload.suback;

	poslength += spld->ret_code_count;

	mqtt->fixed_header.remaining_length = poslength;

	/* Packet Identifier */
	nni_mqtt_msg_append_u16(msg, var_header->packet_id);

	/* Return Codes */
	nni_msg_append(msg, spld->ret_code_arr, spld->ret_code_count);

	nni_mqtt_msg_encode_fixed_header(msg, mqtt);

	return MQTT_SUCCESS;
}

static int
nni_mqtt_msg_encode_publish(nni_msg *msg)
{
	nni_mqtt_proto_data *mqtt = nni_msg_get_proto_data(msg);
	nni_msg_clear(msg);

	int poslength = 0;

	poslength += 2; /* for Topic Name length field */
	poslength += mqtt->var_header.publish.topic_name.length;
	/* Packet Identifier is requested if QoS>0 */
	if (mqtt->fixed_header.publish.qos > 0) {
		poslength += 2; /* for Packet Identifier */
	}
	poslength += mqtt->payload.publish.payload.length;

	mqtt->fixed_header.remaining_length = poslength;

	mqtt_publish_vhdr *var_header = &mqtt->var_header.publish;

	/* Topic Name */
	nni_mqtt_msg_append_byte_str(msg, &var_header->topic_name);

	if (mqtt->fixed_header.publish.qos > 0) {
		/* Packet Id */
		nni_mqtt_msg_append_u16(msg, var_header->packet_id);
	}

	/* Payload */
	if (mqtt->payload.publish.payload.length > 0) {
		nni_msg_append(msg, mqtt->payload.publish.payload.buf,
		    mqtt->payload.publish.payload.length);
	}

	nni_mqtt_msg_encode_fixed_header(msg, mqtt);

	return MQTT_SUCCESS;
}

static int
nni_mqtt_msg_encode_puback(nni_msg *msg)
{
	nni_mqtt_proto_data *mqtt = nni_msg_get_proto_data(msg);
	nni_msg_clear(msg);

	int poslength = 2; /* for Packet Identifier */

	mqtt_puback_vhdr *var_header = &mqtt->var_header.puback;

	mqtt->fixed_header.remaining_length = poslength;

	/* Packet Identifier */
	nni_mqtt_msg_append_u16(msg, var_header->packet_id);

	nni_mqtt_msg_encode_fixed_header(msg, mqtt);

	return MQTT_SUCCESS;
}

static int
nni_mqtt_msg_encode_pubrec(nni_msg *msg)
{
	nni_mqtt_proto_data *mqtt = nni_msg_get_proto_data(msg);
	nni_msg_clear(msg);

	int poslength = 2; /* for Packet Identifier */

	mqtt_pubrec_vhdr *var_header = &mqtt->var_header.pubrec;

	mqtt->fixed_header.remaining_length = poslength;

	/* Packet Identifier */
	nni_mqtt_msg_append_u16(msg, var_header->packet_id);

	nni_mqtt_msg_encode_fixed_header(msg, mqtt);

	return MQTT_SUCCESS;
}

static int
nni_mqtt_msg_encode_pubrel(nni_msg *msg)
{
	nni_mqtt_proto_data *mqtt = nni_msg_get_proto_data(msg);
	nni_msg_clear(msg);

	int poslength = 2; /* for Packet Identifier */

	mqtt_pubrec_vhdr *var_header = &mqtt->var_header.pubrec;

	mqtt->fixed_header.common.bit_1     = 1;
	mqtt->fixed_header.remaining_length = poslength;

	/* Packet Identifier */
	nni_mqtt_msg_append_u16(msg, var_header->packet_id);

	nni_mqtt_msg_encode_fixed_header(msg, mqtt);

	return MQTT_SUCCESS;
}

static int
nni_mqtt_msg_encode_pubcomp(nni_msg *msg)
{
	nni_mqtt_proto_data *mqtt = nni_msg_get_proto_data(msg);
	nni_msg_clear(msg);

	int poslength = 2; /* for Packet Identifier */

	mqtt_pubcomp_vhdr *var_header = &mqtt->var_header.pubcomp;

	mqtt->fixed_header.remaining_length = poslength;

	/* Packet Identifier */
	nni_mqtt_msg_append_u16(msg, var_header->packet_id);

	nni_mqtt_msg_encode_fixed_header(msg, mqtt);

	return MQTT_SUCCESS;
}

static int
nni_mqtt_msg_encode_unsubscribe(nni_msg *msg)
{
	nni_mqtt_proto_data *mqtt = nni_msg_get_proto_data(msg);
	nni_msg_clear(msg);

	int poslength = 0;

	poslength += 2; /* for Packet Identifier */

	mqtt_unsubscribe_payload *uspld = &mqtt->payload.unsubscribe;

	/* Go through topic filters to calculate length information */
	for (size_t i = 0; i < uspld->topic_count; i++) {
		mqtt_buf *topic = &uspld->topic_arr[i];
		poslength += topic->length;
		poslength += 2; // for 'length' field of Topic Filter, which is
		                // encoded as UTF-8 encoded strings */
	}

	mqtt->fixed_header.remaining_length = poslength;
	mqtt->fixed_header.common.bit_1     = 1;

	mqtt_subscribe_vhdr *var_header = &mqtt->var_header.subscribe;
	/* Packet Id */
	nni_mqtt_msg_append_u16(msg, var_header->packet_id);

	/* Subscribe topic_arr */
	for (size_t i = 0; i < uspld->topic_count; i++) {
		mqtt_buf *topic = &uspld->topic_arr[i];
		nni_mqtt_msg_append_byte_str(msg, topic);
	}

	nni_mqtt_msg_encode_fixed_header(msg, mqtt);

	return MQTT_SUCCESS;
}

static int
nni_mqtt_msg_encode_unsuback(nni_msg *msg)
{
	nni_mqtt_proto_data *mqtt = nni_msg_get_proto_data(msg);
	nni_msg_clear(msg);

	int poslength = 2; /* for Packet Identifier */

	mqtt_unsuback_vhdr *var_header = &mqtt->var_header.unsuback;

	mqtt->fixed_header.remaining_length = poslength;

	/* Packet Identifier */
	nni_mqtt_msg_append_u16(msg, var_header->packet_id);

	nni_mqtt_msg_encode_fixed_header(msg, mqtt);
	return MQTT_SUCCESS;
}

static int
nni_mqtt_msg_encode_base(nni_msg *msg)
{
	nni_mqtt_proto_data *mqtt = nni_msg_get_proto_data(msg);
	nni_msg_clear(msg);

	mqtt->fixed_header.remaining_length = 0;

	nni_mqtt_msg_encode_fixed_header(msg, mqtt);

	return MQTT_SUCCESS;
}
