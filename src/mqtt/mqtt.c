#include "mqtt.h"
#include <stdlib.h>
#include <string.h>

static int nni_mqtt_msg_free(void *);
static int nni_mqtt_msg_dup(void **, const void *);

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
nni_mqtt_msg_set_packet_id(nni_msg *msg, uint16_t packet_id)
{
	nni_mqtt_proto_data *proto_data = nni_msg_get_proto_data(msg);
	switch (proto_data->fixed_header.common.packet_type) {
	case NNG_MQTT_PUBACK:
		proto_data->var_header.puback.packet_id = packet_id;
		break;
	case NNG_MQTT_PUBCOMP:
		proto_data->var_header.pubcomp.packet_id = packet_id;
		break;
	case NNG_MQTT_PUBREC:
		proto_data->var_header.pubrec.packet_id = packet_id;
		break;
	case NNG_MQTT_PUBREL:
		proto_data->var_header.pubrel.packet_id = packet_id;
		break;
	case NNG_MQTT_PUBLISH:
		proto_data->var_header.publish.packet_id = packet_id;
		break;
	case NNG_MQTT_SUBACK:
		proto_data->var_header.suback.packet_id = packet_id;
		break;
	case NNG_MQTT_SUBSCRIBE:
		proto_data->var_header.subscribe.packet_id = packet_id;
		break;
	default:
		// logic error
		NNI_ASSERT(false);
	}
}

uint16_t
nni_mqtt_msg_get_packet_id(nni_msg *msg)
{
	nni_mqtt_proto_data *proto_data = nni_msg_get_proto_data(msg);
	switch (proto_data->fixed_header.common.packet_type) {
	case NNG_MQTT_PUBACK:
		return proto_data->var_header.puback.packet_id;
	case NNG_MQTT_PUBCOMP:
		return proto_data->var_header.pubcomp.packet_id;
	case NNG_MQTT_PUBREC:
		return proto_data->var_header.pubrec.packet_id;
	case NNG_MQTT_PUBREL:
		return proto_data->var_header.pubrel.packet_id;
	case NNG_MQTT_PUBLISH:
		return proto_data->var_header.publish.packet_id;
	case NNG_MQTT_SUBACK:
		return proto_data->var_header.suback.packet_id;
	case NNG_MQTT_SUBSCRIBE:
		return proto_data->var_header.subscribe.packet_id;
	default:
		// logic error
		NNI_ASSERT(false);
	}
	return 0;
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

	mqtt_buf mqbuf = { .buf = buffer, .length = len };

	nni_msg *mqtt_data;

	nni_msg_dup(&mqtt_data, msg);
	nni_msg_insert(
	    mqtt_data, nni_msg_header(msg), nni_msg_header_len(msg));

	mqtt_buf body = { .buf = nni_msg_body(mqtt_data),
		.length        = nni_msg_len(mqtt_data) };

	mqtt_msg_dump(proto_data, &mqbuf, &body, print_bytes);

	nni_msg_free(mqtt_data);
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
