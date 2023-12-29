#include "mqtt_msg.h"

int
nng_mqtt_msg_proto_data_alloc(nng_msg *msg)
{
	return nni_mqtt_msg_proto_data_alloc(msg);
}

void
nng_mqtt_msg_proto_data_free(nng_msg *msg)
{
	nni_mqtt_msg_proto_data_free(msg);
}

int
nng_mqtt_msg_alloc(nng_msg **msg, size_t sz)
{
	return nni_mqtt_msg_alloc(msg, sz);
}

int
nng_mqtt_msg_encode(nng_msg *msg)
{
	return nni_mqtt_msg_encode(msg);
}

int
nng_mqtt_msg_decode(nng_msg *msg)
{
	return nni_mqtt_msg_decode(msg);
}

void
nng_mqtt_msg_set_packet_type(nng_msg *msg, nng_mqtt_packet_type packet_type)
{
	nni_mqtt_msg_set_packet_type(msg, (nni_mqtt_packet_type) packet_type);
}

nng_mqtt_packet_type
nng_mqtt_msg_get_packet_type(nng_msg *msg)
{
	return (nng_mqtt_packet_type) nni_mqtt_msg_get_packet_type(msg);
}

void
nng_mqtt_msg_set_connect_clean_session(nng_msg *msg, bool clean_session)
{
	nni_mqtt_msg_set_connect_clean_session(msg, clean_session);
}

void
nng_mqtt_msg_set_connect_will_retain(nng_msg *msg, bool will_retain)
{
	nni_mqtt_msg_set_connect_will_retain(msg, will_retain);
}

void
nng_mqtt_msg_set_connect_will_qos(nng_msg *msg, uint8_t will_qos)
{
	nni_mqtt_msg_set_connect_will_qos(msg, will_qos);
}

bool
nng_mqtt_msg_get_connect_clean_session(nng_msg *msg)
{
	return nni_mqtt_msg_get_connect_clean_session(msg);
}

bool
nng_mqtt_msg_get_connect_will_retain(nng_msg *msg)
{
	return nni_mqtt_msg_get_connect_will_retain(msg);
}

uint8_t
nng_mqtt_msg_get_connect_will_qos(nng_msg *msg)
{
	return nni_mqtt_msg_get_connect_will_qos(msg);
}

void
nng_mqtt_msg_set_connect_proto_version(nng_msg *msg, uint8_t proto_version)
{
	nni_mqtt_msg_set_connect_proto_version(msg, proto_version);
}

void
nng_mqtt_msg_set_connect_keep_alive(nng_msg *msg, uint16_t keep_alive)
{
	nni_mqtt_msg_set_connect_keep_alive(msg, keep_alive);
}

void
nng_mqtt_msg_set_connect_client_id(nng_msg *msg, const char *client_id)
{
	nni_mqtt_msg_set_connect_client_id(msg, client_id);
}

void
nng_mqtt_msg_set_connect_will_topic(nng_msg *msg, const char *will_topic)
{
	nni_mqtt_msg_set_connect_will_topic(msg, will_topic);
}

void
nng_mqtt_msg_set_connect_will_msg(
    nng_msg *msg, uint8_t *will_msg, uint32_t len)
{
	nni_mqtt_msg_set_connect_will_msg(msg, will_msg, len);
}

void
nng_mqtt_msg_set_connect_user_name(nng_msg *msg, const char *user_name)
{
	nni_mqtt_msg_set_connect_user_name(msg, user_name);
}
void
nng_mqtt_msg_set_connect_password(nng_msg *msg, const char *password)
{
	nni_mqtt_msg_set_connect_password(msg, password);
}

uint8_t
nng_mqtt_msg_get_connect_proto_version(nng_msg *msg)
{
	return nni_mqtt_msg_get_connect_proto_version(msg);
}

uint16_t
nng_mqtt_msg_get_connect_keep_alive(nng_msg *msg)
{
	return nni_mqtt_msg_get_connect_keep_alive(msg);
}

const char *
nng_mqtt_msg_get_connect_client_id(nng_msg *msg)
{
	return nni_mqtt_msg_get_connect_client_id(msg);
}

const char *
nng_mqtt_msg_get_connect_will_topic(nng_msg *msg)
{
	return nni_mqtt_msg_get_connect_will_topic(msg);
}

uint8_t *
nng_mqtt_msg_get_connect_will_msg(nng_msg *msg, uint32_t *len)
{
	return nni_mqtt_msg_get_connect_will_msg(msg, len);
}

const char *
nng_mqtt_msg_get_connect_user_name(nng_msg *msg)
{
	return nni_mqtt_msg_get_connect_user_name(msg);
}

const char *
nng_mqtt_msg_get_connect_password(nng_msg *msg)
{
	return nni_mqtt_msg_get_connect_password(msg);
}

void
nng_mqtt_msg_set_connack_return_code(nng_msg *msg, uint8_t return_code)
{
	nni_mqtt_msg_set_connack_return_code(msg, return_code);
}

void
nng_mqtt_msg_set_connack_flags(nng_msg *msg, uint8_t flags)
{
	nni_mqtt_msg_set_connack_flags(msg, flags);
}

uint8_t
nng_mqtt_msg_get_connack_return_code(nng_msg *msg)
{
	return nni_mqtt_msg_get_connack_return_code(msg);
}

uint8_t
nng_mqtt_msg_get_connack_flags(nng_msg *msg)
{
	return nni_mqtt_msg_get_connack_flags(msg);
}

void
nng_mqtt_msg_set_publish_qos(nng_msg *msg, uint8_t qos)
{
	nni_mqtt_msg_set_publish_qos(msg, qos);
}

uint8_t
nng_mqtt_msg_get_publish_qos(nng_msg *msg)
{
	return nni_mqtt_msg_get_publish_qos(msg);
}

void
nng_mqtt_msg_set_publish_retain(nng_msg *msg, bool retain)
{
	nni_mqtt_msg_set_publish_retain(msg, retain);
}

bool
nng_mqtt_msg_get_publish_retain(nng_msg *msg)
{
	return nni_mqtt_msg_get_publish_retain(msg);
}

void
nng_mqtt_msg_set_publish_dup(nng_msg *msg, bool dup)
{
	nni_mqtt_msg_set_publish_dup(msg, dup);
}

bool
nng_mqtt_msg_get_publish_dup(nng_msg *msg)
{
	return nni_mqtt_msg_get_publish_dup(msg);
}

void
nng_mqtt_msg_set_publish_topic(nng_msg *msg, const char *topic)
{
	nni_mqtt_msg_set_publish_topic(msg, topic);
}

const char *
nng_mqtt_msg_get_publish_topic(nng_msg *msg, uint32_t *topic_len)
{
	return nni_mqtt_msg_get_publish_topic(msg, topic_len);
}

void
nng_mqtt_msg_set_publish_packet_id(nng_msg *msg, uint16_t packet_id)
{
	nni_mqtt_msg_set_publish_packet_id(msg, packet_id);
}

uint16_t
nng_mqtt_msg_get_publish_packet_id(nng_msg *msg)
{
	return nni_mqtt_msg_get_publish_packet_id(msg);
}

void
nng_mqtt_msg_set_publish_payload(nng_msg *msg, uint8_t *payload, uint32_t len)
{
	nni_mqtt_msg_set_publish_payload(msg, payload, len);
}

uint8_t *
nng_mqtt_msg_get_publish_payload(nng_msg *msg, uint32_t *len)
{
	return nni_mqtt_msg_get_publish_payload(msg, len);
}

uint16_t
nng_mqtt_msg_get_puback_packet_id(nng_msg *msg)
{
	return nni_mqtt_msg_get_puback_packet_id(msg);
}

void
nng_mqtt_msg_set_puback_packet_id(nng_msg *msg, uint16_t packet_id)
{
	nni_mqtt_msg_set_puback_packet_id(msg, packet_id);
}

uint16_t
nng_mqtt_msg_get_pubrec_packet_id(nng_msg *msg)
{
	return nni_mqtt_msg_get_pubrec_packet_id(msg);
}

void
nng_mqtt_msg_set_pubrec_packet_id(nng_msg *msg, uint16_t packet_id)
{
	nni_mqtt_msg_set_pubrec_packet_id(msg, packet_id);
}

uint16_t
nng_mqtt_msg_get_pubrel_packet_id(nng_msg *msg)
{
	return nni_mqtt_msg_get_pubrel_packet_id(msg);
}

void
nng_mqtt_msg_set_pubrel_packet_id(nng_msg *msg, uint16_t packet_id)
{
	nni_mqtt_msg_set_pubrel_packet_id(msg, packet_id);
}

uint16_t
nng_mqtt_msg_get_pubcomp_packet_id(nng_msg *msg)
{
	return nni_mqtt_msg_get_pubcomp_packet_id(msg);
}

void
nng_mqtt_msg_set_pubcomp_packet_id(nng_msg *msg, uint16_t packet_id)
{
	nni_mqtt_msg_set_pubcomp_packet_id(msg, packet_id);
}

uint16_t
nng_mqtt_msg_get_subscribe_packet_id(nng_msg *msg)
{
	return nni_mqtt_msg_get_subscribe_packet_id(msg);
}

void
nng_mqtt_msg_set_subscribe_packet_id(nng_msg *msg, uint16_t packet_id)
{
	nni_mqtt_msg_set_subscribe_packet_id(msg, packet_id);
}

void
nng_mqtt_msg_set_subscribe_topics(
    nng_msg *msg, nng_mqtt_topic_qos *topics, uint32_t topics_count)
{
	nni_mqtt_msg_set_subscribe_topics(
	    msg, (nni_mqtt_topic_qos *) topics, topics_count);
}

nng_mqtt_topic_qos *
nng_mqtt_msg_get_subscribe_topics(nng_msg *msg, uint32_t *topics_count)
{
	return nni_mqtt_msg_get_subscribe_topics(msg, topics_count);
}

uint16_t
nng_mqtt_msg_get_suback_packet_id(nng_msg *msg)
{
	return nni_mqtt_msg_get_suback_packet_id(msg);
}

void
nng_mqtt_msg_set_suback_packet_id(nng_msg *msg, uint16_t packet_id)
{
	nni_mqtt_msg_set_suback_packet_id(msg, packet_id);
}
void
nng_mqtt_msg_set_suback_return_codes(
    nng_msg *msg, uint8_t *return_codes, uint32_t return_codes_count)
{
	nni_mqtt_msg_set_suback_return_codes(
	    msg, return_codes, return_codes_count);
}
uint8_t *
nng_mqtt_msg_get_suback_return_codes(
    nng_msg *msg, uint32_t *return_codes_counts)
{
	return nni_mqtt_msg_get_suback_return_codes(msg, return_codes_counts);
}

uint16_t
nng_mqtt_msg_get_unsubscribe_packet_id(nng_msg *msg)
{
	return nni_mqtt_msg_get_unsubscribe_packet_id(msg);
}

void
nng_mqtt_msg_set_unsubscribe_packet_id(nng_msg *msg, uint16_t packet_id)
{

	nni_mqtt_msg_set_unsubscribe_packet_id(msg, packet_id);
}

void
nng_mqtt_msg_set_unsubscribe_topics(
    nng_msg *msg, nng_mqtt_topic *topics, uint32_t topics_count)
{
	nni_mqtt_msg_set_unsubscribe_topics(
	    msg, (nni_mqtt_topic *) topics, topics_count);
}

nng_mqtt_topic *
nng_mqtt_msg_get_unsubscribe_topics(nng_msg *msg, uint32_t *topics_count)
{
	return nni_mqtt_msg_get_unsubscribe_topics(msg, topics_count);
}

void
nng_mqtt_msg_set_unsuback_packet_id(nng_msg *msg, uint16_t packet_id)
{
	nni_mqtt_msg_set_unsuback_packet_id(msg, packet_id);
}

uint16_t
nng_mqtt_msg_get_unsuback_packet_id(nng_msg *msg)
{
	return nni_mqtt_msg_get_unsuback_packet_id(msg);
}

nng_mqtt_topic *
nng_mqtt_topic_array_create(size_t n)
{
	return nni_mqtt_topic_array_create(n);
}

void
nng_mqtt_topic_array_set(
    nng_mqtt_topic *topic, size_t n, const char *topic_name)
{
	nni_mqtt_topic_array_set(topic, n, topic_name);
}

void
nng_mqtt_topic_array_free(nng_mqtt_topic *topic, size_t n)
{
	nni_mqtt_topic_array_free(topic, n);
}

nng_mqtt_topic_qos *
nng_mqtt_topic_qos_array_create(size_t n)
{
	return nni_mqtt_topic_qos_array_create(n);
}

void
nng_mqtt_topic_qos_array_set(nng_mqtt_topic_qos *topic_qos, size_t index,
    const char *topic_name, uint8_t qos)
{
	nni_mqtt_topic_qos_array_set(topic_qos, index, topic_name, qos);
}

void
nng_mqtt_topic_qos_array_free(nng_mqtt_topic_qos *topic_qos, size_t n)
{
	nni_mqtt_topic_qos_array_free(topic_qos, n);
}

int
nng_mqtt_set_connect_cb(nng_socket sock, nng_pipe_cb cb, void *arg)
{
	return nng_pipe_notify(sock, NNG_PIPE_EV_ADD_POST, cb, arg);
}

int
nng_mqtt_set_disconnect_cb(nng_socket sock, nng_pipe_cb cb, void *arg)
{
	return nng_pipe_notify(sock, NNG_PIPE_EV_REM_POST, cb, arg);
}

void
nng_mqtt_msg_dump(
    nng_msg *msg, uint8_t *buffer, uint32_t len, bool print_bytes)
{
	nni_mqtt_msg_dump(msg, buffer, len, print_bytes);
}
