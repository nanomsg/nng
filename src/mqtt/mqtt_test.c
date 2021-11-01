#include <string.h>

#include "nng/nng.h"

#include "mqtt.h"
#include "nuts.h"

void
test_alloc(void)
{
	nng_msg *msg;
	NUTS_PASS(nng_mqtt_msg_alloc(&msg, 0));
	nng_msg_free(msg);
}

void
test_dup(void)
{
	nng_msg *msg;

	NUTS_PASS(nng_mqtt_msg_alloc(&msg, 0));

	nng_mqtt_msg_set_packet_type(msg, NNG_MQTT_SUBSCRIBE);
	NUTS_ASSERT(nng_mqtt_msg_get_packet_type(msg) == NNG_MQTT_SUBSCRIBE);

	nng_mqtt_topic_qos topic_qos[] = {
		{ .qos     = 0,
		    .topic = { .buf = (uint8_t *) "/nanomq/mqtt/msg/0",
		        .length     = strlen("/nanomq/mqtt/msg/0") } },
		{ .qos     = 1,
		    .topic = { .buf = (uint8_t *) "/nanomq/mqtt/msg/1",
		        .length     = strlen("/nanomq/mqtt/msg/1") } }
	};
	nng_mqtt_msg_set_subscribe_topics(
	    msg, topic_qos, sizeof(topic_qos) / sizeof(nng_mqtt_topic_qos));

	NUTS_PASS(nng_mqtt_msg_encode(msg));

	nng_msg *msg2;
	NUTS_PASS(nng_msg_dup(&msg2, msg));

	uint8_t print_buf[1024] = { 0 };
	nng_mqtt_msg_dump(msg, print_buf, 1024, true);
	printf("msg: \n%s\n", print_buf);

	nng_mqtt_msg_dump(msg2, print_buf, 1024, true);
	printf("msg2: \n%s\n", print_buf);

	nng_msg_free(msg);
	nng_msg_free(msg2);
}

void
test_encode_connect(void)
{
	nng_msg *msg;

	NUTS_PASS(nng_mqtt_msg_alloc(&msg, 0));

	nng_mqtt_msg_set_packet_type(msg, NNG_MQTT_CONNECT);
	NUTS_ASSERT(nng_mqtt_msg_get_packet_type(msg) == NNG_MQTT_CONNECT);

	// nng_mqtt_msg_set_connect_client_id(msg, "nanomq-mqtt");
	// NUTS_ASSERT(strcmp(nng_mqtt_msg_get_connect_client_id(msg),
	// "nanomq-mqtt") == 0);

	char will_topic[] = "/nanomq/will_msg";
	nng_mqtt_msg_set_connect_will_topic(msg, will_topic);

	char will_msg[] = "Bye-bye";
	nng_mqtt_msg_set_connect_will_msg(msg, will_msg);

	char user[]   = "alvin";
	char passwd[] = "HHH0000";

	nng_mqtt_msg_set_connect_user_name(msg, user);
	nng_mqtt_msg_set_connect_password(msg, passwd);
	nng_mqtt_msg_set_connect_clean_session(msg, true);
	nng_mqtt_msg_set_connect_keep_alive(msg, 60);

	NUTS_PASS(nng_mqtt_msg_encode(msg));

	nng_msg *dup_msg;
	nng_msg_dup(&dup_msg, msg);
	NUTS_PASS(nng_mqtt_msg_decode(dup_msg));

	uint8_t print_buf[1024] = { 0 };
	nng_mqtt_msg_dump(msg, print_buf, 1024, true);
	printf("msg:\n%s\n", print_buf);

	nng_mqtt_msg_dump(dup_msg, print_buf, 1024, true);
	printf("dup msg:\n%s\n", print_buf);

	nng_msg_free(msg);
	nng_msg_free(dup_msg);
}

void
test_encode_connack(void)
{
	nng_msg *msg;

	NUTS_PASS(nng_mqtt_msg_alloc(&msg, 0));

	nng_mqtt_msg_set_packet_type(msg, NNG_MQTT_CONNACK);
	NUTS_ASSERT(nng_mqtt_msg_get_packet_type(msg) == NNG_MQTT_CONNACK);

	nng_mqtt_msg_set_conack_flags(msg, 1);

	nng_mqtt_msg_set_conack_return_code(msg, 0);

	NUTS_PASS(nng_mqtt_msg_encode(msg));

	uint8_t print_buf[1024] = { 0 };
	nng_mqtt_msg_dump(msg, print_buf, 1024, true);
	printf("%s\n", print_buf);
	nng_msg_free(msg);
}

void
test_encode_publish(void)
{
	nng_msg *msg;

	NUTS_PASS(nng_mqtt_msg_alloc(&msg, 0));

	nng_mqtt_msg_set_packet_type(msg, NNG_MQTT_PUBLISH);
	NUTS_ASSERT(nng_mqtt_msg_get_packet_type(msg) == NNG_MQTT_PUBLISH);

	nng_mqtt_msg_set_publish_qos(msg, 2);
	nng_mqtt_msg_set_publish_retain(msg, true);

	char *topic = "/nanomq/msg/18234";
	nng_mqtt_msg_set_publish_topic(msg, topic);

	char *payload = "hello";
	nng_mqtt_msg_set_publish_payload(
	    msg, (uint8_t *) payload, strlen(payload));

	NUTS_PASS(nng_mqtt_msg_encode(msg));

	uint8_t print_buf[1024] = { 0 };
	nng_mqtt_msg_dump(msg, print_buf, 1024, true);
	printf("%s\n", print_buf);
	nng_msg_free(msg);
}

void
test_encode_puback(void)
{
	nng_msg *msg;

	NUTS_PASS(nng_mqtt_msg_alloc(&msg, 0));

	nng_mqtt_msg_set_packet_type(msg, NNG_MQTT_PUBACK);
	NUTS_ASSERT(nng_mqtt_msg_get_packet_type(msg) == NNG_MQTT_PUBACK);

	NUTS_PASS(nng_mqtt_msg_encode(msg));

	uint8_t print_buf[1024] = { 0 };
	nng_mqtt_msg_dump(msg, print_buf, 1024, true);
	printf("%s\n", print_buf);
	nng_msg_free(msg);
}

void
test_encode_subscribe(void)
{
	nng_msg *msg;

	NUTS_PASS(nng_mqtt_msg_alloc(&msg, 0));

	nng_mqtt_msg_set_packet_type(msg, NNG_MQTT_SUBSCRIBE);
	NUTS_ASSERT(nng_mqtt_msg_get_packet_type(msg) == NNG_MQTT_SUBSCRIBE);

	nng_mqtt_topic_qos topic_qos[] = {
		{ .qos     = 0,
		    .topic = { .buf = (uint8_t *) "/nanomq/mqtt/msg/0",
		        .length     = strlen("/nanomq/mqtt/msg/0") } },
		{ .qos     = 1,
		    .topic = { .buf = (uint8_t *) "/nanomq/mqtt/msg/1",
		        .length     = strlen("/nanomq/mqtt/msg/1") } }
	};

	nng_mqtt_msg_set_subscribe_topics(
	    msg, topic_qos, sizeof(topic_qos) / sizeof(nng_mqtt_topic_qos));

	NUTS_PASS(nng_mqtt_msg_encode(msg));

	uint8_t print_buf[1024] = { 0 };
	nng_mqtt_msg_dump(msg, print_buf, 1024, true);

	printf("%s\n", print_buf);
	nng_msg_free(msg);
}

void
test_encode_suback(void)
{
	nng_msg *msg;

	NUTS_PASS(nng_mqtt_msg_alloc(&msg, 0));

	nng_mqtt_msg_set_packet_type(msg, NNG_MQTT_SUBACK);
	NUTS_ASSERT(nng_mqtt_msg_get_packet_type(msg) == NNG_MQTT_SUBACK);

	uint8_t ret_codes[] = { 0, 1, 2, 3 };

	nng_mqtt_msg_set_suback_return_codes(
	    msg, ret_codes, sizeof(ret_codes) / sizeof(uint8_t));

	NUTS_PASS(nng_mqtt_msg_encode(msg));

	uint8_t print_buf[1024] = { 0 };
	nng_mqtt_msg_dump(msg, print_buf, 1024, true);
	printf("%s\n", print_buf);
	nng_msg_free(msg);
}

void
test_encode_unsubscribe(void)
{
	nng_msg *msg;

	NUTS_PASS(nng_mqtt_msg_alloc(&msg, 0));

	nng_mqtt_msg_set_packet_type(msg, NNG_MQTT_UNSUBSCRIBE);
	NUTS_ASSERT(nng_mqtt_msg_get_packet_type(msg) == NNG_MQTT_UNSUBSCRIBE);

	nng_mqtt_topic topic_qos[] = {
		{ .buf      = (uint8_t *) "/nanomq/mqtt/1",
		    .length = strlen("/nanomq/mqtt/1") },
		{ .buf      = (uint8_t *) "/nanomq/mqtt/2",
		    .length = strlen("/nanomq/mqtt/2") },
	};

	nng_mqtt_msg_set_unsubscribe_topics(
	    msg, topic_qos, sizeof(topic_qos) / sizeof(nng_mqtt_topic));
	NUTS_PASS(nng_mqtt_msg_encode(msg));

	uint8_t print_buf[1024] = { 0 };
	nng_mqtt_msg_dump(msg, print_buf, 1024, true);

	printf("%s\n", print_buf);
	nng_msg_free(msg);
}

void
test_encode_disconnect(void)
{
	nng_msg *msg;

	NUTS_PASS(nng_mqtt_msg_alloc(&msg, 0));

	nng_mqtt_msg_set_packet_type(msg, NNG_MQTT_UNSUBSCRIBE);
	NUTS_ASSERT(nng_mqtt_msg_get_packet_type(msg) == NNG_MQTT_UNSUBSCRIBE);
	NUTS_PASS(nng_mqtt_msg_encode(msg));

	uint8_t print_buf[1024] = { 0 };
	nng_mqtt_msg_dump(msg, print_buf, 1024, true);
	printf("%s\n", print_buf);

	nng_msg_free(msg);
}

void
test_decode_connect(void)
{
	nng_msg *msg;
	uint8_t  connect[] = {

		0x10, 0x3f, 0x00, 0x04, 0x4d, 0x51, 0x54, 0x54, 0x04, 0xc6,
		0x00, 0x3c, 0x00, 0x0c, 0x54, 0x65, 0x73, 0x74, 0x2d, 0x43,
		0x6c, 0x69, 0x65, 0x6e, 0x74, 0x31, 0x00, 0x0a, 0x77, 0x69,
		0x6c, 0x6c, 0x5f, 0x74, 0x6f, 0x70, 0x69, 0x63, 0x00, 0x07,
		0x62, 0x79, 0x65, 0x2d, 0x62, 0x79, 0x65, 0x00, 0x05, 0x61,
		0x6c, 0x76, 0x69, 0x6e, 0x00, 0x09, 0x48, 0x48, 0x48, 0x31,
		0x32, 0x33, 0x34, 0x35, 0x36
	};

	size_t sz = sizeof(connect) / sizeof(uint8_t);

	NUTS_PASS(nng_mqtt_msg_alloc(&msg, sz - 2));

	nng_msg_header_append(msg, connect, 2);

	memcpy(nng_msg_body(msg), connect + 2, sz - 2);

	NUTS_PASS(nng_mqtt_msg_decode(msg));

	uint8_t print_buf[1024] = { 0 };
	nng_mqtt_msg_dump(msg, print_buf, 1024, true);
	printf("%s\n", print_buf);
	nng_msg_free(msg);
}

void
test_decode_publish(void)
{
	nng_msg *msg;

	uint8_t publish[] = { 0x34, 0xba, 0x03, 0x00, 0x10, 0x2f, 0x6e, 0x61,
		0x6e, 0x6f, 0x6d, 0x71, 0x2f, 0x6d, 0x71, 0x74, 0x74, 0x2f,
		0x6d, 0x73, 0x67, 0x03, 0x6c, 0x7b, 0x22, 0x62, 0x72, 0x6f,
		0x6b, 0x65, 0x72, 0x22, 0x20, 0x3a, 0x20, 0x22, 0x2f, 0x6e,
		0x61, 0x6e, 0x6f, 0x6d, 0x71, 0x22, 0x2c, 0x22, 0x73, 0x64,
		0x6b, 0x22, 0x20, 0x3a, 0x20, 0x22, 0x6d, 0x71, 0x74, 0x74,
		0x2d, 0x63, 0x6f, 0x64, 0x65, 0x63, 0x22, 0x2c, 0x22, 0x64,
		0x61, 0x74, 0x61, 0x22, 0x20, 0x3a, 0x20, 0x22, 0x31, 0x39,
		0x33, 0x37, 0x38, 0x38, 0x39, 0x37, 0x36, 0x38, 0x39, 0x31,
		0x39, 0x33, 0x37, 0x39, 0x38, 0x37, 0x35, 0x38, 0x39, 0x37,
		0x33, 0x39, 0x31, 0x38, 0x37, 0x38, 0x39, 0x33, 0x37, 0x39,
		0x38, 0x35, 0x36, 0x37, 0x39, 0x38, 0x37, 0x31, 0x38, 0x39,
		0x37, 0x39, 0x34, 0x38, 0x37, 0x36, 0x39, 0x37, 0x39, 0x38,
		0x34, 0x37, 0x39, 0x38, 0x32, 0x37, 0x38, 0x39, 0x34, 0x37,
		0x38, 0x39, 0x36, 0x37, 0x34, 0x38, 0x33, 0x37, 0x32, 0x39,
		0x37, 0x39, 0x37, 0x34, 0x39, 0x37, 0x39, 0x32, 0x36, 0x37,
		0x39, 0x38, 0x33, 0x34, 0x32, 0x37, 0x39, 0x38, 0x34, 0x37,
		0x39, 0x38, 0x36, 0x37, 0x39, 0x38, 0x32, 0x37, 0x34, 0x39,
		0x38, 0x37, 0x36, 0x38, 0x39, 0x32, 0x37, 0x33, 0x34, 0x38,
		0x39, 0x37, 0x36, 0x32, 0x37, 0x39, 0x34, 0x37, 0x36, 0x37,
		0x32, 0x39, 0x38, 0x37, 0x41, 0x45, 0x46, 0x45, 0x46, 0x41,
		0x45, 0x46, 0x44, 0x43, 0x42, 0x46, 0x45, 0x41, 0x4b, 0x4a,
		0x53, 0x48, 0x46, 0x4b, 0x4a, 0x48, 0x53, 0x4a, 0x4b, 0x46,
		0x48, 0x4b, 0x4a, 0x53, 0x48, 0x4c, 0x4b, 0x4a, 0x4b, 0x55,
		0x49, 0x59, 0x49, 0x55, 0x45, 0x54, 0x49, 0x55, 0x51, 0x57,
		0x4f, 0x49, 0x51, 0x4f, 0x3c, 0x4d, 0x5a, 0x4e, 0x3c, 0x4d,
		0x42, 0x4a, 0x48, 0x47, 0x48, 0x4a, 0x46, 0x48, 0x47, 0x4c,
		0x4b, 0x4a, 0x48, 0x47, 0x46, 0x44, 0x53, 0x41, 0x51, 0x57,
		0x45, 0x52, 0x54, 0x59, 0x55, 0x49, 0x4f, 0x50, 0x5a, 0x58,
		0x43, 0x56, 0x42, 0x4e, 0x4d, 0x39, 0x38, 0x38, 0x32, 0x34,
		0x37, 0x35, 0x39, 0x32, 0x38, 0x37, 0x38, 0x39, 0x37, 0x35,
		0x34, 0x39, 0x38, 0x32, 0x37, 0x39, 0x38, 0x35, 0x37, 0x61,
		0x64, 0x41, 0x53, 0x44, 0x46, 0x47, 0x48, 0x4a, 0x46, 0x47,
		0x48, 0x4a, 0x46, 0x47, 0x48, 0x4a, 0x47, 0x48, 0x4a, 0x47,
		0x48, 0x4a, 0x46, 0x47, 0x48, 0x47, 0x48, 0x4a, 0x47, 0x48,
		0x47, 0x48, 0x4a, 0x44, 0x46, 0x31, 0x39, 0x33, 0x37, 0x38,
		0x38, 0x39, 0x37, 0x36, 0x38, 0x39, 0x31, 0x39, 0x33, 0x37,
		0x39, 0x38, 0x37, 0x35, 0x38, 0x39, 0x37, 0x33, 0x39, 0x31,
		0x38, 0x37, 0x38, 0x39, 0x33, 0x37, 0x39, 0x38, 0x35, 0x36,
		0x37, 0x39, 0x38, 0x37, 0x31, 0x38, 0x39, 0x37, 0x39, 0x34,
		0x38, 0x37, 0x36, 0x39, 0x37, 0x39, 0x38, 0x34, 0x37, 0x39,
		0x38, 0x32, 0x37, 0x38, 0x39, 0x64, 0x6a, 0x61, 0x6b, 0x68,
		0x6b, 0x6a, 0x68, 0x65, 0x71, 0x69, 0x75, 0x79, 0x69, 0x65,
		0x75, 0x79, 0x69, 0x75, 0x74, 0x79, 0x69, 0x75, 0x71, 0x79,
		0x69, 0x75, 0x79, 0x69, 0x75, 0x22, 0x7d };

	size_t sz = sizeof(publish) / sizeof(uint8_t);
	nng_mqtt_msg_alloc(&msg, sz - 3);

	nng_msg_header_append(msg, publish, 3);
	memcpy(nng_msg_body(msg), publish + 3, sz - 3);

	NUTS_PASS(nng_mqtt_msg_decode(msg));

	uint8_t print_buf[2048] = { 0 };
	nng_mqtt_msg_dump(msg, print_buf, 2048, true);
	printf("%s\n", print_buf);

	nng_msg_free(msg);
}

void
test_decode_puback(void)
{
	nng_msg *msg;

	uint8_t puback[] = { 0x40, 0x02, 0x01, 0x20 };
	size_t  sz       = sizeof(puback) / sizeof(uint8_t);
	nng_mqtt_msg_alloc(&msg, 0);

	nng_msg_header_append(msg, puback, sz - 2);

	nng_msg_append(msg, puback + 2, sz - 2);

	NUTS_PASS(nng_mqtt_msg_decode(msg));

	uint8_t print_buf[1024] = { 0 };
	nng_mqtt_msg_dump(msg, print_buf, 1024, true);
	printf("%s\n", print_buf);
	nng_msg_free(msg);
}

void
test_decode_subscribe(void)
{
	nng_msg *msg;

	uint8_t subscribe[] = { 0x82, 0x2c, 0x02, 0x10, 0x00, 0x12, 0x2f, 0x6e,
		0x61, 0x6e, 0x6f, 0x6d, 0x71, 0x2f, 0x6d, 0x71, 0x74, 0x74,
		0x2f, 0x6d, 0x73, 0x67, 0x2f, 0x30, 0x00, 0x00, 0x12, 0x2f,
		0x6e, 0x61, 0x6e, 0x6f, 0x6d, 0x71, 0x2f, 0x6d, 0x71, 0x74,
		0x74, 0x2f, 0x6d, 0x73, 0x67, 0x2f, 0x31, 0x01 };

	size_t sz = sizeof(subscribe) / sizeof(uint8_t);
	nng_mqtt_msg_alloc(&msg, 0);

	nng_msg_header_append(msg, subscribe, sz - 2);

	nng_msg_append(msg, subscribe + 2, sz - 2);

	NUTS_PASS(nng_mqtt_msg_decode(msg));

	uint8_t print_buf[1024] = { 0 };
	nng_mqtt_msg_dump(msg, print_buf, 1024, true);
	printf("%s\n", print_buf);

	uint32_t            count;
	nng_mqtt_topic_qos *tq =
	    nng_mqtt_msg_get_subscribe_topics(msg, &count);

	nng_free(tq, count);

	nng_msg_free(msg);
}

void
test_decode_unsubscribe(void)
{
	nng_msg *msg;

	uint8_t unsubscribe[] = { 0xa2, 0x22, 0x01, 0x10, 0x00, 0x0e, 0x2f,
		0x6e, 0x61, 0x6e, 0x6f, 0x6d, 0x71, 0x2f, 0x6d, 0x71, 0x74,
		0x74, 0x2f, 0x31, 0x00, 0x0e, 0x2f, 0x6e, 0x61, 0x6e, 0x6f,
		0x6d, 0x71, 0x2f, 0x6d, 0x71, 0x74, 0x74, 0x2f, 0x32 };

	size_t sz = sizeof(unsubscribe) / sizeof(uint8_t);
	nng_mqtt_msg_alloc(&msg, 0);

	nng_msg_header_append(msg, unsubscribe, sz - 2);
	nng_msg_append(msg, unsubscribe + 2, sz - 2);

	NUTS_PASS(nng_mqtt_msg_decode(msg));

	uint8_t print_buf[1024] = { 0 };
	nng_mqtt_msg_dump(msg, print_buf, 1024, true);
	printf("%s\n", print_buf);

	nng_msg_free(msg);
}

void
test_decode_disconnect(void)
{
	nng_msg *msg;
	uint8_t  disconnect[] = { 0xe0, 0x00 };

	size_t sz = sizeof(disconnect) / sizeof(uint8_t);
	nng_mqtt_msg_alloc(&msg, 0);

	nng_msg_header_append(msg, disconnect, sz);

	NUTS_PASS(nng_mqtt_msg_decode(msg));

	uint8_t print_buf[1024] = { 0 };
	nng_mqtt_msg_dump(msg, print_buf, 1024, true);
	printf("%s\n", print_buf);
	nng_msg_free(msg);
}

TEST_LIST = {
	{ "alloc message", test_alloc },
	{ "dup message", test_dup },
	{ "encode connect", test_encode_connect },
	{ "encode conack", test_encode_connack },
	{ "encode publish", test_encode_publish },
	{ "encode puback", test_encode_puback },
	{ "encode disconnect", test_encode_disconnect },
	{ "encode subscribe", test_encode_subscribe },
	{ "encode suback", test_encode_suback },
	{ "encode unsubscribe", test_encode_unsubscribe },
	{ "decode connect", test_decode_connect },
	{ "decode subscribe", test_decode_subscribe },
	{ "decode unsubscribe", test_decode_unsubscribe },
	{ "decode disconnect", test_decode_disconnect },
	{ "decode publish", test_decode_publish },
	{ "decode puback", test_decode_puback },
	{ NULL, NULL },
};
