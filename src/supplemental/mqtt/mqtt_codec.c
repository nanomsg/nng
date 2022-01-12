
#include "mqtt_msg.h"

#include <stdio.h>
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

static int nni_mqtt_msg_decode_fixed_header(nni_msg *);
static int nni_mqtt_msg_decode_connect(nni_msg *);
static int nni_mqtt_msg_decode_connack(nni_msg *);
static int nni_mqtt_msg_decode_subscribe(nni_msg *);
static int nni_mqtt_msg_decode_suback(nni_msg *);
static int nni_mqtt_msg_decode_publish(nni_msg *);
static int nni_mqtt_msg_decode_puback(nni_msg *);
static int nni_mqtt_msg_decode_pubrec(nni_msg *);
static int nni_mqtt_msg_decode_pubrel(nni_msg *);
static int nni_mqtt_msg_decode_pubcomp(nni_msg *);
static int nni_mqtt_msg_decode_unsubscribe(nni_msg *);
static int nni_mqtt_msg_decode_unsuback(nni_msg *);
static int nni_mqtt_msg_decode_base(nni_msg *);

static void destory_connect(nni_mqtt_proto_data *);
static void destory_publish(nni_mqtt_proto_data *);
static void destory_subscribe(nni_mqtt_proto_data *);
static void destory_suback(nni_mqtt_proto_data *);
static void destory_unsubscribe(nni_mqtt_proto_data *);

static void dup_connect(nni_mqtt_proto_data *, nni_mqtt_proto_data *);
static void dup_publish(nni_mqtt_proto_data *, nni_mqtt_proto_data *);
static void dup_subscribe(nni_mqtt_proto_data *, nni_mqtt_proto_data *);
static void dup_suback(nni_mqtt_proto_data *, nni_mqtt_proto_data *);
static void dup_unsubscribe(nni_mqtt_proto_data *, nni_mqtt_proto_data *);

static void mqtt_msg_content_free(nni_mqtt_proto_data *);

typedef struct {
	nni_mqtt_packet_type packet_type;
	int (*encode)(nni_msg *);
	int (*decode)(nni_msg *);
} mqtt_msg_codec_handler;

static mqtt_msg_codec_handler codec_handler[] = {
	{ NNG_MQTT_CONNECT, nni_mqtt_msg_encode_connect,
	    nni_mqtt_msg_decode_connect },
	{ NNG_MQTT_CONNACK, nni_mqtt_msg_encode_connack,
	    nni_mqtt_msg_decode_connack },
	{ NNG_MQTT_PUBLISH, nni_mqtt_msg_encode_publish,
	    nni_mqtt_msg_decode_publish },
	{ NNG_MQTT_PUBACK, nni_mqtt_msg_encode_puback,
	    nni_mqtt_msg_decode_puback },
	{ NNG_MQTT_PUBREC, nni_mqtt_msg_encode_pubrec,
	    nni_mqtt_msg_decode_pubrec },
	{ NNG_MQTT_PUBREL, nni_mqtt_msg_encode_pubrel,
	    nni_mqtt_msg_decode_pubrel },
	{ NNG_MQTT_PUBCOMP, nni_mqtt_msg_encode_pubcomp,
	    nni_mqtt_msg_decode_pubcomp },
	{ NNG_MQTT_SUBSCRIBE, nni_mqtt_msg_encode_subscribe,
	    nni_mqtt_msg_decode_subscribe },
	{ NNG_MQTT_SUBACK, nni_mqtt_msg_encode_suback,
	    nni_mqtt_msg_decode_suback },
	{ NNG_MQTT_UNSUBSCRIBE, nni_mqtt_msg_encode_unsubscribe,
	    nni_mqtt_msg_decode_unsubscribe },
	{ NNG_MQTT_UNSUBACK, nni_mqtt_msg_encode_unsuback,
	    nni_mqtt_msg_decode_unsuback },
	{ NNG_MQTT_PINGREQ, nni_mqtt_msg_encode_base,
	    nni_mqtt_msg_decode_base },
	{ NNG_MQTT_PINGRESP, nni_mqtt_msg_encode_base,
	    nni_mqtt_msg_decode_base },
	{ NNG_MQTT_DISCONNECT, nni_mqtt_msg_encode_base,
	    nni_mqtt_msg_decode_base }
};

int
nni_mqtt_msg_encode(nni_msg *msg)
{
	nni_msg_clear(msg);
	nni_msg_header_clear(msg);

	nni_mqtt_proto_data *mqtt = nni_msg_get_proto_data(msg);

	for (size_t i = 0;
	     i < sizeof(codec_handler) / sizeof(mqtt_msg_codec_handler); i++) {
		if (codec_handler[i].packet_type ==
		    mqtt->fixed_header.common.packet_type) {
			mqtt->is_decoded = false;
			mqtt->is_copied  = true;
			return codec_handler[i].encode(msg);
		}
	}

	return MQTT_ERR_PROTOCOL;
}

int
nni_mqtt_msg_decode(nni_msg *msg)
{
	int ret;
	if ((ret = nni_mqtt_msg_decode_fixed_header(msg)) != MQTT_SUCCESS) {
		// nni_plat_printf("decode_fixed_header failed %d\n", ret);
		return ret;
	}
	nni_mqtt_proto_data *mqtt = nni_msg_get_proto_data(msg);

	for (size_t i = 0;
	     i < sizeof(codec_handler) / sizeof(mqtt_msg_codec_handler); i++) {
		if (codec_handler[i].packet_type ==
		    mqtt->fixed_header.common.packet_type) {
			mqtt_msg_content_free(mqtt);
			mqtt->is_copied  = false;
			mqtt->is_decoded = true;
			return codec_handler[i].decode(msg);
		}
	}

	return MQTT_ERR_PROTOCOL;
}

static void
mqtt_msg_content_free(nni_mqtt_proto_data *mqtt)
{
	switch (mqtt->fixed_header.common.packet_type) {
	case NNG_MQTT_CONNECT:
		if (mqtt->is_copied) {
			destory_connect(mqtt);
		}
		break;
	case NNG_MQTT_PUBLISH:
		if (mqtt->is_copied) {
			destory_publish(mqtt);
		}
		break;
	case NNG_MQTT_SUBSCRIBE:
		if (mqtt->is_copied) {
			destory_subscribe(mqtt);
		} else {
			nni_free(mqtt->payload.subscribe.topic_arr,
			    mqtt->payload.subscribe.topic_count *
			        sizeof(nni_mqtt_topic_qos));
			mqtt->payload.subscribe.topic_count = 0;
		}
		break;
	case NNG_MQTT_SUBACK:
		destory_suback(mqtt);
		break;
	case NNG_MQTT_UNSUBSCRIBE:
		if (mqtt->is_copied) {
			destory_unsubscribe(mqtt);
		} else {
			nni_free(mqtt->payload.unsubscribe.topic_arr,
			    mqtt->payload.unsubscribe.topic_count *
			        sizeof(nni_mqtt_topic));
			mqtt->payload.unsubscribe.topic_count = 0;
		}
		break;

	default:
		break;
	}
}

int
nni_mqtt_msg_free(void *self)
{
	if (self) {
		nni_mqtt_proto_data *mqtt = self;
		mqtt_msg_content_free(mqtt);
		free(mqtt);
		return (0);
	}
	return (1);
}

int
nni_mqtt_msg_dup(void **dest, const void *src)
{
	nni_mqtt_proto_data *mqtt = (nni_mqtt_proto_data *) *dest;
	nni_mqtt_proto_data *s    = (nni_mqtt_proto_data *) src;

	mqtt = NNI_ALLOC_STRUCT(mqtt);
	memcpy(mqtt, (nni_mqtt_proto_data *) src, sizeof(nni_mqtt_proto_data));

	switch (mqtt->fixed_header.common.packet_type) {
	case NNG_MQTT_CONNECT:
		if (mqtt->is_copied) {
			dup_connect(mqtt, s);
		}
		break;
	case NNG_MQTT_PUBLISH:
		if (mqtt->is_copied) {
			dup_publish(mqtt, s);
		}
		break;
	case NNG_MQTT_SUBSCRIBE:
		if (mqtt->is_copied) {
			dup_subscribe(mqtt, s);
		} else {
			mqtt->payload.subscribe.topic_arr =
			    nni_alloc(s->payload.subscribe.topic_count *
			        sizeof(nni_mqtt_topic_qos));
			mqtt->payload.subscribe.topic_count =
			    s->payload.subscribe.topic_count;
			memcpy(mqtt->payload.subscribe.topic_arr,
			    s->payload.subscribe.topic_arr,
			    s->payload.subscribe.topic_count *
			        sizeof(nni_mqtt_topic_qos));
		}
		break;
	case NNG_MQTT_SUBACK:
		dup_suback(mqtt, s);
		break;
	case NNG_MQTT_UNSUBSCRIBE:
		if (mqtt->is_copied) {
			dup_unsubscribe(mqtt, s);
		} else {
			mqtt->payload.unsubscribe.topic_arr =
			    nni_alloc(s->payload.unsubscribe.topic_count *
			        sizeof(nni_mqtt_topic));
			mqtt->payload.unsubscribe.topic_count =
			    s->payload.unsubscribe.topic_count;
			memcpy(mqtt->payload.unsubscribe.topic_arr,
			    s->payload.unsubscribe.topic_arr,
			    s->payload.unsubscribe.topic_count *
			        sizeof(nni_mqtt_topic));
		}
		break;

	default:
		break;
	}

	*dest = mqtt;

	return (0);
}

static void
dup_connect(nni_mqtt_proto_data *dest, nni_mqtt_proto_data *src)
{
	mqtt_buf_dup(&dest->var_header.connect.protocol_name,
	    &src->var_header.connect.protocol_name);
	mqtt_buf_dup(
	    &dest->payload.connect.client_id, &src->payload.connect.client_id);
	mqtt_buf_dup(
	    &dest->payload.connect.user_name, &src->payload.connect.user_name);
	mqtt_buf_dup(
	    &dest->payload.connect.password, &src->payload.connect.password);
	mqtt_buf_dup(&dest->payload.connect.will_topic,
	    &src->payload.connect.will_topic);
	mqtt_buf_dup(
	    &dest->payload.connect.will_msg, &src->payload.connect.will_msg);
}

static void
dup_publish(nni_mqtt_proto_data *dest, nni_mqtt_proto_data *src)
{
	mqtt_buf_dup(&dest->var_header.publish.topic_name,
	    &src->var_header.publish.topic_name);
	mqtt_buf_dup(
	    &dest->payload.publish.payload, &src->payload.publish.payload);
}

static void
dup_subscribe(nni_mqtt_proto_data *dest, nni_mqtt_proto_data *src)
{
	dest->payload.subscribe.topic_arr = nni_mqtt_topic_qos_array_create(
	    src->payload.subscribe.topic_count);
	dest->payload.subscribe.topic_count =
	    src->payload.subscribe.topic_count;

	for (size_t i = 0; i < src->payload.subscribe.topic_count; i++) {
		nni_mqtt_topic_qos_array_set(dest->payload.subscribe.topic_arr,
		    i,
		    (const char *) src->payload.subscribe.topic_arr[i]
		        .topic.buf,
		    src->payload.subscribe.topic_arr[i].qos);
	}
}

static void
dup_suback(nni_mqtt_proto_data *dest, nni_mqtt_proto_data *src)
{
	dest->payload.suback.ret_code_arr =
	    nni_alloc(src->payload.suback.ret_code_count);
	dest->payload.suback.ret_code_count =
	    src->payload.suback.ret_code_count;
	memcpy(dest->payload.suback.ret_code_arr,
	    src->payload.suback.ret_code_arr,
	    src->payload.suback.ret_code_count);
}

static void
dup_unsubscribe(nni_mqtt_proto_data *dest, nni_mqtt_proto_data *src)
{
	dest->payload.unsubscribe.topic_arr =
	    nni_mqtt_topic_array_create(src->payload.unsubscribe.topic_count);
	dest->payload.unsubscribe.topic_count =
	    src->payload.unsubscribe.topic_count;

	for (size_t i = 0; i < src->payload.unsubscribe.topic_count; i++) {
		nni_mqtt_topic_array_set(dest->payload.unsubscribe.topic_arr,
		    i,
		    (const char *) src->payload.unsubscribe.topic_arr[i].buf);
	}
}

static void
destory_connect(nni_mqtt_proto_data *mqtt)
{
	mqtt_buf_free(&mqtt->var_header.connect.protocol_name);
	mqtt_buf_free(&mqtt->payload.connect.client_id);
	mqtt_buf_free(&mqtt->payload.connect.user_name);
	mqtt_buf_free(&mqtt->payload.connect.password);
	mqtt_buf_free(&mqtt->payload.connect.will_topic);
	mqtt_buf_free(&mqtt->payload.connect.will_msg);
}

static void
destory_publish(nni_mqtt_proto_data *mqtt)
{
	mqtt_buf_free(&mqtt->var_header.publish.topic_name);
	mqtt_buf_free(&mqtt->payload.publish.payload);
}

static void
destory_subscribe(nni_mqtt_proto_data *mqtt)
{
	nni_mqtt_topic_qos_array_free(mqtt->payload.subscribe.topic_arr,
	    mqtt->payload.subscribe.topic_count);
	mqtt->payload.subscribe.topic_count = 0;
}

static void
destory_suback(nni_mqtt_proto_data *mqtt)
{
	if (mqtt->payload.suback.ret_code_count > 0) {
		nni_free(mqtt->payload.suback.ret_code_arr,
		    mqtt->payload.suback.ret_code_count);
		mqtt->payload.suback.ret_code_arr   = NULL;
		mqtt->payload.suback.ret_code_count = 0;
	}
}

static void
destory_unsubscribe(nni_mqtt_proto_data *mqtt)
{
	nni_mqtt_topic_array_free(mqtt->payload.unsubscribe.topic_arr,
	    mqtt->payload.unsubscribe.topic_count);
	mqtt->payload.unsubscribe.topic_count = 0;
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
                .endpos                = &rlen[sizeof(rlen)] };

	nni_msg_header_clear(msg);
	uint8_t header = *(uint8_t *) &data->fixed_header.common;

	nni_msg_header_append(msg, &header, 1);

	int len = write_variable_length_value(
	    data->fixed_header.remaining_length, &buf);
	data->used_bytes = len;
	nni_msg_header_append(msg, rlen, len);
}

static int
nni_mqtt_msg_encode_connect(nni_msg *msg)
{
	nni_mqtt_proto_data *mqtt          = nni_msg_get_proto_data(msg);
	char                 client_id[20] = { 0 };

	nni_msg_clear(msg);

	int poslength = 6;

	mqtt_connect_vhdr *var_header = &mqtt->var_header.connect;

	if (var_header->protocol_name.length == 0) {
		mqtt_buf_create(&var_header->protocol_name,
		    (const uint8_t *) MQTT_PROTOCOL_NAME,
		    strlen(MQTT_PROTOCOL_NAME));
	}

	if (var_header->protocol_version == 0) {
		var_header->protocol_version = 4;
	}

	if (mqtt->payload.connect.client_id.length == 0) {
		snprintf(client_id, 20, "nanomq-%04x", nni_random());
		mqtt_buf_create(&mqtt->payload.connect.client_id,
		    (const uint8_t *) client_id, (uint32_t) strlen(client_id));
	}

	poslength += var_header->protocol_name.length;
	/* add the length of payload part */
	mqtt_connect_payload *payload = &mqtt->payload.connect;
	/* Clientid length */
	poslength += payload->client_id.length + 2;

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

	mqtt->fixed_header.remaining_length = (uint32_t) poslength;
	if (mqtt->fixed_header.remaining_length > MQTT_MAX_MSG_LEN) {
		return MQTT_ERR_PAYLOAD_SIZE;
	}
	nni_mqtt_msg_encode_fixed_header(msg, mqtt);

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

	return MQTT_SUCCESS;
}

static int
nni_mqtt_msg_encode_connack(nni_msg *msg)
{
	nni_mqtt_proto_data *mqtt = nni_msg_get_proto_data(msg);
	nni_msg_clear(msg);

	int poslength = 2; /* ConnAck Flags(1) + Connect Return Code(1) */

	mqtt_connack_vhdr *var_header = &mqtt->var_header.connack;

	mqtt->fixed_header.remaining_length = (uint32_t) poslength;
	nni_mqtt_msg_encode_fixed_header(msg, mqtt);

	/* Connect Acknowledge Flags */
	nni_mqtt_msg_append_u8(msg, *(uint8_t *) &var_header->connack_flags);

	/* Connect Return Code */
	nni_mqtt_msg_append_u8(
	    msg, *(uint8_t *) &var_header->conn_return_code);

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

	mqtt->fixed_header.remaining_length = (uint32_t) poslength;
	mqtt->fixed_header.common.bit_1     = 1;
	nni_mqtt_msg_encode_fixed_header(msg, mqtt);

	mqtt_subscribe_vhdr *var_header = &mqtt->var_header.subscribe;
	/* Packet Id */
	nni_mqtt_msg_append_u16(msg, var_header->packet_id);

	/* Subscribe topic_arr */
	for (size_t i = 0; i < spld->topic_count; i++) {
		mqtt_topic_qos *topic = &spld->topic_arr[i];
		nni_mqtt_msg_append_byte_str(msg, &topic->topic);
		nni_mqtt_msg_append_u8(msg, topic->qos);
	}

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

	mqtt->fixed_header.remaining_length = (uint32_t) poslength;
	nni_mqtt_msg_encode_fixed_header(msg, mqtt);

	/* Packet Identifier */
	nni_mqtt_msg_append_u16(msg, var_header->packet_id);

	/* Return Codes */
	nni_msg_append(msg, spld->ret_code_arr, spld->ret_code_count);

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
	mqtt->fixed_header.remaining_length = (uint32_t) poslength;

	nni_mqtt_msg_encode_fixed_header(msg, mqtt);

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

	return MQTT_SUCCESS;
}

static int
nni_mqtt_msg_encode_puback(nni_msg *msg)
{
	nni_mqtt_proto_data *mqtt = nni_msg_get_proto_data(msg);
	nni_msg_clear(msg);

	int poslength = 2; /* for Packet Identifier */

	mqtt_puback_vhdr *var_header = &mqtt->var_header.puback;

	mqtt->fixed_header.remaining_length = (uint32_t) poslength;

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

	int poslength                       = 2; /* for Packet Identifier */
	mqtt->fixed_header.remaining_length = (uint32_t) poslength;
	nni_mqtt_msg_encode_fixed_header(msg, mqtt);

	mqtt_pubrec_vhdr *var_header = &mqtt->var_header.pubrec;

	/* Packet Identifier */
	nni_mqtt_msg_append_u16(msg, var_header->packet_id);

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
	mqtt->fixed_header.remaining_length = (uint32_t) poslength;
	nni_mqtt_msg_encode_fixed_header(msg, mqtt);

	/* Packet Identifier */
	nni_mqtt_msg_append_u16(msg, var_header->packet_id);

	return MQTT_SUCCESS;
}

static int
nni_mqtt_msg_encode_pubcomp(nni_msg *msg)
{
	nni_mqtt_proto_data *mqtt = nni_msg_get_proto_data(msg);
	nni_msg_clear(msg);

	int poslength = 2; /* for Packet Identifier */

	mqtt_pubcomp_vhdr *var_header = &mqtt->var_header.pubcomp;

	mqtt->fixed_header.remaining_length = (uint32_t) poslength;
	nni_mqtt_msg_encode_fixed_header(msg, mqtt);

	/* Packet Identifier */
	nni_mqtt_msg_append_u16(msg, var_header->packet_id);

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

	mqtt->fixed_header.remaining_length = (uint32_t) poslength;
	mqtt->fixed_header.common.bit_1     = 1;
	nni_mqtt_msg_encode_fixed_header(msg, mqtt);

	mqtt_unsubscribe_vhdr *var_header = &mqtt->var_header.unsubscribe;
	/* Packet Id */
	nni_mqtt_msg_append_u16(msg, var_header->packet_id);

	/* Unsubscribe topic_arr */
	for (size_t i = 0; i < uspld->topic_count; i++) {
		mqtt_buf *topic = &uspld->topic_arr[i];
		nni_mqtt_msg_append_byte_str(msg, topic);
	}

	return MQTT_SUCCESS;
}

static int
nni_mqtt_msg_encode_unsuback(nni_msg *msg)
{
	nni_mqtt_proto_data *mqtt = nni_msg_get_proto_data(msg);
	nni_msg_clear(msg);

	int poslength = 2; /* for Packet Identifier */

	mqtt_unsuback_vhdr *var_header = &mqtt->var_header.unsuback;

	mqtt->fixed_header.remaining_length = (uint32_t) poslength;
	nni_mqtt_msg_encode_fixed_header(msg, mqtt);

	/* Packet Identifier */
	nni_mqtt_msg_append_u16(msg, var_header->packet_id);

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

static int
nni_mqtt_msg_decode_fixed_header(nni_msg *msg)
{
	nni_mqtt_proto_data *mqtt = nni_msg_get_proto_data(msg);

	size_t   len    = nni_msg_header_len(msg);
	uint8_t *header = nni_msg_header(msg);

	if (len < 2) {
		return MQTT_ERR_PROTOCOL;
	}

	memcpy(&mqtt->fixed_header.common, header, 1);

	uint8_t  used_bytes;
	uint32_t remain_len = 0;

	int ret;
	if ((ret = mqtt_get_remaining_length(header, (uint32_t) len,
	         &remain_len, &used_bytes)) != MQTT_SUCCESS) {
		return ret;
	}

	mqtt->fixed_header.remaining_length = remain_len;
	mqtt->used_bytes                    = used_bytes;

	return MQTT_SUCCESS;
}

static int
nni_mqtt_msg_decode_connect(nni_msg *msg)
{
	int                  ret;
	nni_mqtt_proto_data *mqtt = nni_msg_get_proto_data(msg);

	uint8_t *body   = nni_msg_body(msg);
	size_t   length = nni_msg_len(msg);

	struct pos_buf buf;
	buf.curpos = &body[0];
	buf.endpos = &body[length];

	/* Protocol Name */
	ret = read_str_data(&buf, &mqtt->var_header.connect.protocol_name);
	if (ret != 0) {
		return MQTT_ERR_PROTOCOL;
	}
	/* Protocol Level */
	ret = read_byte(&buf, &mqtt->var_header.connect.protocol_version);
	if (ret != 0) {
		return MQTT_ERR_PROTOCOL;
	}
	/* Protocol Level */
	ret =
	    read_byte(&buf, (uint8_t *) &mqtt->var_header.connect.conn_flags);
	if (ret != 0) {
		return MQTT_ERR_PROTOCOL;
	}

	/* Keep Alive */
	ret = read_uint16(&buf, &mqtt->var_header.connect.keep_alive);
	if (ret != 0) {
		return MQTT_ERR_PROTOCOL;
	}
	/* Client Identifier */
	ret = read_utf8_str(&buf, &mqtt->payload.connect.client_id);
	if (ret != 0) {
		return MQTT_ERR_PROTOCOL;
	}
	if (mqtt->var_header.connect.conn_flags.will_flag) {
		/* Will Topic */
		ret = read_utf8_str(&buf, &mqtt->payload.connect.will_topic);
		if (ret != 0) {
			return MQTT_ERR_PROTOCOL;
		}
		/* Will Message */
		ret = read_str_data(&buf, &mqtt->payload.connect.will_msg);
		if (ret != 0) {
			return MQTT_ERR_PROTOCOL;
		}
	}
	if (mqtt->var_header.connect.conn_flags.username_flag) {
		/* Will Topic */
		ret = read_utf8_str(&buf, &mqtt->payload.connect.user_name);
		if (ret != 0) {
			return MQTT_ERR_PROTOCOL;
		}
	}
	if (mqtt->var_header.connect.conn_flags.password_flag) {
		/* Will Topic */
		ret = read_str_data(&buf, &mqtt->payload.connect.password);
		if (ret != 0) {
			return MQTT_ERR_PROTOCOL;
		}
	}
	return MQTT_SUCCESS;
}

static int
nni_mqtt_msg_decode_connack(nni_msg *msg)
{
	nni_mqtt_proto_data *mqtt = nni_msg_get_proto_data(msg);

	uint8_t *body   = nni_msg_body(msg);
	size_t   length = nni_msg_len(msg);

	struct pos_buf buf;
	buf.curpos = &body[0];
	buf.endpos = &body[length];

	int result = read_byte(&buf, &mqtt->var_header.connack.connack_flags);
	if (result != 0) {
		return MQTT_ERR_PROTOCOL;
	}

	/* Connect Return Code */
	result = read_byte(&buf, &mqtt->var_header.connack.connack_flags);
	if (result != 0) {
		return MQTT_ERR_PROTOCOL;
	}

	return MQTT_SUCCESS;
}

static int
nni_mqtt_msg_decode_subscribe(nni_msg *msg)
{
	int                  ret;
	nni_mqtt_proto_data *mqtt = nni_msg_get_proto_data(msg);

	uint8_t *body   = nni_msg_body(msg);
	size_t   length = nni_msg_len(msg);

	struct pos_buf buf;
	buf.curpos = &body[0];
	buf.endpos = &body[length];

	mqtt_subscribe_payload *spld = &mqtt->payload.subscribe;

	/* Packet Identifier */
	ret = read_uint16(&buf, &mqtt->var_header.subscribe.packet_id);
	if (ret != 0) {
		return MQTT_ERR_PROTOCOL;
	}

	uint8_t *saved_current_pos = NULL;
	uint16_t temp_length       = 0;
	uint32_t topic_count       = 0;

	/* The loop to determine the number of topic_arr.
	 * TODO: Some other way may be used such as std::vector to collect
	 * topic_arr but there is a question that which is faster
	 */
	/* Save the current position to back */
	saved_current_pos = buf.curpos;
	while (buf.curpos < buf.endpos) {
		ret = read_uint16(&buf, &temp_length);
		/* jump to the end of topic-name */
		buf.curpos += temp_length;
		/* skip QoS field */
		buf.curpos++;
		topic_count++;
	}
	/* Allocate topic_qos array */
	spld->topic_arr =
	    (mqtt_topic_qos *) nni_alloc(sizeof(mqtt_topic_qos) * topic_count);

	/* Set back current position */
	buf.curpos = saved_current_pos;
	while (buf.curpos < buf.endpos) {
		/* Topic Name */
		ret = read_utf8_str(
		    &buf, &spld->topic_arr[spld->topic_count].topic);
		if (ret != MQTT_SUCCESS) {
			ret = MQTT_ERR_PROTOCOL;
			goto err;
		}
		/* QoS */
		ret = read_byte(&buf, &spld->topic_arr[spld->topic_count].qos);
		if (ret != MQTT_SUCCESS) {
			ret = MQTT_ERR_PROTOCOL;
			goto err;
		}
		spld->topic_count++;
	}
	return MQTT_SUCCESS;

err:
	nni_free(spld->topic_arr, sizeof(mqtt_topic_qos) * topic_count);
	return ret;
}

static int
nni_mqtt_msg_decode_suback(nni_msg *msg)
{
	int                  ret;
	nni_mqtt_proto_data *mqtt = nni_msg_get_proto_data(msg);

	uint8_t *body   = nni_msg_body(msg);
	size_t   length = nni_msg_len(msg);

	struct pos_buf buf;
	buf.curpos = &body[0];
	buf.endpos = &body[length];

	ret = read_uint16(&buf, &mqtt->var_header.suback.packet_id);
	if (ret != MQTT_SUCCESS) {
		return MQTT_ERR_PROTOCOL;
	}

	/* Suback Return Codes */
	mqtt->payload.suback.ret_code_count = buf.endpos - buf.curpos;

	mqtt->payload.suback.ret_code_arr =
	    (uint8_t *) nni_alloc(mqtt->payload.suback.ret_code_count);
	uint8_t *ptr = mqtt->payload.suback.ret_code_arr;

	for (uint32_t i = 0; i < mqtt->payload.suback.ret_code_count; i++) {
		ret = read_byte(&buf, ptr);
		if (ret != MQTT_SUCCESS) {
			ret = MQTT_ERR_PROTOCOL;
			goto err;
		}
		ptr++;
	}

	return MQTT_SUCCESS;

err:
	nni_free(mqtt->payload.suback.ret_code_arr,
	    mqtt->payload.suback.ret_code_count);
	return ret;
}

static int
nni_mqtt_msg_decode_publish(nni_msg *msg)
{
	int                  ret;
	int                  packid_length = 0;
	nni_mqtt_proto_data *mqtt          = nni_msg_get_proto_data(msg);

	uint8_t *body   = nni_msg_body(msg);
	size_t   length = nni_msg_len(msg);

	struct pos_buf buf;
	buf.curpos = &body[0];
	buf.endpos = &body[length];

	/* Topic Name */
	ret = read_utf8_str(&buf, &mqtt->var_header.publish.topic_name);
	if (ret != MQTT_SUCCESS) {
		return MQTT_ERR_PROTOCOL;
	}

	if (mqtt->fixed_header.publish.qos > MQTT_QOS_0_AT_MOST_ONCE) {
		/* Packet Identifier */
		ret = read_uint16(&buf, &mqtt->var_header.publish.packet_id);
		if (ret != MQTT_SUCCESS) {
			return MQTT_ERR_PROTOCOL;
		}
		packid_length = 2;
	}

	/* Payload */
	/* No length information for payload. The length of the payload can be
	   calculated by subtracting the length of the variable header from the
	   Remaining Length field that is in the Fixed Header. It is valid for
	   a PUBLISH Packet to contain a zero length payload.*/
	mqtt->payload.publish.payload.length =
	    mqtt->fixed_header.remaining_length -
	    (2 /* Length bytes of Topic Name */ +
	        mqtt->var_header.publish.topic_name.length + packid_length);
	mqtt->payload.publish.payload.buf =
	    (mqtt->payload.publish.payload.length > 0) ? buf.curpos : NULL;

	return MQTT_SUCCESS;
}

static int
nni_mqtt_msg_decode_base_with_packet_id(nni_msg *msg, uint16_t *packet_id)
{
	uint8_t *body   = nni_msg_body(msg);
	size_t   length = nni_msg_len(msg);

	struct pos_buf buf;
	buf.curpos = &body[0];
	buf.endpos = &body[length];

	int result = read_uint16(&buf, packet_id);
	if (result != MQTT_SUCCESS) {
		return MQTT_ERR_PROTOCOL;
	}

	return MQTT_SUCCESS;
}

static int
nni_mqtt_msg_decode_puback(nni_msg *msg)
{
	nni_mqtt_proto_data *mqtt = nni_msg_get_proto_data(msg);

	return nni_mqtt_msg_decode_base_with_packet_id(
	    msg, &mqtt->var_header.puback.packet_id);
}

static int
nni_mqtt_msg_decode_pubrec(nni_msg *msg)
{
	nni_mqtt_proto_data *mqtt = nni_msg_get_proto_data(msg);

	return nni_mqtt_msg_decode_base_with_packet_id(
	    msg, &mqtt->var_header.pubrec.packet_id);
}

static int
nni_mqtt_msg_decode_pubrel(nni_msg *msg)
{
	nni_mqtt_proto_data *mqtt = nni_msg_get_proto_data(msg);

	if (mqtt->fixed_header.common.bit_0 != 0 ||
	    mqtt->fixed_header.common.bit_1 != 1 ||
	    mqtt->fixed_header.common.bit_2 != 0 ||
	    mqtt->fixed_header.common.bit_3 != 0) {
		return MQTT_ERR_PROTOCOL;
	}

	return nni_mqtt_msg_decode_base_with_packet_id(
	    msg, &mqtt->var_header.pubrel.packet_id);
}

static int
nni_mqtt_msg_decode_pubcomp(nni_msg *msg)
{
	nni_mqtt_proto_data *mqtt = nni_msg_get_proto_data(msg);

	return nni_mqtt_msg_decode_base_with_packet_id(
	    msg, &mqtt->var_header.pubcomp.packet_id);
}

static int
nni_mqtt_msg_decode_unsubscribe(nni_msg *msg)
{
	nni_mqtt_proto_data *mqtt = nni_msg_get_proto_data(msg);

	if (mqtt->fixed_header.common.bit_0 != 0 ||
	    mqtt->fixed_header.common.bit_1 != 1 ||
	    mqtt->fixed_header.common.bit_2 != 0 ||
	    mqtt->fixed_header.common.bit_3 != 0) {
		return MQTT_ERR_PROTOCOL;
	}

	uint8_t *body   = nni_msg_body(msg);
	size_t   length = nni_msg_len(msg);

	struct pos_buf buf;
	buf.curpos                      = &body[0];
	buf.endpos                      = &body[length];
	mqtt_unsubscribe_payload *uspld = &mqtt->payload.unsubscribe;

	int ret = read_uint16(&buf, &mqtt->var_header.unsubscribe.packet_id);
	if (ret != MQTT_SUCCESS) {
		return MQTT_ERR_PROTOCOL;
	}

	uint8_t *saved_current_pos = NULL;
	uint16_t temp_length       = 0;
	uint32_t topic_count       = 0;

	saved_current_pos = buf.curpos;
	while (buf.curpos < buf.endpos) {
		ret = read_uint16(&buf, &temp_length);
		/* jump to the end of topic-name */
		buf.curpos += temp_length;
		/* skip QoS field */
		topic_count++;
	}

	/* Allocate topic array */
	uspld->topic_arr =
	    (mqtt_buf *) nni_alloc(topic_count * sizeof(mqtt_buf));

	/* Set back current position */
	buf.curpos = saved_current_pos;
	while (buf.curpos < buf.endpos) {
		/* Topic Name */
		ret =
		    read_utf8_str(&buf, &uspld->topic_arr[uspld->topic_count]);
		if (ret != MQTT_SUCCESS) {
			ret = MQTT_ERR_PROTOCOL;
			goto err;
		}
		uspld->topic_count++;
	}
	return MQTT_SUCCESS;

err:
	nni_free(uspld->topic_arr, topic_count * sizeof(mqtt_buf));

	return ret;
}

static int
nni_mqtt_msg_decode_unsuback(nni_msg *msg)
{
	nni_mqtt_proto_data *mqtt = nni_msg_get_proto_data(msg);

	return nni_mqtt_msg_decode_base_with_packet_id(
	    msg, &mqtt->var_header.unsuback.packet_id);
}

static int
nni_mqtt_msg_decode_base(nni_msg *msg)
{
	NNI_ARG_UNUSED(msg);
	return MQTT_SUCCESS;
}

int
byte_number_for_variable_length(uint32_t variable)
{
	if (variable < 128) {
		return 1;
	} else if (variable < 16384) {
		return 2;
	} else if (variable < 2097152) {
		return 3;
	} else if (variable < 268435456) {
		return 4;
	}
	return 5;
}

int
write_variable_length_value(uint32_t value, struct pos_buf *buf)
{
	uint8_t byte;
	int     count = 0;

	do {
		byte  = value % 128;
		value = value / 128;
		/* If there are more digits to encode, set the top bit of this
		 * digit */
		if (value > 0) {
			byte = byte | 0x80;
		}
		*(buf->curpos++) = byte;
		count++;
	} while (value > 0 && count < 5);

	if (count == 5) {
		return -1;
	}
	return count;
}

int
write_byte(uint8_t val, struct pos_buf *buf)
{
	if ((buf->endpos - buf->curpos) < 1) {
		return MQTT_ERR_NOMEM;
	}

	*(buf->curpos++) = val;

	return 0;
}

int
write_uint16(uint16_t value, struct pos_buf *buf)
{
	if ((buf->endpos - buf->curpos) < 2) {
		return MQTT_ERR_NOMEM;
	}

	*(buf->curpos++) = (value >> 8) & 0xFF;
	*(buf->curpos++) = value & 0xFF;

	return 0;
}

int
write_byte_string(mqtt_buf *str, struct pos_buf *buf)
{
	if ((buf->endpos - buf->curpos) < (str->length + 2)) {
		return MQTT_ERR_NOMEM;
	}
	write_uint16(str->length, buf);

	memcpy(buf->curpos, str->buf, str->length);
	str->buf = buf->curpos; /* reset data position to indicate data in raw
	                           data block */
	buf->curpos += str->length;

	return 0;
}

int
read_byte(struct pos_buf *buf, uint8_t *val)
{
	if ((buf->endpos - buf->curpos) < 1) {
		return MQTT_ERR_NOMEM;
	}

	*val = *(buf->curpos++);

	return 0;
}

int
read_uint16(struct pos_buf *buf, uint16_t *val)
{
	if ((size_t)(buf->endpos - buf->curpos) < sizeof(uint16_t)) {
		return MQTT_ERR_INVAL;
	}

	*val = *(buf->curpos++) << 8; /* MSB */
	*val |= *(buf->curpos++);     /* LSB */

	return 0;
}

int
read_utf8_str(struct pos_buf *buf, mqtt_buf *val)
{
	uint16_t length = 0;
	int      ret    = read_uint16(buf, &length);
	if (ret != 0) {
		return ret;
	}
	if ((buf->endpos - buf->curpos) < length) {
		return MQTT_ERR_INVAL;
	}

	val->length = length;
	/* Zero length UTF8 strings are permitted. */
	if (length > 0) {
		val->buf = buf->curpos;
		buf->curpos += length;
	} else {
		val->buf = NULL;
	}
	return 0;
}

int
read_str_data(struct pos_buf *buf, mqtt_buf *val)
{
	uint16_t length = 0;
	int      ret    = read_uint16(buf, &length);
	if (ret != 0) {
		return ret;
	}
	if ((buf->endpos - buf->curpos) < length) {
		return MQTT_ERR_INVAL;
	}

	val->length = length;
	if (length > 0) {
		val->buf = buf->curpos;
		buf->curpos += length;
	} else {
		val->buf = NULL;
	}
	return 0;
}

int
read_packet_length(struct pos_buf *buf, uint32_t *length)
{
	uint8_t  shift = 0;
	uint32_t bytes = 0;

	*length = 0;
	do {
		if (bytes >= MQTT_MAX_MSG_LEN) {
			return MQTT_ERR_INVAL;
		}

		if (buf->curpos >= buf->endpos) {
			return MQTT_ERR_MALFORMED;
		}

		*length +=
		    ((uint32_t) * (buf->curpos) & MQTT_LENGTH_VALUE_MASK)
		    << shift;
		shift += MQTT_LENGTH_SHIFT;
		bytes++;
	} while ((*(buf->curpos++) & MQTT_LENGTH_CONTINUATION_BIT) != 0U);

	if (*length > MQTT_MAX_MSG_LEN) {
		return MQTT_ERR_INVAL;
	}

	return 0;
}

int
mqtt_get_remaining_length(uint8_t *packet, uint32_t len,
    uint32_t *remainning_length, uint8_t *used_bytes)
{
	int      multiplier = 1;
	int32_t  lword      = 0;
	uint8_t  lbytes     = 0;
	uint8_t *ptr        = packet + 1;
	uint8_t *start      = ptr;

	for (size_t i = 0; i < 4; i++) {
		if ((size_t)(ptr - start + 1) > len) {
			return MQTT_ERR_PAYLOAD_SIZE;
		}
		lbytes++;
		uint8_t byte = ptr[0];
		lword += (byte & 127) * multiplier;
		multiplier *= 128;
		ptr++;
		if ((byte & 128) == 0) {
			if (lbytes > 1 && byte == 0) {
				return MQTT_ERR_INVAL;
			} else {
				*remainning_length = lword;
				if (used_bytes) {
					*used_bytes = lbytes;
				}
				return MQTT_SUCCESS;
			}
		}
	}

	return MQTT_ERR_INVAL;
}

int
mqtt_buf_create(mqtt_buf *mbuf, const uint8_t *buf, uint32_t length)
{
	if ((mbuf->buf = nni_alloc(length)) != NULL) {
		mbuf->length = length;
		memcpy(mbuf->buf, buf, mbuf->length);
		return (0);
	}
	return NNG_ENOMEM;
}

int
mqtt_buf_dup(mqtt_buf *dest, const mqtt_buf *src)
{
	if (src->length <= 0) {
		return 0;
	}
	if ((dest->buf = nni_alloc(src->length)) != NULL) {
		dest->length = src->length;
		memcpy(dest->buf, src->buf, src->length);
		return (0);
	}
	return NNG_ENOMEM;
}

void
mqtt_buf_free(mqtt_buf *buf)
{
	if (buf->length > 0) {
		nni_free(buf->buf, buf->length);
		buf->length = 0;
		buf->buf    = NULL;
	}
}

static mqtt_msg *
mqtt_msg_create_empty(void)
{
	mqtt_msg *msg = (mqtt_msg *) malloc(sizeof(mqtt_msg));
	memset((char *) msg, 0, sizeof(mqtt_msg));

	return msg;
}

mqtt_msg *
mqtt_msg_create(nni_mqtt_packet_type packet_type)
{
	mqtt_msg *msg                        = mqtt_msg_create_empty();
	msg->fixed_header.common.packet_type = packet_type;

	return msg;
}

int
mqtt_msg_destroy(mqtt_msg *self)
{
	free(self);

	return 0;
}

const char *
get_packet_type_str(nni_mqtt_packet_type packtype)
{
	static const char *packTypeNames[16] = { "Forbidden-0", "CONNECT",
		"CONNACK", "PUBLISH", "PUBACK", "PUBREC", "PUBREL", "PUBCOMP",
		"SUBSCRIBE", "SUBACK", "UNSUBSCRIBE", "UNSUBACK", "PINGREQ",
		"PINGRESP", "DISCONNECT", "Forbidden-15" };
	if (packtype > 15) {
		packtype = 0;
	}
	return packTypeNames[packtype];
}

int
mqtt_msg_dump(mqtt_msg *msg, mqtt_buf *buf, mqtt_buf *packet, bool print_bytes)
{
	uint32_t pos = 0;
	int      ret = 0;

	size_t i = 0;

	ret = sprintf((char *) &buf->buf[pos],
	    "\n----- mqtt message dump  -----\n"
	    "packet type        :   %d (%s)\n"
	    "packet flags       :   |%d|%d|%d|%d|\n"
	    "remaining length   :   %d (%d bytes)\n",
	    msg->fixed_header.common.packet_type,
	    get_packet_type_str(msg->fixed_header.common.packet_type),
	    msg->fixed_header.common.bit_3, msg->fixed_header.common.bit_2,
	    msg->fixed_header.common.bit_1, msg->fixed_header.common.bit_0,
	    (int) msg->fixed_header.remaining_length, msg->used_bytes);
	if ((ret < 0) || ((pos + ret) > buf->length)) {
		return 1;
	}
	pos += ret;

	/* Print variable header part */
	switch (msg->fixed_header.common.packet_type) {
	case NNG_MQTT_CONNECT: {
		ret = sprintf((char *) &buf->buf[pos],
		    "protocol name      :   %.*s\n"
		    "protocol version   :   %d\n"
		    "keep alive         :   %d\n",
		    msg->var_header.connect.protocol_name.length,
		    msg->var_header.connect.protocol_name.buf,
		    (int) msg->var_header.connect.protocol_version,
		    (int) msg->var_header.connect.keep_alive);
		if ((ret < 0) || ((pos + ret) > buf->length)) {
			return 1;
		}
		pos += ret;
		conn_flags flags_set = msg->var_header.connect.conn_flags;

		ret = sprintf((char *) &buf->buf[pos],
		    "connect flags:\n"
		    "   clean session flag : %s\n"
		    "   will flag          : %s\n"
		    "   will retain flag   : %s\n"
		    "   will qos flag      : %d\n"
		    "   user name flag     : %s\n"
		    "   password flag      : %s\n",
		    ((flags_set.clean_session) ? "true" : "false"),
		    ((flags_set.will_flag) ? "true" : "false"),
		    ((flags_set.will_retain) ? "true" : "false"),
		    flags_set.will_qos,
		    ((flags_set.username_flag) ? "true" : "false"),
		    ((flags_set.password_flag) ? "true" : "false"));
		if ((ret < 0) || ((pos + ret) > buf->length)) {
			return 1;
		}
		pos += ret;
		ret = sprintf((char *) &buf->buf[pos],
		    "client id             : %.*s\n",
		    msg->payload.connect.client_id.length,
		    msg->payload.connect.client_id.buf);
		if ((ret < 0) || ((pos + ret) > buf->length)) {
			return 1;
		}
		pos += ret;
		ret = sprintf((char *) &buf->buf[pos],
		    "will topic            : %.*s\n",
		    msg->payload.connect.will_topic.length,
		    msg->payload.connect.will_topic.buf);
		if ((ret < 0) || ((pos + ret) > buf->length)) {
			return 1;
		}
		pos += ret;
		ret = sprintf((char *) &buf->buf[pos],
		    "will message          : %.*s\n",
		    msg->payload.connect.will_msg.length,
		    msg->payload.connect.will_msg.buf);
		if ((ret < 0) || ((pos + ret) > buf->length)) {
			return 1;
		}
		pos += ret;
		ret = sprintf((char *) &buf->buf[pos],
		    "user name             : %.*s\n",
		    msg->payload.connect.user_name.length,
		    msg->payload.connect.user_name.buf);
		if ((ret < 0) || ((pos + ret) > buf->length)) {
			return 1;
		}
		pos += ret;
		ret = sprintf((char *) &buf->buf[pos],
		    "password              : %.*s\n",
		    msg->payload.connect.password.length,
		    msg->payload.connect.password.buf);
		if ((ret < 0) || ((pos + ret) > buf->length)) {
			return 1;
		}
		pos += ret;
	} break;

	case NNG_MQTT_CONNACK:
		ret = sprintf((char *) &buf->buf[pos],
		    "connack flags      : %d\n"
		    "connack return-code: %d\n",
		    (int) msg->var_header.connack.connack_flags,
		    (int) msg->var_header.connack.conn_return_code);
		if ((ret < 0) || ((pos + ret) > buf->length)) {
			return 1;
		}
		pos += ret;
		break;

	case NNG_MQTT_PUBLISH: {

		ret = sprintf((char *) &buf->buf[pos],
		    "publis flags:\n"
		    "   retain   : %s\n"
		    "   qos      : %d\n"
		    "   dup      : %s\n",
		    ((msg->fixed_header.publish.retain) ? "true" : "false"),
		    msg->fixed_header.publish.qos,
		    ((msg->fixed_header.publish.dup) ? "true" : "false"));
		if ((ret < 0) || ((pos + ret) > buf->length)) {
			return 1;
		}
		pos += ret;
		ret = sprintf((char *) &buf->buf[pos],
		    "topic       : %.*s\n"
		    "packet id   : %d\n"
		    "payload     : %.*s\n",
		    msg->var_header.publish.topic_name.length,
		    msg->var_header.publish.topic_name.buf,
		    (int) msg->var_header.publish.packet_id,
		    msg->payload.publish.payload.length,
		    msg->payload.publish.payload.buf);
		if ((ret < 0) || ((pos + ret) > buf->length)) {
			return 1;
		}
		pos += ret;
	} break;

	case NNG_MQTT_PUBACK:
		ret = sprintf((char *) &buf->buf[pos], "packet-id: %d\n",
		    msg->var_header.puback.packet_id);
		if ((ret < 0) || ((pos + ret) > buf->length)) {
			return 1;
		}
		pos += ret;
		break;

	case NNG_MQTT_PUBREC:
		ret = sprintf((char *) &buf->buf[pos], "packet-id: %d\n",
		    msg->var_header.pubrec.packet_id);
		if ((ret < 0) || ((pos + ret) > buf->length)) {
			return 1;
		}
		pos += ret;
		break;

	case NNG_MQTT_PUBREL:
		ret = sprintf((char *) &buf->buf[pos], "packet-id: %d\n",
		    msg->var_header.pubrel.packet_id);
		if ((ret < 0) || ((pos + ret) > buf->length)) {
			return 1;
		}
		pos += ret;
		break;

	case NNG_MQTT_PUBCOMP:
		ret = sprintf((char *) &buf->buf[pos], "packet-id: %d\n",
		    msg->var_header.pubcomp.packet_id);
		if ((ret < 0) || ((pos + ret) > buf->length)) {
			return 1;
		}
		pos += ret;
		break;

	case NNG_MQTT_SUBSCRIBE: {
		ret = sprintf((char *) &buf->buf[pos],
		    "packet-id          :   %d\n",
		    msg->var_header.subscribe.packet_id);
		if ((ret < 0) || ((pos + ret) > buf->length)) {
			return 1;
		}
		pos += ret;
		for (uint32_t i = 0; i < msg->payload.subscribe.topic_count;
		     i++) {
			ret = sprintf((char *) &buf->buf[pos],
			    "topic       [%u]    :   %.*s\n"
			    "requested qos[%u]   :   %d\n",
			    i,
			    msg->payload.subscribe.topic_arr[i].topic.length,
			    msg->payload.subscribe.topic_arr[i].topic.buf, i,
			    (int) msg->payload.subscribe.topic_arr[i].qos);
			if ((ret < 0) || ((pos + ret) > buf->length)) {
				return 1;
			}
			pos += ret;
		}
	} break;

	case NNG_MQTT_SUBACK: {
		ret = sprintf((char *) &buf->buf[pos],
		    "packet-id          :   %d\n",
		    msg->var_header.suback.packet_id);
		if ((ret < 0) || ((pos + ret) > buf->length)) {
			return 1;
		}
		pos += ret;
		for (uint32_t i = 0; i < msg->payload.suback.ret_code_count;
		     i++) {
			ret = sprintf((char *) &buf->buf[pos],
			    "return code[%u]: %d\n", i,
			    (int) msg->payload.suback.ret_code_arr[i]);
			if ((ret < 0) || ((pos + ret) > buf->length)) {
				return 1;
			}
			pos += ret;
		}
	} break;

	case NNG_MQTT_UNSUBSCRIBE: {
		ret = sprintf((char *) &buf->buf[pos],
		    "packet-id          : %d\n",
		    msg->var_header.unsubscribe.packet_id);
		if ((ret < 0) || ((pos + ret) > buf->length)) {
			return 1;
		}
		pos += ret;
		for (i = 0; i < msg->payload.unsubscribe.topic_count; i++) {
			ret = sprintf((char *) &buf->buf[pos],
			    "topic       [%lu] :  %.*s\n", i,
			    msg->payload.unsubscribe.topic_arr[i].length,
			    (char *) msg->payload.unsubscribe.topic_arr[i]
			        .buf);
			if ((ret < 0) || ((pos + ret) > buf->length)) {
				return 1;
			}
			pos += ret;
		}
	} break;

	case NNG_MQTT_UNSUBACK:
		ret = sprintf((char *) &buf->buf[pos],
		    "packet-id          : %d\n",
		    msg->var_header.unsuback.packet_id);
		if ((ret < 0) || ((pos + ret) > buf->length)) {
			return 1;
		}
		pos += ret;
		break;

	case NNG_MQTT_PINGREQ:
	case NNG_MQTT_PINGRESP:
		break;

	case NNG_MQTT_DISCONNECT:
		break;

	case NNG_MQTT_AUTH:
		break;
	}

	if (print_bytes) {
		ret = sprintf((char *) &buf->buf[pos], "raw message: ");
		if ((ret < 0) || ((pos + ret) > buf->length)) {
			return 1;
		}
		pos += ret;
		for (i = 0; i < packet->length; i++) {
			ret = sprintf((char *) &buf->buf[pos], "%02x ",
			    ((uint8_t)(packet->buf[i] & 0xff)));
			if ((ret < 0) || ((pos + ret) > buf->length)) {
				return 1;
			}
			pos += ret;
		}
		buf->buf[pos++] = '\n';
		if (pos > packet->length) {
			return 1;
		}
		sprintf((char *) &buf->buf[pos], "------------------------\n");
	}
	return 0;
}
