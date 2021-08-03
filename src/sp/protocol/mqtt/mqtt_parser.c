//
// Copyright 2020 NanoMQ Team, Inc. <jaylin@emqx.io>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "nng/protocol/mqtt/mqtt_parser.h"
#include "core/nng_impl.h"
#include "nng/nng_debug.h"
#include "nng/protocol/mqtt/mqtt.h"

#include <conf.h>
#include <stdio.h>
#include <string.h>

static uint8_t  get_value_size(uint64_t value);
static uint64_t power(uint64_t x, uint32_t n);

static uint64_t
power(uint64_t x, uint32_t n)
{
	uint64_t val = 1;

	for (uint32_t i = 0; i <= n; ++i) {
		val = x * val;
	}

	return val / x;
}

/**
 * get size from value
 *
 * @param value
 * @return
 */
static uint8_t
get_value_size(uint64_t value)
{
	uint8_t  len = 1;
	uint64_t pow;
	for (int i = 1; i <= 4; ++i) {
		pow = power(0x080, i);
		if (value >= pow) {
			++len;
		} else {
			break;
		}
	}
	return len;
}

/**
 * put a value to variable byte array
 * @param dest
 * @param value
 * @return data length
 */
uint8_t
put_var_integer(uint8_t *dest, uint32_t value)
{
	uint8_t  len        = 0;
	uint32_t init_val   = 0x7F;
	uint8_t  value_size = get_value_size(value);

	for (uint32_t i = 0; i < value_size; ++i) {

		if (i > 0) {
			init_val = (init_val * 0x80) | 0xFF;
		}
		dest[i] = value / (uint32_t) power(0x80, i);
		if (value > init_val) {
			dest[i] |= 0x80;
		}
		len++;
	}
	return len;
}

/**
 * Get variable integer value
 *
 * @param buf Byte array
 * @param pos
 * @return Integer value
 */
uint32_t
get_var_integer(const uint8_t *buf, uint32_t *pos)
{
	uint8_t  temp;
	uint32_t result = 0;

	uint32_t p = *pos;
	int      i = 0;

	do {
		temp   = *(buf + p);
		result = result + (uint32_t)(temp & 0x7f) * (power(0x80, i));
		p++;
	} while ((temp & 0x80) > 0 && i++ < 4);
	*pos = p;
	return result;
}

/**
 * Get utf-8 string
 *
 * @param dest output string
 * @param src input bytes
 * @param pos
 * @return string length -1: not utf-8, 0: empty string, >0 : normal utf-8
 * string
 */
int32_t
get_utf8_str(char **dest, const uint8_t *src, uint32_t *pos)
{
	int32_t str_len = 0;
	NNI_GET16(src + (*pos), str_len);

	*pos = (*pos) + 2;
	if (str_len > 0) {
		if (utf8_check((const char *) (src + *pos), str_len) ==
		    ERR_SUCCESS) {
			*dest = (char *) (src + (*pos));
			*pos  = (*pos) + str_len;
		} else {
			str_len = -1;
		}
	}
	return str_len;
}

/**
 * copy utf-8 string to dst
 *
 * @param dest output string
 * @param src input bytes
 * @param pos
 * @return string length -1: not utf-8, 0: empty string, >0 : normal utf-8
 * string
 */
uint8_t *
copy_utf8_str(const uint8_t *src, uint32_t *pos, int *str_len)
{
	*str_len      = 0;
	uint8_t *dest = NULL;

	NNI_GET16(src + (*pos), *str_len);

	*pos = (*pos) + 2;
	if (*str_len > 0) {
		dest = nng_alloc(*str_len + 1);
		if (utf8_check((const char *) (src + *pos), *str_len) ==
		    ERR_SUCCESS) {
			memcpy(dest, src + (*pos), *str_len);
			dest[*str_len] = '\0';
			*pos           = (*pos) + (*str_len);
		} else {
			nng_free(dest, *str_len + 1);
			dest     = NULL;
			*str_len = -1;
		}
	}
	return dest;
}

int
utf8_check(const char *str, size_t len)
{
	int i;
	int j;
	int codelen;
	int codepoint;

	const unsigned char *ustr = (const unsigned char *) str;

	if (!str)
		return ERR_INVAL;
	if (len > 65536)
		return ERR_INVAL;

	for (i = 0; i < (int) len; i++) {
		if (ustr[i] == 0) {
			return ERR_MALFORMED_UTF8;
		} else if (ustr[i] <= 0x7f) {
			codelen   = 1;
			codepoint = ustr[i];
		} else if ((ustr[i] & 0xE0) == 0xC0) {
			/* 110xxxxx - 2 byte sequence */
			if (ustr[i] == 0xC0 || ustr[i] == 0xC1) {
				/* Invalid bytes */
				return ERR_MALFORMED_UTF8;
			}
			codelen   = 2;
			codepoint = (ustr[i] & 0x1F);
		} else if ((ustr[i] & 0xF0) == 0xE0) {
			/* 1110xxxx - 3 byte sequence */
			codelen   = 3;
			codepoint = (ustr[i] & 0x0F);
		} else if ((ustr[i] & 0xF8) == 0xF0) {
			/* 11110xxx - 4 byte sequence */
			if (ustr[i] > 0xF4) {
				/* Invalid, this would produce values >
				 * 0x10FFFF. */
				return ERR_MALFORMED_UTF8;
			}
			codelen   = 4;
			codepoint = (ustr[i] & 0x07);
		} else {
			/* Unexpected continuation byte. */
			return ERR_MALFORMED_UTF8;
		}

		/* Reconstruct full code point */
		if (i == (int) len - codelen + 1) {
			/* Not enough data */
			return ERR_MALFORMED_UTF8;
		}
		for (j = 0; j < codelen - 1; j++) {
			if ((ustr[++i] & 0xC0) != 0x80) {
				/* Not a continuation byte */
				return ERR_MALFORMED_UTF8;
			}
			codepoint = (codepoint << 6) | (ustr[i] & 0x3F);
		}

		/* Check for UTF-16 high/low surrogates */
		if (codepoint >= 0xD800 && codepoint <= 0xDFFF) {
			return ERR_MALFORMED_UTF8;
		}

		/* Check for overlong or out of range encodings */
		/* Checking codelen == 2 isn't necessary here, because it is
		 *already covered above in the C0 and C1 checks. if(codelen ==
		 *2 && codepoint < 0x0080){ return ERR_MALFORMED_UTF8; }else
		 */
		if (codelen == 3 && codepoint < 0x0800) {
			return ERR_MALFORMED_UTF8;
		} else if (codelen == 4 &&
		    (codepoint < 0x10000 || codepoint > 0x10FFFF)) {
			return ERR_MALFORMED_UTF8;
		}

		/* Check for non-characters */
		if (codepoint >= 0xFDD0 && codepoint <= 0xFDEF) {
			return ERR_MALFORMED_UTF8;
		}
		if ((codepoint & 0xFFFF) == 0xFFFE ||
		    (codepoint & 0xFFFF) == 0xFFFF) {
			return ERR_MALFORMED_UTF8;
		}
		/* Check for control characters */
		if (codepoint <= 0x001F ||
		    (codepoint >= 0x007F && codepoint <= 0x009F)) {
			return ERR_MALFORMED_UTF8;
		}
	}
	return ERR_SUCCESS;
}

uint16_t
get_variable_binary(uint8_t **dest, const uint8_t *src)
{
	uint16_t len = 0;
	NNI_GET16(src, len);
	*dest = (uint8_t *) (src + 2);
	return len;
}

int
fixed_header_adaptor(uint8_t *packet, nng_msg *dst)
{
	nni_msg *m;
	int      rv;
	size_t   pos = 1;

	m = (nni_msg *) dst;
	get_var_integer(packet, (uint32_t *) &pos);

	rv = nni_msg_header_append(m, packet, pos);
	return rv;
}

/*
int variable_header_adaptor(uint8_t *packet, nni_msg *dst)
{
        nni_msg  *m;
        int      pos = 0;
        uint32_t len;
        return 0;
}
*/
/*
static char *client_id_gen(int *idlen, const char *auto_id_prefix, int
auto_id_prefix_len)
{
        char *client_id;
        return client_id;
}

conn_param * copy_conn_param(conn_param * des, conn_param * src){
        return (conn_param *)memcpy((void *)des, (const void *)src,
sizeof(struct conn_param));
}
*/

/**
 * only use in nego_cb !!!
 *
 */
int32_t
conn_handler(uint8_t *packet, conn_param *cparam)
{

	uint32_t len, tmp, pos = 0, len_of_properties = 0;
	int      len_of_str = 0, len_of_var = 0;
	int32_t  rv = 0;
	uint8_t  property_id;

	if (packet[pos] != CMD_CONNECT) {
		rv = -1;
		return rv;
	} else {
		pos++;
	}

	init_conn_param(cparam);
	// remaining length
	len = (uint32_t) get_var_integer(packet + pos, &len_of_var);
	pos += len_of_var;
	// protocol name
	cparam->pro_name.body =
	    (char *) copy_utf8_str(packet, &pos, &len_of_str);
	cparam->pro_name.len = len_of_str;
	rv                   = len_of_str < 0 ? 1 : 0;
	debug_msg("pro_name: %s", cparam->pro_name.body);
	// protocol ver
	cparam->pro_ver = packet[pos];
	pos++;
	// connect flag
	cparam->con_flag    = packet[pos];
	cparam->clean_start = (cparam->con_flag & 0x02) >> 1;
	cparam->will_flag   = (cparam->con_flag & 0x04) >> 2;
	cparam->will_qos    = (cparam->con_flag & 0x18) >> 3;
	cparam->will_retain = (cparam->con_flag & 0x20) >> 5;
	debug_msg("conn flag:%x", cparam->con_flag);
	pos++;
	// keepalive
	NNI_GET16(packet + pos, tmp);
	cparam->keepalive_mqtt = tmp;
	pos += 2;
	// properties
	if (cparam->pro_ver == PROTOCOL_VERSION_v5) {
		debug_msg("MQTT 5 Properties");
		len_of_properties   = (uint32_t) get_var_integer(packet, &pos);
		uint32_t target_pos = pos + len_of_properties;
		debug_msg("propertyLen in variable [%d]", len_of_properties);

		// parse property in variable header
		if (len_of_properties > 0) {
			while (1) {
				property_id = packet[pos++];
				switch (property_id) {
				case SESSION_EXPIRY_INTERVAL:
					debug_msg("SESSION_EXPIRY_INTERVAL");
					NNI_GET32(packet + pos,
					    cparam->session_expiry_interval);
					pos += 4;
					break;
				case RECEIVE_MAXIMUM:
					debug_msg("RECEIVE_MAXIMUM");
					NNI_GET16(
					    packet + pos, cparam->rx_max);
					pos += 2;
					break;
				case MAXIMUM_PACKET_SIZE:
					debug_msg("MAXIMUM_PACKET_SIZE");
					NNI_GET32(packet + pos,
					    cparam->max_packet_size);
					pos += 4;
					break;
				case TOPIC_ALIAS_MAXIMUM:
					debug_msg("TOPIC_ALIAS_MAXIMUM");
					NNI_GET16(packet + pos,
					    cparam->topic_alias_max);
					pos += 2;
					break;
				case REQUEST_RESPONSE_INFORMATION:
					debug_msg(
					    "REQUEST_RESPONSE_INFORMATION");
					cparam->req_resp_info = packet[pos++];
					break;
				case REQUEST_PROBLEM_INFORMATION:
					debug_msg(
					    "REQUEST_PROBLEM_INFORMATION");
					cparam->req_problem_info =
					    packet[pos++];
					break;
				case USER_PROPERTY:
					debug_msg("USER_PROPERTY");
					// key
					cparam->user_property.key =
					    (char *) copy_utf8_str(
					        packet, &pos, &len_of_str);
					cparam->user_property.len_key =
					    len_of_str;
					rv = len_of_str < 0 ? 1 : 0;
					// value
					cparam->user_property.val =
					    (char *) copy_utf8_str(
					        packet, &pos, &len_of_str);
					cparam->user_property.len_val =
					    len_of_str;
					rv = len_of_str < 0 ? 1 : 0;
					break;
				case AUTHENTICATION_METHOD:
					debug_msg("AUTHENTICATION_METHOD");
					cparam->auth_method.body =
					    (char *) copy_utf8_str(
					        packet, &pos, &len_of_str);
					rv = len_of_str < 0 ? 1 : 0;
					cparam->auth_method.len = len_of_str;
					len_of_str              = 0;
					break;
				case AUTHENTICATION_DATA:
					debug_msg("AUTHENTICATION_DATA");
					cparam->auth_data.body = copy_utf8_str(
					    packet, &pos, &len_of_str);
					rv = len_of_str < 0 ? 1 : 0;
					cparam->auth_data.len = len_of_str;
					break;
				default:
					break;
				}
				if (pos == target_pos) {
					break;
				} else if (pos > target_pos) {
					debug_msg("ERROR: protocol error");
					return PROTOCOL_ERROR;
				}
			}
		}
	}
	debug_msg("pos after property: [%d]", pos);
	// payload client_id
	cparam->clientid.body =
	    (char *) copy_utf8_str(packet, &pos, &len_of_str);
	rv                   = len_of_str < 0 ? 1 : 0;
	cparam->clientid.len = len_of_str;
	debug_msg("clientid: [%s] [%d]", cparam->clientid.body, len_of_str);
	// will topic
	if (cparam->will_flag != 0) {
		if (cparam->pro_ver == PROTOCOL_VERSION_v5) {
			len_of_properties   = get_var_integer(packet, &pos);
			uint32_t target_pos = pos + len_of_properties;
			debug_msg(
			    "propertyLen in payload [%d]", len_of_properties);

			// parse property in variable header
			if (len_of_properties > 0) {
				while (1) {
					property_id = packet[pos++];
					switch (property_id) {
					case WILL_DELAY_INTERVAL:
						debug_msg(
						    "WILL_DELAY_INTERVAL");
						NNI_GET32(packet + pos,
						    cparam
						        ->will_delay_interval);
						pos += 4;
						break;
					case PAYLOAD_FORMAT_INDICATOR:
						debug_msg("PAYLOAD_FORMAT_"
						          "INDICATOR");
						cparam
						    ->payload_format_indicator =
						    packet[pos++];
						break;
					case MESSAGE_EXPIRY_INTERVAL:
						debug_msg(
						    "MESSAGE_EXPIRY_INTERVAL");
						NNI_GET32(packet + pos,
						    cparam
						        ->msg_expiry_interval);
						pos += 4;
						break;
					case CONTENT_TYPE:
						debug_msg("CONTENT_TYPE");
						cparam->content_type.body =
						    (char *) copy_utf8_str(
						        packet, &pos,
						        &len_of_str);
						cparam->content_type.len =
						    len_of_str;
						rv = len_of_str < 0 ? 1 : 0;
						debug_msg(
						    "content type: %s %d",
						    cparam->content_type.body,
						    rv);
						break;
					case RESPONSE_TOPIC:
						debug_msg("RESPONSE_TOPIC");
						cparam->resp_topic.body =
						    (char *) copy_utf8_str(
						        packet, &pos,
						        &len_of_str);
						cparam->resp_topic.len =
						    len_of_str;
						rv = len_of_str < 0 ? 1 : 0;
						debug_msg("resp topic: %s %d",
						    cparam->resp_topic.body,
						    rv);
						break;
					case CORRELATION_DATA:
						debug_msg("CORRELATION_DATA");
						cparam->corr_data.body =
						    copy_utf8_str(packet, &pos,
						        &len_of_str);
						cparam->corr_data.len =
						    len_of_str;
						rv = len_of_str < 0 ? 1 : 0;
						debug_msg("corr_data: %s %d",
						    cparam->corr_data.body,
						    rv);
						break;
					case USER_PROPERTY:
						debug_msg("USER_PROPERTY");
						// key
						cparam->payload_user_property
						    .key =
						    (char *) copy_utf8_str(
						        packet, &pos,
						        &len_of_str);
						cparam->payload_user_property
						    .len_key = len_of_str;
						rv           = rv | len_of_str;
						// value
						cparam->payload_user_property
						    .val =
						    (char *) copy_utf8_str(
						        packet, &pos,
						        &len_of_str);
						cparam->payload_user_property
						    .len_val = len_of_str;
						rv = len_of_str < 0 ? 1 : 0;
						break;
					default:
						break;
					}
					if (pos == target_pos) {
						break;
					} else if (pos > target_pos) {
						debug_msg(
						    "ERROR: protocol error");
						return PROTOCOL_ERROR;
					}
				}
			}
		}
		cparam->will_topic.body =
		    (char *) copy_utf8_str(packet, &pos, &len_of_str);
		cparam->will_topic.len = len_of_str;
		rv                     = len_of_str < 0 ? 1 : 0;
		debug_msg("will_topic: %s %d", cparam->will_topic.body, rv);
		// will msg
		cparam->will_msg.body =
		    (char *) copy_utf8_str(packet, &pos, &len_of_str);
		cparam->will_msg.len = len_of_str;
		rv                   = len_of_str < 0 ? 1 : 0;
		debug_msg("will_msg: %s %d", cparam->will_msg.body, rv);
	}
	// username
	if ((cparam->con_flag & 0x80) > 0) {
		cparam->username.body =
		    (char *) copy_utf8_str(packet, &pos, &len_of_str);
		cparam->username.len = len_of_str;
		rv                   = len_of_str < 0 ? 1 : 0;
		debug_msg(
		    "username: %s %d", cparam->username.body, len_of_str);
	}
	// password
	if ((cparam->con_flag & 0x40) > 0) {
		cparam->password.body =
		    copy_utf8_str(packet, &pos, &len_of_str);
		cparam->password.len = len_of_str;
		rv                   = len_of_str < 0 ? 1 : 0;
		debug_msg(
		    "password: %s %d", cparam->password.body, len_of_str);
	}
	// what if rv = 0?
	if (len + len_of_var + 1 != pos) {
		debug_msg("ERROR in connect handler");
	}
	return rv;
}

void
destroy_conn_param(conn_param *cparam)
{
	if (cparam == NULL) {
		return;
	}
	debug_msg("destroy conn param");
	nng_free(cparam->pro_name.body, cparam->pro_name.len);
	nng_free(cparam->clientid.body, cparam->clientid.len);
	nng_free(cparam->will_topic.body, cparam->will_topic.len);
	nng_free(cparam->will_msg.body, cparam->will_msg.len);
	nng_free(cparam->username.body, cparam->username.len);
	nng_free(cparam->password.body, cparam->password.len);
	nng_free(cparam->auth_method.body, cparam->auth_method.len);
	nng_free(cparam->auth_data.body, cparam->auth_data.len);
	nng_free(cparam->user_property.key, cparam->user_property.len_key);
	nng_free(cparam->user_property.val, cparam->user_property.len_val);
	nng_free(cparam->content_type.body, cparam->content_type.len);
	nng_free(cparam->resp_topic.body, cparam->resp_topic.len);
	nng_free(cparam->corr_data.body, cparam->corr_data.len);
	nng_free(cparam->payload_user_property.key,
	    cparam->payload_user_property.len_key);
	nng_free(cparam->payload_user_property.val,
	    cparam->payload_user_property.len_val);
	nng_free(cparam, sizeof(struct conn_param));
	cparam = NULL;
}

void
init_conn_param(conn_param *cparam)
{
	cparam->pro_name.len                  = 0;
	cparam->pro_name.body                 = NULL;
	cparam->clientid.len                  = 0;
	cparam->clientid.body                 = NULL;
	cparam->will_topic.body               = NULL;
	cparam->will_topic.len                = 0;
	cparam->will_msg.body                 = NULL;
	cparam->will_msg.len                  = 0;
	cparam->username.body                 = NULL;
	cparam->username.len                  = 0;
	cparam->password.body                 = NULL;
	cparam->password.len                  = 0;
	cparam->auth_method.body              = NULL;
	cparam->auth_method.len               = 0;
	cparam->auth_data.body                = NULL;
	cparam->auth_data.len                 = 0;
	cparam->user_property.key             = NULL;
	cparam->user_property.len_key         = 0;
	cparam->user_property.val             = NULL;
	cparam->user_property.len_val         = 0;
	cparam->content_type.body             = NULL;
	cparam->content_type.len              = 0;
	cparam->resp_topic.body               = NULL;
	cparam->resp_topic.len                = 0;
	cparam->corr_data.body                = NULL;
	cparam->corr_data.len                 = 0;
	cparam->payload_user_property.key     = NULL;
	cparam->payload_user_property.len_key = 0;
	cparam->payload_user_property.val     = NULL;
	cparam->payload_user_property.len_val = 0;
}

uint32_t
DJBHash(char *str)
{
	unsigned int hash = 5381;
	while (*str) {
		hash = ((hash << 5) + hash) + (*str++); /* times 33 */
	}
	hash &= ~(1 << 31); /* strip the highest bit */
	return hash;
}

uint32_t
DJBHashn(char *str, uint16_t len)
{
	unsigned int hash = 5381;
	uint16_t     i    = 0;
	while (i < len) {
		hash = ((hash << 5) + hash) + (*str++); /* times 33 */
		i++;
	}
	hash &= ~(1 << 31); /* strip the highest bit */
	return hash;
}

uint64_t
nano_hash(char *str)
{
	uint64_t hash = 5381;
	int      c;

	while ((c = *str++))
		hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
	                                         // hash = hash * 33 + c;
	return hash;
}

void
nano_msg_set_dup(nng_msg *msg)
{
	uint8_t *header;

	header  = nni_msg_header(msg);
	*header = *header | 0x08;
}

// alloc a publish msg according to the need
nng_msg *
nano_msg_composer(
    uint8_t retain, uint8_t qos, mqtt_string *payload, mqtt_string *topic)
{
	size_t   rlen;
	uint8_t *ptr, buf[5] = { '\0' };
	uint32_t len;
	nni_msg *msg;

	len = payload->len + topic->len + 2;
	if (qos > 0) {
		nni_msg_alloc(&msg, len + 2);
		rlen = put_var_integer(buf + 1, len + 2);
		nni_msg_set_remaining_len(msg, len + 2);
		if (qos == 1) {
			buf[0] = CMD_PUBLISH | 0x02;
		} else if (qos == 2) {
			buf[0] = CMD_PUBLISH | 0x04;
		} else {
			nni_println("ERROR: will msg qos invalid");
			return NULL;
		}
	} else {
		nni_msg_alloc(&msg, len);
		rlen = put_var_integer(buf + 1, len);
		nni_msg_set_remaining_len(msg, len);
		buf[0] = CMD_PUBLISH;
	}
	ptr = nni_msg_header(msg);
	if (retain > 0) {
		buf[0] = buf[0] | 0x01;
	}
	memcpy(ptr, buf, rlen + 1);

	ptr = nni_msg_body(msg);
	NNI_PUT16(ptr, topic->len);
	ptr = ptr + 2;
	memcpy(ptr, topic->body, topic->len);
	ptr += topic->len;
	if (qos > 0) {
		// Set pid?
		NNI_PUT16(ptr, 0x10);
		ptr = ptr + 2;
	}
	memcpy(ptr, payload->body, payload->len);
	nni_msg_set_payload_ptr(msg, ptr);

	return msg;
}

uint8_t
verify_connect(conn_param *cparam, conf *conf)
{
	int   i, n = conf->auths.count;
	char *username = cparam->username.body;
	char *password = cparam->password.body;

	if (conf->auths.count == 0 || conf->allow_anonymous == true) {
		debug_msg("WARNING: no valid entry in "
		          "etc/nanomq_auth_username.conf.");
		return 0;
	}

	if (cparam->username.len == 0 || cparam->password.len == 0) {
		if (cparam->pro_ver == 5) {
			return BAD_USER_NAME_OR_PASSWORD;
		} else {
			return 0x04;
		}
	}

	for (i = 0; i < n; i++) {
		if (strcmp(username, conf->auths.usernames[i]) == 0 &&
		    strcmp(password, conf->auths.passwords[i]) == 0) {
			return 0;
		}
	}
	if (cparam->pro_ver == 5) {
		return BAD_USER_NAME_OR_PASSWORD;
	} else {
		return 0x05;
	}
}

nng_msg *
nano_msg_notify_disconnect(conn_param *cparam, uint8_t code)
{
	nni_msg *   msg;
	mqtt_string string, topic;
	uint8_t     buff[256];
	snprintf(buff, 256, DISCONNECT_MSG, cparam->username.body,
	    (uint64_t) nni_clock(), code, cparam->clientid.body);
	string.body = buff;
	string.len  = strlen(string.body);
	topic.body = DISCONNECT_TOPIC;
	topic.len  = strlen(DISCONNECT_TOPIC);
	msg        = nano_msg_composer(0, 0, &string, &topic);
	return msg;
}

nng_msg *
nano_msg_notify_connect(conn_param *cparam, uint8_t code)
{
	nni_msg *   msg;
	mqtt_string string, topic;
	uint8_t     buff[256];
	snprintf(buff, 256, CONNECT_MSG, cparam->username.body,
	    (uint64_t) nni_clock(), cparam->pro_name.body, cparam->keepalive_mqtt, code, cparam->pro_ver, cparam->clientid.body, cparam->clean_start);
	string.body = buff;
	string.len  = strlen(string.body);
	topic.body = CONNECT_TOPIC;
	topic.len  = strlen(CONNECT_TOPIC);
	msg        = nano_msg_composer(0, 0, &string, &topic);
	return msg;
}