//
// Copyright 2020 NanoMQ Team, Inc. <jaylin@emqx.io>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#ifndef MQTT_PROTOCOL_H
#define MQTT_PROTOCOL_H

#define PROTOCOL_NAME_v31 "MQIsdp"
#define PROTOCOL_VERSION_v31 3

#define PROTOCOL_NAME "MQTT"

#define PROTOCOL_VERSION_v311 4
#define PROTOCOL_VERSION_v5 5

/* Length defination */
#define NANO_MAX_PACKET_LEN NNI_NANO_MAX_PACKET_SIZE
#define NANO_MIN_PACKET_LEN sizeof(uint8_t) * 8
#define NANO_CONNECT_PACKET_LEN sizeof(uint8_t) * 12
#define NANO_MIN_FIXED_HEADER_LEN sizeof(uint8_t) * 2


#ifdef NANO_PACKET_SIZE
#define NNI_NANO_MAX_PACKET_SIZE sizeof(uint8_t) * NANO_PACKET_SIZE
#else
#define NNI_NANO_MAX_PACKET_SIZE sizeof(uint8_t) * 12
#endif

/* Message types & flags */
#define CMD_UNKNOWN 0x00
#define CMD_CONNECT 0x10
#define CMD_CONNACK 0x20
#define CMD_PUBLISH 0x30
#define CMD_PUBACK 0x40
#define CMD_PUBREC 0x50
#define CMD_PUBREL 0x60
#define CMD_PUBCOMP 0x70
#define CMD_SUBSCRIBE 0x80
#define CMD_SUBACK 0x90
#define CMD_UNSUBSCRIBE 0xA0
#define CMD_UNSUBACK 0xB0
#define CMD_PINGREQ 0xC0
#define CMD_PINGRESP 0xD0
#define CMD_DISCONNECT 0xE0
#define CMD_AUTH_V5 0xF0
#define CMD_PUBLISH_V5 0x31
#define CMD_DISCONNECT_EV 0xE2
#define CMD_LASTWILL 0XE3

/* Error values */
enum err_t {
	ERR_AUTH_CONTINUE      = -4,
	ERR_NO_SUBSCRIBERS     = -3,
	ERR_SUB_EXISTS         = -2,
	ERR_CONN_PENDING       = -1,
	ERR_SUCCESS            = 0,
	ERR_NOMEM              = 1,
	ERR_PROTOCOL           = 2,
	ERR_INVAL              = 3,
	ERR_NO_CONN            = 4,
	ERR_CONN_REFUSED       = 5,
	ERR_NOT_FOUND          = 6,
	ERR_CONN_LOST          = 7,
	ERR_TLS                = 8,
	ERR_PAYLOAD_SIZE       = 9,
	ERR_NOT_SUPPORTED      = 10,
	ERR_AUTH               = 11,
	ERR_ACL_DENIED         = 12,
	ERR_UNKNOWN            = 13,
	ERR_ERRNO              = 14,
	ERR_EAI                = 15,
	ERR_PROXY              = 16,
	ERR_PLUGIN_DEFER       = 17,
	ERR_MALFORMED_UTF8     = 18,
	ERR_KEEPALIVE          = 19,
	ERR_LOOKUP             = 20,
	ERR_MALFORMED_PACKET   = 21,
	ERR_DUPLICATE_PROPERTY = 22,
	ERR_TLS_HANDSHAKE      = 23,
	ERR_QOS_NOT_SUPPORTED  = 24,
	ERR_OVERSIZE_PACKET    = 25,
	ERR_OCSP               = 26,
};

typedef enum {
	SUCCESS                                = 0,
	NORMAL_DISCONNECTION                   = 0,
	GRANTED_QOS_0                          = 0,
	GRANTED_QOS_1                          = 1,
	GRANTED_QOS_2                          = 2,
	DISCONNECT_WITH_WILL_MESSAGE           = 4,
	NO_MATCHING_SUBSCRIBERS                = 16,
	NO_SUBSCRIPTION_EXISTED                = 17,
	CONTINUE_AUTHENTICATION                = 24,
	RE_AUTHENTICATE                        = 25,
	UNSPECIFIED_ERROR                      = 128,
	MALFORMED_PACKET                       = 129,
	PROTOCOL_ERROR                         = 130,
	IMPLEMENTATION_SPECIFIC_ERROR          = 131,
	UNSUPPORTED_PROTOCOL_VERSION           = 132,
	CLIENT_IDENTIFIER_NOT_VALID            = 133,
	BAD_USER_NAME_OR_PASSWORD              = 134,
	NOT_AUTHORIZED                         = 135,
	SERVER_UNAVAILABLE                     = 136,
	SERVER_BUSY                            = 137,
	BANNED                                 = 138,
	SERVER_SHUTTING_DOWN                   = 139,
	BAD_AUTHENTICATION_METHOD              = 140,
	KEEP_ALIVE_TIMEOUT                     = 141,
	SESSION_TAKEN_OVER                     = 142,
	TOPIC_FILTER_INVALID                   = 143,
	TOPIC_NAME_INVALID                     = 144,
	PACKET_IDENTIFIER_IN_USE               = 145,
	PACKET_IDENTIFIER_NOT_FOUND            = 146,
	RECEIVE_MAXIMUM_EXCEEDED               = 147,
	TOPIC_ALIAS_INVALID                    = 148,
	PACKET_TOO_LARGE                       = 149,
	MESSAGE_RATE_TOO_HIGH                  = 150,
	QUOTA_EXCEEDED                         = 151,
	ADMINISTRATIVE_ACTION                  = 152,
	PAYLOAD_FORMAT_INVALID                 = 153,
	RETAIN_NOT_SUPPORTED                   = 154,
	QOS_NOT_SUPPORTED                      = 155,
	USE_ANOTHER_SERVER                     = 156,
	SERVER_MOVED                           = 157,
	SHARED_SUBSCRIPTIONS_NOT_SUPPORTED     = 158,
	CONNECTION_RATE_EXCEEDED               = 159,
	MAXIMUM_CONNECT_TIME                   = 160,
	SUBSCRIPTION_IDENTIFIERS_NOT_SUPPORTED = 161,
	WILDCARD_SUBSCRIPTIONS_NOT_SUPPORTED   = 162

} reason_code;

typedef enum {
	PAYLOAD_FORMAT_INDICATOR          = 1,
	MESSAGE_EXPIRY_INTERVAL           = 2,
	CONTENT_TYPE                      = 3,
	RESPONSE_TOPIC                    = 8,
	CORRELATION_DATA                  = 9,
	SUBSCRIPTION_IDENTIFIER           = 11,
	SESSION_EXPIRY_INTERVAL           = 17,
	ASSIGNED_CLIENT_IDENTIFIER        = 18,
	SERVER_KEEP_ALIVE                 = 19,
	AUTHENTICATION_METHOD             = 21,
	AUTHENTICATION_DATA               = 22,
	REQUEST_PROBLEM_INFORMATION       = 23,
	WILL_DELAY_INTERVAL               = 24,
	REQUEST_RESPONSE_INFORMATION      = 25,
	RESPONSE_INFORMATION              = 26,
	SERVER_REFERENCE                  = 28,
	REASON_STRING                     = 31,
	RECEIVE_MAXIMUM                   = 33,
	TOPIC_ALIAS_MAXIMUM               = 34,
	TOPIC_ALIAS                       = 35,
	PUBLISH_MAXIMUM_QOS               = 36,
	RETAIN_AVAILABLE                  = 37,
	USER_PROPERTY                     = 38,
	MAXIMUM_PACKET_SIZE               = 39,
	WILDCARD_SUBSCRIPTION_AVAILABLE   = 40,
	SUBSCRIPTION_IDENTIFIER_AVAILABLE = 41,
	SHARED_SUBSCRIPTION_AVAILABLE     = 42
} properties_type;

// MQTT Control Packet types
typedef enum {
	RESERVED    = 0,
	CONNECT     = 1,
	CONNACK     = 2,
	PUBLISH     = 3,
	PUBACK      = 4,
	PUBREC      = 5,
	PUBREL      = 6,
	PUBCOMP     = 7,
	SUBSCRIBE   = 8,
	SUBACK      = 9,
	UNSUBSCRIBE = 10,
	UNSUBACK    = 11,
	PINGREQ     = 12,
	PINGRESP    = 13,
	DISCONNECT  = 14,
	AUTH        = 15
} mqtt_control_packet_types;

#endif
