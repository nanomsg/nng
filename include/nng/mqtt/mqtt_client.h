//
// Copyright 2021 Staysail Systems, Inc. <info@staysail.tech>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

// This file is for the MQTT client implementation.
// Note that while there are some similarities, MQTT is sufficiently
// different enough from SP that many of the APIs cannot be easily
// shared.
//
// At this time there is no server provided by NNG itself, although
// the nanomq project provides such a server (and is based on NNG.)
//
// About our semantics:
//
// 1. MQTT client sockets have a single implicit dialer, and cannot
//    support creation of additional dialers or listeners.
// 2. MQTT client sockets do support contexts; each context will
//    maintain its own subscriptions, and the socket will keep a
//    per-socket list of them and manage the full list.
// 3. Send sends PUBLISH messages.
// 4. Receive is used to receive published data from the server.
// 5. Most of the MQTT specific "features" are as options on the socket,
//    dialer, or even the message.  (For example message topics are set
//    as options on the message.)
// 6. Pipe events can be used to detect connect/disconnect events.
// 7. Any QoS details such as retransmit, etc. are handled under the hood.
//    This includes packet IDs.
// 8. PING and keep-alive is handled under the hood.
// 9. For publish actions, a separate method is used (not send/receive).

#ifndef NNG_MQTT_CLIENT_H
#define NNG_MQTT_CLIENT_H

#include <nng/nng.h>
#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// NNG_OPT_MQTT_EXPIRES is a 32-bit integer representing the expiration in
// seconds. This can be applied to a message.
// (TODO: What about session expiry?)
#define NNG_OPT_MQTT_EXPIRES "expires"

// NNG_OPT_MQTT_QOS is a byte (only lower two bits significant) representing
// the quality of service.  At this time, only level zero is supported.
// TODO: level 1 and level 2 QoS
#define NNG_OPT_MQTT_QOS "qos"

// NNG_OPT_MQTT_RETAIN indicates that the message should be retained on
// the server as the single retained message for the associated topic.
// This is a boolean.
#define NNG_OPT_MQTT_RETAIN "retain"

// NNG_OPT_MQTT_DUP indicates that the message is a duplicate. This can
// only be returned on a message -- this client will add this flag if
// sending a duplicate message (QoS 1 and 2 only).
#define NNG_OPT_MQTT_DUP "dup"

// NNG_OPT_MQTT_TOPIC is the message topic.  It is encoded as an "Encoded
// UTF-8 string" (uint16 length followed by UTF-8 data).  At the API, it
// is just a UTF-8 string (C style, with a terminating byte.)  Note that
// we do not support embedded NUL bytes in our UTF-8 strings.  Every
// MQTT published message must have a topic.
#define NNG_OPT_MQTT_TOPIC "topic"

// NNG_OPT_MQTT_REASon is a reason that can be conveyed with a message.
// It is a UTF-8 string.
#define NNG_OPT_MQTT_REASON "reason"

// NNG_OPT_MQTT_USER_PROPS is an array of user properties. These are
// send with the message, and used for application specific purposes.
// The properties are of the type nng_mqtt_user_props_t.
#define NNG_OPT_MQTT_USER_PROPS "user-props"

// NNG_OPT_MQTT_PAYLOAD_FORMAT is the format of the payload for a message.
// It can be 0, indicating binary data, or 1, indicating UTF-8.
#define NNG_OPT_MQTT_PAYLOAD_FORMAT "mqtt-payload-format"

// NNG_OPT_MQTT_CONTENT_TYPE is the mime type as UTF-8 for PUBLISH
// or Will messages.
#define NNG_OPT_MQTT_CONTENT_TYPE "content-type"

// The following options are reserved for MQTT v5.0 request/reply support.
#define NNG_OPT_MQTT_RESPONSE_TOPIC "response-topic"
#define NNG_OPT_MQTT_CORRELATION_DATA "correlation-data"

// NNG_OPT_MQTT_CLIENT_ID is the UTF-8 string corresponding to the client
// identification.  We automatically generate an initial value fo this,
// which is the UUID.
// TODO: Should applications be permitted to change this?
#define NNG_OPT_MQTT_CLIENT_ID "client-id" // UTF-8 string

#define NNG_OPT_MQTT_WILL_DELAY "will-delay"

// NNG_OPT_MQTT_RECEIVE_MAX is used with QoS 1 or 2 (not implemented),
// and indicates the level of concurrent receives it is willing to
// process. (TODO: Implementation note: we will need to preallocate a complete
// state machine (aio, plus any state) for each value of this > 0.
// It's not clear whether this should be tunable.)  This is read-only
// property on the socket, and records the value given from the server.
// It will be 64K if the server did not indicate a specific value.
#define NNG_OPT_MQTT_RECEIVE_MAX "mqtt-receive-max"

// NNG_OPT_MQTT_SESSION_EXPIRES is an nng_duration.
// If set to NNG_DURATION_ZERO, then the session will expire automatically
// when the connection is closed.
// If it set to NNG_DURATION_INFINITE, the session never expires.
// Otherwise it will be a whole number of seconds indicating the session
// expiry interval.
#define NNG_OPT_MQTT_SESSION_EXPIRES "session-expires"

#define NNG_OPT_MQTT_TOPIC_ALIAS_MAX "alias-max"
#define NNG_OPT_MQTT_TOPIC_ALIAS "topic-alias"
#define NNG_OPT_MQTT_MAX_QOS "max-qos"

// NNG_MAX_RECV_LMQ and NNG_MAX_SEND_LMQ define the length of waiting queue
// they are the length of nni_lmq, please be ware it affects the memory usage
// significantly while having heavy throughput
#define NNG_MAX_RECV_LMQ 16
#define NNG_MAX_SEND_LMQ 16
#define NNG_TRAN_MAX_LMQ_SIZE 128

// NNG_TLS_xxx options can be set on the client as well.
// E.g. NNG_OPT_TLS_CA_CERT, etc.

// TBD: Extended authentication.  I think we should skip it -- everyone
// should just use TLS if they need security.

// NNG_OPT_MQTT_KEEP_ALIVE is set on the client, and can be retrieved
// by the client.  This is an nng_duration but will always be zero or
// a whole number of seconds less than 65536.  If setting the value,
// it must be set before the client connects.  When retrieved, the
// server's value will be returned (if it is different from what we
// requested.)  If we reconnect, we will try again with the configured
// value rather than the value that we got from the server last time.
#define NNG_OPT_MQTT_KEEP_ALIVE "mqtt-keep-alive"

// NNG_OPT_MQTT_MAX_PACKET_SIZE is the maximum packet size that can
// be used.  It needs to be set before the client dials.
#define NNG_OPT_MQTT_MAX_PACKET_SIZE "mqtt-max-packet-size"
#define NNG_OPT_MQTT_USERNAME "username"
#define NNG_OPT_MQTT_PASSWORD "password"

// Note that MQTT sockets can be connected to at most a single server.
// Creating the client does not connect it.
NNG_DECL int nng_mqtt_client_open(nng_socket *);

// Note that there is a single implicit dialer for the client,
// and options may be set on the socket to configure dial options.
// Those options should be set before doing nng_dial().

// close done via nng_close().

// Question: session resumption.  Should we resume sessions under the hood
// as part of reconnection, or do we want to expose this to the API user?
// My inclination is not to expose.

// nng_dial or nng_dialer_create can be used, but this protocol only
// allows a single dialer to be created on the socket.

// Subscriptions are normally run synchronously from the view of the
// caller.  Because there is a round-trip message involved, we use
// a separate method instead of merely relying upon socket options.
// TODO: shared subscriptions.  Subscription options (retain, QoS)
NNG_DECL int nng_mqtt_subscribe(nng_socket, const char *);
NNG_DECL int nng_mqtt_subscribe_aio(nng_socket, const char *, nng_aio *);
NNG_DECL int nng_mqtt_unsubscribe(nng_socket *, const char *);
NNG_DECL int nng_mqtt_unsubscribe_aio(nng_socket *, const char *, nng_aio *);
// as with other ctx based methods, we use the aio form exclusively
NNG_DECL int nng_mqtt_ctx_subscribe(nng_ctx *, const char *, nng_aio *, ...);

// Message handling.  Note that topic aliases are handled by the library
// automatically on behalf of the consumer.

typedef enum {
	nng_mqtt_msg_format_binary = 0,
	nng_mqtt_msg_format_utf8   = 1,
} nng_mqtt_msg_format_t;

// Message options.  These are convenience wrappers around the above
// options.

NNG_DECL int nng_mqtt_set_msg_expiry(nng_msg *, nng_duration);
NNG_DECL int nng_mqtt_get_msg_expiry(nng_msg *, nng_duration *);
NNG_DECL int nng_mqtt_set_msg_format(nng_msg *, nng_mqtt_msg_format_t);
NNG_DECL int nng_mqtt_get_msg_format(nng_msg *, nng_mqtt_msg_format_t *);
NNG_DECL int nng_mqtt_set_msg_topic(nng_msg *, const char *);
NNG_DECL int nng_mqtt_set_msg_qos(nng_msg *, int);
NNG_DECL int nng_mqtt_get_msg_topic(nng_msg *, const char **);
NNG_DECL int nng_mqtt_get_msg_qos(nng_msg *, int *);
NNG_DECL int nng_mqtt_set_content_type(nng_msg *, const char *);
NNG_DECL int nng_mqtt_get_content_type(nng_msg *, const char **);
NNG_DECL int nng_mqtt_get_reason(nng_msg *, const char **);

// User property support.
typedef struct {
	const char *up_name;
	const char *up_value;
} nng_mqtt_user_prop_t;

typedef struct {
	int                   up_count;
	nng_mqtt_user_prop_t *up_props;
} nng_mqtt_user_props_t;

extern int nng_mqtt_user_props_alloc(nng_mqtt_user_props_t **);
extern int nng_mqtt_user_props_add(
    nng_mqtt_user_props_t *, const char *, const char *);
extern void nng_mqtt_user_props_free(nng_mqtt_user_props_t *);

#define NNG_OPT_MQTT_CONNMSG "mqtt-connect-msg"

typedef enum {
	NNG_MQTT_CONNECT     = 0x01,
	NNG_MQTT_CONNACK     = 0x02,
	NNG_MQTT_PUBLISH     = 0x03,
	NNG_MQTT_PUBACK      = 0x04,
	NNG_MQTT_PUBREC      = 0x05,
	NNG_MQTT_PUBREL      = 0x06,
	NNG_MQTT_PUBCOMP     = 0x07,
	NNG_MQTT_SUBSCRIBE   = 0x08,
	NNG_MQTT_SUBACK      = 0x09,
	NNG_MQTT_UNSUBSCRIBE = 0x0A,
	NNG_MQTT_UNSUBACK    = 0x0B,
	NNG_MQTT_PINGREQ     = 0x0C,
	NNG_MQTT_PINGRESP    = 0x0D,
	NNG_MQTT_DISCONNECT  = 0x0E,
	NNG_MQTT_AUTH        = 0x0F
} nng_mqtt_packet_type;

struct mqtt_buf_t {
	uint32_t length;
	uint8_t *buf;
};

typedef struct mqtt_buf_t mqtt_buf;
typedef struct mqtt_buf_t nng_mqtt_buffer;
typedef struct mqtt_buf_t nng_mqtt_topic;

typedef struct mqtt_topic_qos_t {
	nng_mqtt_topic topic;
	uint8_t        qos;
} mqtt_topic_qos;

typedef struct mqtt_topic_qos_t nng_mqtt_topic_qos;

NNG_DECL int  nng_mqtt_msg_alloc(nng_msg **, size_t);
NNG_DECL int  nng_mqtt_msg_proto_data_alloc(nng_msg *);
NNG_DECL void nng_mqtt_msg_proto_data_free(nng_msg *);
NNG_DECL int  nng_mqtt_msg_encode(nng_msg *);
NNG_DECL int  nng_mqtt_msg_decode(nng_msg *);
NNG_DECL void nng_mqtt_msg_set_packet_type(nng_msg *, nng_mqtt_packet_type);
NNG_DECL nng_mqtt_packet_type nng_mqtt_msg_get_packet_type(nng_msg *);
NNG_DECL void nng_mqtt_msg_set_connect_proto_version(nng_msg *, uint8_t);
NNG_DECL void nng_mqtt_msg_set_connect_keep_alive(nng_msg *, uint16_t);
NNG_DECL void nng_mqtt_msg_set_connect_client_id(nng_msg *, const char *);
NNG_DECL void nng_mqtt_msg_set_connect_user_name(nng_msg *, const char *);
NNG_DECL void nng_mqtt_msg_set_connect_password(nng_msg *, const char *);
NNG_DECL void nng_mqtt_msg_set_connect_clean_session(nng_msg *, bool);
NNG_DECL void nng_mqtt_msg_set_connect_will_topic(nng_msg *, const char *);
NNG_DECL void nng_mqtt_msg_set_connect_will_msg(
    nng_msg *, uint8_t *, uint32_t);
NNG_DECL void        nng_mqtt_msg_set_connect_will_retain(nng_msg *, bool);
NNG_DECL void        nng_mqtt_msg_set_connect_will_qos(nng_msg *, uint8_t);
NNG_DECL const char *nng_mqtt_msg_get_connect_user_name(nng_msg *);
NNG_DECL const char *nng_mqtt_msg_get_connect_password(nng_msg *);
NNG_DECL bool        nng_mqtt_msg_get_connect_clean_session(nng_msg *);
NNG_DECL uint8_t     nng_mqtt_msg_get_connect_proto_version(nng_msg *);
NNG_DECL uint16_t    nng_mqtt_msg_get_connect_keep_alive(nng_msg *);
NNG_DECL const char *nng_mqtt_msg_get_connect_client_id(nng_msg *);
NNG_DECL const char *nng_mqtt_msg_get_connect_will_topic(nng_msg *);
NNG_DECL uint8_t *   nng_mqtt_msg_get_connect_will_msg(nng_msg *, uint32_t *);
NNG_DECL bool        nng_mqtt_msg_get_connect_will_retain(nng_msg *);
NNG_DECL uint8_t     nng_mqtt_msg_get_connect_will_qos(nng_msg *);
NNG_DECL void        nng_mqtt_msg_set_connack_return_code(nng_msg *, uint8_t);
NNG_DECL void        nng_mqtt_msg_set_connack_flags(nng_msg *, uint8_t);
NNG_DECL uint8_t     nng_mqtt_msg_get_connack_return_code(nng_msg *);
NNG_DECL uint8_t     nng_mqtt_msg_get_connack_flags(nng_msg *);
NNG_DECL void        nng_mqtt_msg_set_publish_qos(nng_msg *, uint8_t);
NNG_DECL uint8_t     nng_mqtt_msg_get_publish_qos(nng_msg *);
NNG_DECL void        nng_mqtt_msg_set_publish_retain(nng_msg *, bool);
NNG_DECL bool        nng_mqtt_msg_get_publish_retain(nng_msg *);
NNG_DECL void        nng_mqtt_msg_set_publish_dup(nng_msg *, bool);
NNG_DECL bool        nng_mqtt_msg_get_publish_dup(nng_msg *);
NNG_DECL void        nng_mqtt_msg_set_publish_topic(nng_msg *, const char *);
NNG_DECL const char *nng_mqtt_msg_get_publish_topic(nng_msg *, uint32_t *);
NNG_DECL void nng_mqtt_msg_set_publish_payload(nng_msg *, uint8_t *, uint32_t);
NNG_DECL uint8_t *nng_mqtt_msg_get_publish_payload(nng_msg *, uint32_t *);
NNG_DECL nng_mqtt_topic_qos *nng_mqtt_msg_get_subscribe_topics(
    nng_msg *, uint32_t *);
NNG_DECL void nng_mqtt_msg_set_subscribe_topics(
    nng_msg *, nng_mqtt_topic_qos *, uint32_t);
NNG_DECL void nng_mqtt_msg_set_suback_return_codes(
    nng_msg *, uint8_t *, uint32_t);
NNG_DECL uint8_t *nng_mqtt_msg_get_suback_return_codes(nng_msg *, uint32_t *);
NNG_DECL void     nng_mqtt_msg_set_unsubscribe_topics(
        nng_msg *, nng_mqtt_topic *, uint32_t);
NNG_DECL nng_mqtt_topic *nng_mqtt_msg_get_unsubscribe_topics(
    nng_msg *, uint32_t *);

NNG_DECL nng_mqtt_topic *nng_mqtt_topic_array_create(size_t);
NNG_DECL void nng_mqtt_topic_array_set(nng_mqtt_topic *, size_t, const char *);
NNG_DECL void nng_mqtt_topic_array_free(nng_mqtt_topic *, size_t);
NNG_DECL nng_mqtt_topic_qos *nng_mqtt_topic_qos_array_create(size_t);
NNG_DECL void                nng_mqtt_topic_qos_array_set(
                   nng_mqtt_topic_qos *, size_t, const char *, uint8_t);
NNG_DECL void nng_mqtt_topic_qos_array_free(nng_mqtt_topic_qos *, size_t);
NNG_DECL int  nng_mqtt_set_connect_cb(nng_socket, nng_pipe_cb, void *);
NNG_DECL int  nng_mqtt_set_disconnect_cb(nng_socket, nng_pipe_cb, void *);
NNG_DECL void nng_mqtt_msg_dump(nng_msg *, uint8_t *, uint32_t, bool);

#ifdef __cplusplus
}
#endif

#endif // NNG_MQTT_CLIENT_H
