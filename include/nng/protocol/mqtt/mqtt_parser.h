
#ifndef NNG_MQTT_H
#define NNG_MQTT_H

#include <conf.h>
#include <nng/nng.h>
#include <packet.h>
#include <stdlib.h>

#define DISCONNECT_MSG          \
	"{\"username\":\"%s\"," \
	"\"ts\":%lu,\"reason_code\":\"%x\",\"client_id\":\"%s\"}"

#define CONNECT_MSG                                                          \
	"{\"username\":\"%s\", "                                             \
	"\"ts\":%lu,\"proto_name\":\"%s\",\"keepalive\":%d,\"return_code\":" \
	"\"%x\",\"proto_ver\":%d,\"client_id\":\"%s\", \"clean_start\":%d}"

#define DISCONNECT_TOPIC "$SYS/brokers/disconnected"

#define CONNECT_TOPIC "$SYS/brokers/connected"

// Variables & Structs
typedef struct pub_extra pub_extra;

// int hex_to_oct(char *str);
// uint32_t htoi(char *str);

extern pub_extra *pub_extra_alloc(pub_extra *);
extern void       pub_extra_free(pub_extra *);
extern uint8_t    pub_extra_get_qos(pub_extra *);
extern uint16_t   pub_extra_get_packet_id(pub_extra *);
extern void       pub_extra_set_qos(pub_extra *, uint8_t);
extern void *     pub_extra_get_msg(pub_extra *);
extern void       pub_extra_set_msg(pub_extra *, void *);
extern void       pub_extra_set_packet_id(pub_extra *, uint16_t);

// MQTT CONNECT
int32_t conn_handler(uint8_t *packet, conn_param *conn_param);
int     new_conn_param(conn_param **cparam);
void    init_conn_param(conn_param *cparam);
void    destroy_conn_param(conn_param *cparam);
void    deep_copy_conn_param(conn_param *new_cp, conn_param *cp);
int     fixed_header_adaptor(uint8_t *packet, nng_msg *dst);
int     ws_fixed_header_adaptor(uint8_t *packet, nng_msg *dst);

// parser
NNG_DECL uint8_t put_var_integer(uint8_t *dest, uint32_t value);

NNG_DECL uint32_t get_var_integer(const uint8_t *buf, uint32_t *pos);

NNG_DECL int32_t get_utf8_str(char **dest, const uint8_t *src, uint32_t *pos);
NNG_DECL uint8_t *copy_utf8_str(
    const uint8_t *src, uint32_t *pos, int *str_len);

NNG_DECL int utf8_check(const char *str, size_t length);

NNG_DECL uint16_t get_variable_binary(uint8_t **dest, const uint8_t *src);

NNG_DECL uint32_t DJBHash(char *str);
NNG_DECL uint32_t DJBHashn(char *str, uint16_t len);
NNG_DECL uint64_t nano_hash(char *str);
NNG_DECL uint8_t  verify_connect(conn_param *cparam, conf *conf);

// repack
NNG_DECL void nano_msg_set_dup(nng_msg *msg);
NNG_DECL nng_msg *nano_msg_composer(
    nng_msg **, uint8_t retain, uint8_t qos, mqtt_string *payload, mqtt_string *topic);
NNG_DECL nng_msg *nano_msg_notify_disconnect(conn_param *cparam, uint8_t code);
NNG_DECL nng_msg *nano_msg_notify_connect(conn_param *cparam, uint8_t code);
NNG_DECL nano_pipe_db *nano_msg_get_subtopic(
    nng_msg *msg, nano_pipe_db *root, conn_param *cparam);
NNG_DECL void nano_msg_free_pipedb(nano_pipe_db *db);
NNG_DECL void nano_msg_ubsub_free(nano_pipe_db *db);

#endif // NNG_MQTT_H
