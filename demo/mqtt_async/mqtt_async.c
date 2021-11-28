#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <nng/mqtt/mqtt_client.h>
#include <nng/nng.h>
#include <nng/supplemental/tls/tls.h>
#include <nng/supplemental/util/platform.h>

#ifndef PARALLEL
#define PARALLEL 32
#endif

struct work {
	enum { INIT, RECV, WAIT, SEND } state;
	nng_aio *aio;
	nng_msg *msg;
	nng_ctx  ctx;
	uint32_t index;
};

#define SUB_TOPIC1 "/nanomq/msg/1"
#define SUB_TOPIC2 "/nanomq/msg/2"
#define SUB_TOPIC3 "/nanomq/msg/3"
#define SUB_TOPIC4 "/nanomq/msg/4"

// Mqtt subscribe array of topic with qos
static nng_mqtt_topic_qos topic_qos[] = {
	{ .qos     = 0,
	    .topic = { .buf = (uint8_t *) SUB_TOPIC1,
	        .length     = strlen(SUB_TOPIC1) } },
	{ .qos     = 1,
	    .topic = { .buf = (uint8_t *) SUB_TOPIC2,
	        .length     = strlen(SUB_TOPIC2) } },
	{ .qos     = 2,
	    .topic = { .buf = (uint8_t *) SUB_TOPIC3,
	        .length     = strlen(SUB_TOPIC3) } },
	{ .qos     = 0,
	    .topic = { .buf = (uint8_t *) SUB_TOPIC4,
	        .length     = strlen(SUB_TOPIC4) } }
};

static size_t topic_qos_count = sizeof(topic_qos) / sizeof(nng_mqtt_topic_qos);

void
fatal(const char *msg, int rv)
{
	fprintf(stderr, "%s: %s\n", msg, nng_strerror(rv));
	exit(1);
}

void
client_cb(void *arg)
{
	struct work *work = arg;
	nng_msg *    msg;
	int          rv;

	switch (work->state) {
	case INIT:
		if (work->index == 0) {
			// Send subscribe message by work[0]
			nng_mqtt_msg_alloc(&msg, 0);
			nng_mqtt_msg_set_packet_type(msg, NNG_MQTT_SUBSCRIBE);
			nng_mqtt_msg_set_subscribe_topics(
			    msg, topic_qos, topic_qos_count);

			work->msg = msg;
			nng_aio_set_msg(work->aio, work->msg);
			work->msg   = NULL;
			work->state = SEND;
			nng_ctx_send(work->ctx, work->aio);
		} else {
			work->state = RECV;
			nng_ctx_recv(work->ctx, work->aio);
		}
		break;
	case RECV:
		if ((rv = nng_aio_result(work->aio)) != 0) {
			fatal("nng_recv_aio", rv);
		}
		msg = nng_aio_get_msg(work->aio);

		uint32_t payload_len;
		uint8_t *payload =
		    nng_mqtt_msg_get_publish_payload(msg, &payload_len);
		uint32_t    topic_len;
		const char *recv_topic =
		    nng_mqtt_msg_get_publish_topic(msg, &topic_len);

		printf("Recv '%.*s' from topic '%.*s'\n", payload_len,
		    (char *) payload, topic_len, recv_topic);

		work->msg   = msg;
		work->state = WAIT;
		nng_sleep_aio(1, work->aio);
		break;
	case WAIT:
		nng_msg_header_clear(work->msg);
		nng_msg_clear(work->msg);
		// Send message to another topic
		char topic[50] = { 0 };
		snprintf(topic, 50, "/nanomq/msg/%02d/rep", work->index);
		nng_mqtt_msg_set_packet_type(work->msg, NNG_MQTT_PUBLISH);
		nng_mqtt_msg_set_publish_topic(work->msg, topic);
		nng_mqtt_msg_set_publish_payload(
		    work->msg, (uint8_t *) topic, strlen(topic));

		nng_aio_set_msg(work->aio, work->msg);
		work->msg   = NULL;
		work->state = SEND;
		nng_ctx_send(work->ctx, work->aio);
		break;
	case SEND:
		if ((rv = nng_aio_result(work->aio)) != 0) {
			nng_msg_free(work->msg);
			fatal("nng_send_aio", rv);
		}
		work->state = RECV;
		nng_ctx_recv(work->ctx, work->aio);
		break;
	default:
		fatal("bad state!", NNG_ESTATE);
		break;
	}
}

struct work *
alloc_work(nng_socket sock, uint32_t index)
{
	struct work *w;
	int          rv;

	if ((w = nng_alloc(sizeof(*w))) == NULL) {
		fatal("nng_alloc", NNG_ENOMEM);
	}
	if ((rv = nng_aio_alloc(&w->aio, client_cb, w)) != 0) {
		fatal("nng_aio_alloc", rv);
	}
	if ((rv = nng_ctx_open(&w->ctx, sock)) != 0) {
		fatal("nng_ctx_open", rv);
	}
	w->state = INIT;
	w->index = index;
	return (w);
}

// Connack message callback function
static void
connect_cb(void *arg, nng_msg *msg)
{
	(void) arg;
	printf(
	    "Connack status: %d\n", nng_mqtt_msg_get_connack_return_code(msg));
	nng_msg_free(msg);
}

int
client(const char *url)
{
	nng_socket   sock;
	nng_dialer   dialer;
	struct work *works[PARALLEL];
	int          i;
	int          rv;

	if ((rv = nng_mqtt_client_open(&sock)) != 0) {
		fatal("nng_socket", rv);
	}

	for (i = 0; i < PARALLEL; i++) {
		works[i] = alloc_work(sock, i);
	}

	if ((rv = nng_dialer_create(&dialer, sock, url)) != 0) {
		fatal("nng_dialer_create", rv);
	}

	// Mqtt connect message
	nng_msg *msg;
	nng_mqtt_msg_alloc(&msg, 0);
	nng_mqtt_msg_set_packet_type(msg, NNG_MQTT_CONNECT);
	nng_mqtt_msg_set_connect_keep_alive(msg, 60);
	nng_mqtt_msg_set_connect_clean_session(msg, true);

	nng_dialer_set_ptr(dialer, NNG_OPT_MQTT_CONNMSG, msg);
	nng_dialer_set_cb(dialer, connect_cb, NULL);
	nng_dialer_start(dialer, NNG_FLAG_NONBLOCK);

	nng_msleep(1000);

	for (i = 0; i < PARALLEL; i++) {
		client_cb(works[i]);
	}

	for (;;) {
		nng_msleep(3600000); // neither pause() nor sleep() portable
	}
}

static int
init_dialer_tls_ex(
    nng_dialer d, const char *cert, const char *key, bool own_cert)
{
	nng_tls_config *cfg;
	int             rv;

	if ((rv = nng_tls_config_alloc(&cfg, NNG_TLS_MODE_CLIENT)) != 0) {
		return (rv);
	}

	if ((rv = nng_tls_config_ca_chain(cfg, cert, NULL)) != 0) {
		goto out;
	}

	if ((rv = nng_tls_config_server_name(cfg, "www.fabric.com")) != 0) {
		goto out;
	}
	// nng_tls_config_auth_mode(cfg, NNG_TLS_AUTH_MODE_REQUIRED);
	nng_tls_config_auth_mode(cfg, NNG_TLS_AUTH_MODE_NONE);

	if (own_cert) {
		if ((rv = nng_tls_config_own_cert(cfg, cert, key, NULL)) !=
		    0) {
			goto out;
		}
	}

	rv = nng_dialer_setopt_ptr(d, NNG_OPT_TLS_CONFIG, cfg);

out:
	nng_tls_config_free(cfg);
	return (rv);
}

static int
init_dialer_tls(nng_dialer d, const char *cert, const char *key)
{
	return (init_dialer_tls_ex(d, cert, key, false));
}

int
tls_client(const char *url, const char *cert, const char *key)
{
	nng_socket   sock;
	nng_dialer   dialer;
	struct work *works[PARALLEL];
	int          i;
	int          rv;

	if ((rv = nng_mqtt_client_open(&sock)) != 0) {
		fatal("nng_socket", rv);
	}

	for (i = 0; i < PARALLEL; i++) {
		works[i] = alloc_work(sock, i);
	}

	if ((rv = nng_dialer_create(&dialer, sock, url)) != 0) {
		fatal("nng_dialer_create", rv);
	}

	// Mqtt connect message
	nng_msg *msg;
	nng_mqtt_msg_alloc(&msg, 0);
	nng_mqtt_msg_set_packet_type(msg, NNG_MQTT_CONNECT);
	nng_mqtt_msg_set_connect_keep_alive(msg, 60);
	nng_mqtt_msg_set_connect_clean_session(msg, true);

	init_dialer_tls(dialer, cert, key);
	nng_dialer_set_ptr(dialer, NNG_OPT_MQTT_CONNMSG, msg);
	nng_dialer_set_cb(dialer, connect_cb, NULL);
	nng_dialer_start(dialer, NNG_FLAG_NONBLOCK);

	nng_msleep(1000);

	for (i = 0; i < PARALLEL; i++) {
		client_cb(works[i]);
	}

	for (;;) {
		nng_msleep(3600000); // neither pause() nor sleep() portable
	}
}

int
main(int argc, const char **argv)
{
	int   rc;
	char *url;
	char *cert;
	char *key;

	if (argc < 2) {
		fprintf(stderr, "Usage: %s <url> \n", argv[0]);
		exit(EXIT_FAILURE);
	}

	url = (char *) argv[1];

	if (argc >= 3) {
		cert = (char *)argv[2];
		if (argc >= 4) {
			key = (char *)argv[3];
		}

		tls_client(url, cert, key);

		nng_strfree(cert);
		nng_strfree(key);

	} else {
		client(url);
	}

	return 0;
}
