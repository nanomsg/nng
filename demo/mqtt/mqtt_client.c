// Author: eeff <eeff at eeff dot dev>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

//
// This is just a simple MQTT client demonstration application.
//
// The application has two sub-commands: `pub` and `sub`. The `pub`
// sub-command publishes a given message to the server and then exits.
// The `sub` sub-command subscribes to the given topic filter and blocks
// waiting for incoming messages.
//
// # Example:
//
// Publish 'hello' to `topic` with QoS `0`:
// ```
// $ ./mqtt_client pub mqtt-tcp://127.0.0.1:1883 0 topic hello
// ```
//
// Subscribe to `topic` with QoS `0` and waiting for messages:
// ```
// $ ./mqtt_client sub mqtt-tcp://127.0.0.1:1883 0 topic
// ```
//

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <time.h>

#include <nng/mqtt/mqtt_client.h>
#include <nng/nng.h>
#include <nng/supplemental/util/platform.h>

// Subcommands
#define PUBLISH "pub"
#define SUBSCRIBE "sub"

void
fatal(const char *msg, int rv)
{
	fprintf(stderr, "%s: %s\n", msg, nng_strerror(rv));
}

int keepRunning = 1;
void
intHandler(int dummy)
{
	keepRunning = 0;
	fprintf(stderr, "\nclient exit(0).\n");
	nng_closeall();
	exit(0);
}

// Print the given string limited to 80 columns.
//
// The `prefix` should be a null terminated string much smaller than 80,
// `str` and `len` designates the string to be printed, `quote` specifies
// whether to print in single quotes.
void
print80(const char *prefix, const char *str, size_t len, bool quote)
{
	size_t max_len = 80 - strlen(prefix) - (quote ? 2 : 0);
	char * q       = quote ? "'" : "";
	if (len <= max_len) {
		// case the output fit in a line
		printf("%s%s%.*s%s\n", prefix, q, (int) len, str, q);
	} else {
		// case we truncate the payload with ellipses
		printf(
		    "%s%s%.*s%s...\n", prefix, q, (int) (max_len - 3), str, q);
	}
}

static void
disconnect_cb(nng_pipe p, nng_pipe_ev ev, void *arg)
{
	nng_msg * msg = arg;
	nng_msg_free(msg);
	printf("%s: disconnected!\n", __FUNCTION__);
}

static void
connect_cb(nng_pipe p, nng_pipe_ev ev, void *arg)
{
	printf("%s: connected!\n", __FUNCTION__);
}

// Connect to the given address.
int
client_connect(nng_socket *sock, const char *url, bool verbose)
{
	nng_dialer dialer;
	int        rv;

	if ((rv = nng_mqtt_client_open(sock)) != 0) {
		fatal("nng_socket", rv);
	}

	if ((rv = nng_dialer_create(&dialer, *sock, url)) != 0) {
		fatal("nng_dialer_create", rv);
	}

	// create a CONNECT message
	/* CONNECT */
	nng_msg *connmsg;
	nng_mqtt_msg_alloc(&connmsg, 0);
	nng_mqtt_msg_set_packet_type(connmsg, NNG_MQTT_CONNECT);
	nng_mqtt_msg_set_connect_proto_version(connmsg, 4);
	nng_mqtt_msg_set_connect_keep_alive(connmsg, 60);
	nng_mqtt_msg_set_connect_user_name(connmsg, "nng_mqtt_client");
	nng_mqtt_msg_set_connect_password(connmsg, "secrets");
	nng_mqtt_msg_set_connect_will_msg(
	    connmsg, (uint8_t *) "bye-bye", strlen("bye-bye"));
	nng_mqtt_msg_set_connect_will_topic(connmsg, "will_topic");
	nng_mqtt_msg_set_connect_clean_session(connmsg, true);

	nng_mqtt_set_connect_cb(*sock, connect_cb, &sock);
	nng_mqtt_set_disconnect_cb(*sock, disconnect_cb, connmsg);

	uint8_t buff[1024] = { 0 };

	if (verbose) {
		nng_mqtt_msg_dump(connmsg, buff, sizeof(buff), true);
		printf("%s\n", buff);
	}

	printf("Connecting to server ...\n");
	nng_dialer_set_ptr(dialer, NNG_OPT_MQTT_CONNMSG, connmsg);
	nng_dialer_start(dialer, NNG_FLAG_NONBLOCK);

	return (0);
}

// Subscribe to the given subscriptions, and start receiving messages forever.
int
client_subscribe(nng_socket sock, nng_mqtt_topic_qos *subscriptions, int count,
    bool verbose)
{
	int rv;

	// create a SUBSCRIBE message
	nng_msg *submsg;
	nng_mqtt_msg_alloc(&submsg, 0);
	nng_mqtt_msg_set_packet_type(submsg, NNG_MQTT_SUBSCRIBE);

	nng_mqtt_msg_set_subscribe_topics(submsg, subscriptions, count);

	uint8_t buff[1024] = { 0 };

	if (verbose) {
		nng_mqtt_msg_dump(submsg, buff, sizeof(buff), true);
		printf("%s\n", buff);
	}

	printf("Subscribing ...");
	if ((rv = nng_sendmsg(sock, submsg, 0)) != 0) {
		nng_msg_free(submsg);
		fatal("nng_sendmsg", rv);
	}
	printf("done.\n");

	printf("Start receiving loop:\n");
	while (true) {
		nng_msg *msg;
		uint8_t *payload;
		uint32_t payload_len;
		if ((rv = nng_recvmsg(sock, &msg, 0)) != 0) {
			fatal("nng_recvmsg", rv);
			continue;
		}

		// we should only receive publish messages
		assert(nng_mqtt_msg_get_packet_type(msg) == NNG_MQTT_PUBLISH);

		payload = nng_mqtt_msg_get_publish_payload(msg, &payload_len);

		print80("Received: ", (char *) payload, payload_len, true);

		if (verbose) {
			memset(buff, 0, sizeof(buff));
			nng_mqtt_msg_dump(msg, buff, sizeof(buff), true);
			printf("%s\n", buff);
		}

		nng_msg_free(msg);
	}

	return rv;
}

// Publish a message to the given topic and with the given QoS.
int
client_publish(nng_socket sock, const char *topic, uint8_t *payload,
    uint32_t payload_len, uint8_t qos, bool verbose)
{
	int rv;

	// create a PUBLISH message
	nng_msg *pubmsg;
	nng_mqtt_msg_alloc(&pubmsg, 0);
	nng_mqtt_msg_set_packet_type(pubmsg, NNG_MQTT_PUBLISH);
	nng_mqtt_msg_set_publish_dup(pubmsg, 0);
	nng_mqtt_msg_set_publish_qos(pubmsg, qos);
	nng_mqtt_msg_set_publish_retain(pubmsg, 0);
	nng_mqtt_msg_set_publish_payload(
	    pubmsg, (uint8_t *) payload, payload_len);
	nng_mqtt_msg_set_publish_topic(pubmsg, topic);

	if (verbose) {
		uint8_t print[1024] = { 0 };
		nng_mqtt_msg_dump(pubmsg, print, 1024, true);
		printf("%s\n", print);
	}

	printf("Publishing to '%s' ...\n", topic);
	if ((rv = nng_sendmsg(sock, pubmsg, NNG_FLAG_NONBLOCK)) != 0) {
		fatal("nng_sendmsg", rv);
	}

	return rv;
}

struct pub_params {
	nng_socket *sock;
	const char *topic;
	uint8_t *   data;
	uint32_t    data_len;
	uint8_t     qos;
	bool        verbose;
	uint32_t    interval;
};

void
publish_cb(void *args)
{
	int                rv;
	struct pub_params *params = args;
	do {
		rv = client_publish(*params->sock, params->topic, params->data,
		    params->data_len, params->qos, params->verbose);
		nng_msleep(params->interval);
	} while (params->interval > 0 && rv == 0);
	printf("thread_exit\n");
}

struct pub_params params;

int
main(const int argc, const char **argv)
{
	nng_socket sock;

	const char *exe = argv[0];

	const char *cmd;

	if (5 == argc && 0 == strcmp(argv[1], SUBSCRIBE)) {
		cmd = SUBSCRIBE;
	} else if (6 <= argc && 0 == strcmp(argv[1], PUBLISH)) {
		cmd = PUBLISH;
	} else {
		goto error;
	}

	const char *url         = argv[2];
	uint8_t     qos         = atoi(argv[3]);
	const char *topic       = argv[4];
	int         rv          = 0;
	char *      verbose_env = getenv("VERBOSE");
	bool        verbose     = verbose_env && strlen(verbose_env) > 0;

	client_connect(&sock, url, verbose);

	signal(SIGINT, intHandler);

	if (strcmp(PUBLISH, cmd) == 0) {
		const char *data     = argv[5];
		uint32_t    interval = 0;
		uint32_t    nthread  = 1;

		if (argc >= 7) {
			interval = atoi(argv[6]);
		}
		if (argc >= 8) {
			nthread = atoi(argv[7]);
		}
		nng_thread *threads[nthread];

		params.sock = &sock, params.topic = topic;
		params.data     = (uint8_t *) data;
		params.data_len = strlen(data);
		params.qos      = qos;
		params.interval = interval;
		params.verbose  = verbose;

		char thread_name[20];

		size_t i = 0;
		for (i = 0; i < nthread; i++) {
			nng_thread_create(&threads[i], publish_cb, &params);
		}

		for (i = 0; i < nthread; i++) {
			nng_thread_destroy(threads[i]);
		}
	} else if (strcmp(SUBSCRIBE, cmd) == 0) {
		nng_mqtt_topic_qos subscriptions[] = {
			{ .qos     = qos,
			    .topic = { .buf = (uint8_t *) topic,
			        .length     = strlen(topic) } },
		};
		rv = client_subscribe(sock, subscriptions, 1, verbose);
	}

	nng_msleep(1000);
	nng_close(sock);

	return 0;

error:
	fprintf(stderr,
	    "Usage: %s %s <URL> <QOS> <TOPIC> <data> <interval> <parallel>\n"
	    "       %s %s <URL> <QOS> <TOPIC>\n",
	    exe, PUBLISH, exe, SUBSCRIBE);
	return 1;
}
