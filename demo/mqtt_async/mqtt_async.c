#include <assert.h>
#include <errno.h>
#include <getopt.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <nng/mqtt/mqtt_client.h>
#include <nng/nng.h>
#include <nng/supplemental/util/platform.h>

#ifdef NNG_SUPP_TLS
#include <nng/supplemental/tls/tls.h>

static void loadfile(const char *path, void **datap, size_t *lenp);
static int  init_dialer_tls(nng_dialer d, const char *cacert, const char *cert,
     const char *key, const char *pass);
#endif

static size_t nwork = 32;

struct work {
	enum { INIT, RECV, WAIT, SEND } state;
	nng_aio *aio;
	nng_msg *msg;
	nng_ctx  ctx;
};

#define SUB_TOPIC1 "/nanomq/msg/1"
#define SUB_TOPIC2 "/nanomq/msg/2"
#define SUB_TOPIC3 "/nanomq/msg/3"

void
fatal(const char *msg, int rv)
{
	fprintf(stderr, "%s: %s\n", msg, nng_strerror(rv));
}

void
client_cb(void *arg)
{
	struct work *work = arg;
	nng_msg *    msg;
	int          rv;

	switch (work->state) {

	case INIT:
		work->state = RECV;
		nng_ctx_recv(work->ctx, work->aio);
		break;

	case RECV:
		if ((rv = nng_aio_result(work->aio)) != 0) {
			fatal("nng_recv_aio", rv);
			work->state = RECV;
			nng_ctx_recv(work->ctx, work->aio);
			break;
		}

		work->msg   = nng_aio_get_msg(work->aio);
		work->state = WAIT;
		nng_sleep_aio(0, work->aio);
		break;

	case WAIT:
		msg = work->msg;

		// Get PUBLISH payload and topic from msg;
		uint32_t payload_len;
		uint8_t *payload =
		    nng_mqtt_msg_get_publish_payload(msg, &payload_len);
		uint32_t    topic_len;
		const char *recv_topic =
		    nng_mqtt_msg_get_publish_topic(msg, &topic_len);

		printf("RECV: '%.*s' FROM: '%.*s'\n", payload_len,
		    (char *) payload, topic_len, recv_topic);

		uint8_t *send_data = nng_alloc(payload_len);
		memcpy(send_data, payload, payload_len);

		nng_msg_header_clear(work->msg);
		nng_msg_clear(work->msg);

		// Send payload to topic "/nanomq/msg/transfer"
		char *topic = "/nanomq/msg/transfer";
		nng_mqtt_msg_set_packet_type(work->msg, NNG_MQTT_PUBLISH);
		nng_mqtt_msg_set_publish_topic(work->msg, topic);
		nng_mqtt_msg_set_publish_payload(
		    work->msg, send_data, payload_len);

		printf("SEND: '%.*s' TO:   '%s'\n", payload_len,
		    (char *) send_data, topic);

		nng_free(send_data, payload_len);
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
alloc_work(nng_socket sock)
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
	return (w);
}

void
connect_cb(nng_pipe p, nng_pipe_ev ev, void *arg)
{
	printf("%s: connected!\n", __FUNCTION__);
	nng_socket sock = *(nng_socket *) arg;

	nng_mqtt_topic_qos topic_qos[] = {
		{ .qos     = 0,
		    .topic = { .buf = (uint8_t *) SUB_TOPIC1,
		        .length     = strlen(SUB_TOPIC1) } },
		{ .qos     = 1,
		    .topic = { .buf = (uint8_t *) SUB_TOPIC2,
		        .length     = strlen(SUB_TOPIC2) } },
		{ .qos     = 2,
		    .topic = { .buf = (uint8_t *) SUB_TOPIC3,
		        .length     = strlen(SUB_TOPIC3) } }
	};

	size_t topic_qos_count =
	    sizeof(topic_qos) / sizeof(nng_mqtt_topic_qos);

	// Connected succeed
	nng_msg *msg;
	nng_mqtt_msg_alloc(&msg, 0);
	nng_mqtt_msg_set_packet_type(msg, NNG_MQTT_SUBSCRIBE);
	nng_mqtt_msg_set_subscribe_topics(msg, topic_qos, topic_qos_count);

	// Send subscribe message
	nng_sendmsg(sock, msg, NNG_FLAG_NONBLOCK);
}

void
disconnect_cb(nng_pipe p, nng_pipe_ev ev, void *arg)
{
	printf("%s: disconnected!\n", __FUNCTION__);
}

int
client(const char *url)
{
	nng_socket   sock;
	nng_dialer   dialer;
	struct work *works[nwork];
	int          i;
	int          rv;

	if ((rv = nng_mqtt_client_open(&sock)) != 0) {
		fatal("nng_socket", rv);
	}

	for (i = 0; i < nwork; i++) {
		works[i] = alloc_work(sock);
	}

	// Mqtt connect message
	nng_msg *msg;
	nng_mqtt_msg_alloc(&msg, 0);
	nng_mqtt_msg_set_packet_type(msg, NNG_MQTT_CONNECT);
	nng_mqtt_msg_set_connect_keep_alive(msg, 60);
	nng_mqtt_msg_set_connect_clean_session(msg, true);

	nng_mqtt_set_connect_cb(sock, connect_cb, &sock);
	nng_mqtt_set_disconnect_cb(sock, disconnect_cb, NULL);

	if ((rv = nng_dialer_create(&dialer, sock, url)) != 0) {
		fatal("nng_dialer_create", rv);
	}

	nng_dialer_set_ptr(dialer, NNG_OPT_MQTT_CONNMSG, msg);
	nng_dialer_start(dialer, NNG_FLAG_NONBLOCK);

	for (i = 0; i < nwork; i++) {
		client_cb(works[i]);
	}

	for (;;) {
		nng_msleep(3600000); // neither pause() nor sleep() portable
	}
}

#ifdef NNG_SUPP_TLS
// This reads a file into memory.  Care is taken to ensure that
// the buffer is one byte larger and contains a terminating
// NUL. (Useful for key files and such.)
static void
loadfile(const char *path, void **datap, size_t *lenp)
{
	FILE * f;
	size_t total_read      = 0;
	size_t allocation_size = BUFSIZ;
	char * fdata;
	char * realloc_result;

	if (strcmp(path, "-") == 0) {
		f = stdin;
	} else {
		if ((f = fopen(path, "rb")) == NULL) {
			fprintf(stderr, "Cannot open file %s: %s", path,
			    strerror(errno));
			exit(1);
		}
	}

	if ((fdata = malloc(allocation_size + 1)) == NULL) {
		fprintf(stderr, "Out of memory.");
	}

	while (1) {
		total_read += fread(
		    fdata + total_read, 1, allocation_size - total_read, f);
		if (ferror(f)) {
			if (errno == EINTR) {
				continue;
			}
			fprintf(stderr, "Read from %s failed: %s", path,
			    strerror(errno));
			exit(1);
		}
		if (feof(f)) {
			break;
		}
		if (total_read == allocation_size) {
			if (allocation_size > SIZE_MAX / 2) {
				fprintf(stderr, "Out of memory.");
			}
			allocation_size *= 2;
			if ((realloc_result = realloc(
			         fdata, allocation_size + 1)) == NULL) {
				free(fdata);
				fprintf(stderr, "Out of memory.");
				exit(1);
			}
			fdata = realloc_result;
		}
	}
	if (f != stdin) {
		fclose(f);
	}
	fdata[total_read] = '\0';
	*datap            = fdata;
	*lenp             = total_read;
}

static int
init_dialer_tls(nng_dialer d, const char *cacert, const char *cert,
    const char *key, const char *pass)
{
	nng_tls_config *cfg;
	int             rv;

	if ((rv = nng_tls_config_alloc(&cfg, NNG_TLS_MODE_CLIENT)) != 0) {
		return (rv);
	}

	if (cert != NULL && key != NULL) {
		nng_tls_config_auth_mode(cfg, NNG_TLS_AUTH_MODE_REQUIRED);
		if ((rv = nng_tls_config_own_cert(cfg, cert, key, pass)) !=
		    0) {
			goto out;
		}
	} else {
		nng_tls_config_auth_mode(cfg, NNG_TLS_AUTH_MODE_NONE);
	}

	if (cacert != NULL) {
		if ((rv = nng_tls_config_ca_chain(cfg, cacert, NULL)) != 0) {
			goto out;
		}
	}

	rv = nng_dialer_set_ptr(d, NNG_OPT_TLS_CONFIG, cfg);

out:
	nng_tls_config_free(cfg);
	return (rv);
}

int
tls_client(const char *url, const char *ca, const char *cert, const char *key,
    const char *pass)
{
	nng_socket   sock;
	nng_dialer   dialer;
	struct work *works[nwork];
	int          i;
	int          rv;

	if ((rv = nng_mqtt_client_open(&sock)) != 0) {
		fatal("nng_socket", rv);
	}

	for (i = 0; i < nwork; i++) {
		works[i] = alloc_work(sock);
	}
	// Mqtt connect message
	nng_msg *msg;
	nng_mqtt_msg_alloc(&msg, 0);
	nng_mqtt_msg_set_packet_type(msg, NNG_MQTT_CONNECT);
	nng_mqtt_msg_set_connect_keep_alive(msg, 60);
	nng_mqtt_msg_set_connect_clean_session(msg, true);

	nng_mqtt_set_connect_cb(sock, connect_cb, &sock);
	nng_mqtt_set_disconnect_cb(sock, disconnect_cb, NULL);

	if ((rv = nng_dialer_create(&dialer, sock, url)) != 0) {
		fatal("nng_dialer_create", rv);
	}

	if ((rv = init_dialer_tls(dialer, ca, cert, key, pass)) != 0) {
		fatal("init_dialer_tls", rv);
	}

	nng_dialer_set_ptr(dialer, NNG_OPT_MQTT_CONNMSG, msg);
	nng_dialer_start(dialer, NNG_FLAG_NONBLOCK);

	for (i = 0; i < nwork; i++) {
		client_cb(works[i]);
	}

	for (;;) {
		nng_msleep(3600000); // neither pause() nor sleep() portable
	}
}
#endif

void
usage(void)
{
	printf("mqtt_async: \n");
	printf("	-u <url> \n");
	printf("	-n <number of works> (default: 32)\n");
#ifdef NNG_SUPP_TLS
	printf("	-s enable ssl/tls mode (default: disable)\n");
	printf("	-a <cafile path>\n");
	printf("	-c <cert file path>\n");
	printf("	-k <key file path>\n");
	printf("	-p <key password>\n");
#endif
}

int
main(int argc, char **argv)
{
	int    rc;
	char * path;
	size_t file_len;

	bool  enable_ssl = false;
	char *url        = NULL;
	char *cafile     = NULL;
	char *cert       = NULL;
	char *key        = NULL;
	char *key_psw    = NULL;

	int   opt;
	int   digit_optind  = 0;
	int   option_index  = 0;
	char *short_options = "u:n:sa:c:k:p:W;";

	static struct option long_options[] = {
		{ "url", required_argument, NULL, 0 },
		{ "nwork", no_argument, NULL, 'n' },
		{ "ssl", no_argument, NULL, false },
		{ "cafile", required_argument, NULL, 0 },
		{ "cert", required_argument, NULL, 0 },
		{ "key", required_argument, NULL, 0 },
		{ "psw", required_argument, NULL, 0 },
		{ "help", no_argument, NULL, 'h' },
		{ NULL, 0, NULL, 0 },
	};

	while ((opt = getopt_long(argc, argv, short_options, long_options,
	            &option_index)) != -1) {
		switch (opt) {
		case 0:
			// TODO
			break;
		case '?':
		case 'h':
			usage();
			exit(0);
		case 'u':
			url = argv[optind - 1];
			break;
		case 'n':
			nwork = atoi(argv[optind - 1]);
			break;
		case 's':
			enable_ssl = true;
			break;
#ifdef NNG_SUPP_TLS
		case 'a':
			path = argv[optind - 1];
			loadfile(path, (void **) &cafile, &file_len);
			break;
		case 'c':
			path = argv[optind - 1];
			loadfile(path, (void **) &cert, &file_len);
			break;
		case 'k':
			path = argv[optind - 1];
			loadfile(path, (void **) &key, &file_len);
			break;
		case 'p':
			key_psw = argv[optind - 1];
			break;
#endif
		default:
			fprintf(stderr, "invalid argument: '%c'\n", opt);
			usage();
			exit(1);
		}
	}

	if (url == NULL) {
		url = "mqtt-tcp://broker.emqx.io:1883";
		printf("set default url: '%s'\n", url);
	}

	if (enable_ssl) {
#ifdef NNG_SUPP_TLS
		tls_client(url, cafile, cert, key, key_psw);
#else
		fprintf(stderr, "tls client: Not supported \n");
#endif

	} else {
		client(url);
	}

	return 0;
}
