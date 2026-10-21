// Copyright 2026 Staysail Systems, Inc. <info@staysail.tech>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt). A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.

// Long-lived, mutually authenticated peers driven by dtls_soak.py.
#include <inttypes.h>
#include <nng/nng.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern const char *nuts_server_crt, *nuts_server_key;
extern const char *nuts_client_crt, *nuts_client_key;

#define MAX_WORKERS 16
#define MAX_BODY 4096
#define HEARTBEAT 5000

typedef struct worker worker;
typedef struct {
	nng_mtx        *mtx;
	bool            stop;
	int             error;
	nng_tls_config *cfg;
	const char     *url;
	unsigned        persistent, count, pace;
	worker         *workers;
} client;

struct worker {
	client     *owner;
	nng_thread *thread;
	unsigned    id;
	uint64_t    ok, timeouts, cycles, bytes;
	uint8_t     request[MAX_BODY], reply[MAX_BODY];
};

static volatile sig_atomic_t interrupted;

static void
on_signal(int sig)
{
	(void) sig;
	interrupted = 1;
}

static int
check(int rv, const char *what)
{
	if (rv != 0) {
		fprintf(stderr, "%s: %s (%d)\n", what, nng_strerror(rv), rv);
	}
	return (rv);
}

#define TRY(call)                           \
	do {                                \
		int e = (call);             \
		if (check(e, #call) != 0) { \
			return (e);         \
		}                           \
	} while (0)

static int
configure(nng_tls_config **out, bool server, nng_tls_version version)
{
	nng_tls_config *cfg;
	TRY(nng_tls_config_alloc(
	    &cfg, server ? NNG_TLS_MODE_SERVER : NNG_TLS_MODE_CLIENT));
	*out = cfg;
	TRY(nng_tls_config_version(cfg, version, version));
	TRY(nng_tls_config_own_cert(cfg,
	    server ? nuts_server_crt : nuts_client_crt,
	    server ? nuts_server_key : nuts_client_key, NULL));
	TRY(nng_tls_config_ca_chain(cfg, nuts_server_crt, NULL));
	TRY(nng_tls_config_auth_mode(cfg, NNG_TLS_AUTH_MODE_REQUIRED));
	if (!server) {
		TRY(nng_tls_config_server_name(cfg, "localhost"));
	}
	return (0);
}

static uint64_t
stat_value(const nng_stat *root, const char *name)
{
	const nng_stat *s = nng_stat_find(root, name);
	return (s == NULL ? 0 : nng_stat_value(s));
}

static void
json_string(const char *value)
{
	putchar('"');
	for (const unsigned char *p = (const unsigned char *) value; *p; p++) {
		if (*p == '"' || *p == '\\') {
			putchar('\\');
			putchar(*p);
		} else if (*p < 32) {
			printf("\\u%04x", *p);
		} else {
			putchar(*p);
		}
	}
	putchar('"');
}

static int
serve(nng_tls_version version, bool probe)
{
	nng_socket      sock;
	nng_listener    listener;
	nng_tls_config *cfg = NULL;
	const nng_url  *url;
	int             rv = configure(&cfg, true, version);
	if (rv != 0) {
		nng_tls_config_free(cfg);
		return (rv);
	}
	TRY(nng_rep0_open(&sock));
	TRY(nng_socket_set_ms(sock, NNG_OPT_RECVTIMEO, 250));
	TRY(nng_socket_set_ms(sock, NNG_OPT_SENDTIMEO, 1000));
	TRY(nng_listener_create(&listener, sock, "dtls4://127.0.0.1:0"));
	TRY(nng_listener_set_tls(listener, cfg));
	TRY(nng_listener_set_size(listener, NNG_OPT_UDP_MAX_PEERS, 16));
	TRY(nng_listener_set_size(listener, NNG_OPT_DTLS_CONN_RATE, 16));
	rv = nng_listener_start(listener, 0);
	if (rv != 0) {
		nng_socket_close(sock);
		nng_tls_config_free(cfg);
		return (rv);
	}
	TRY(nng_listener_get_url(listener, &url));
	printf("{\"event\":\"ready\",\"engine\":\"%s\",\"description\":",
	    nng_tls_engine_name());
	json_string(nng_tls_engine_description());
	printf(",\"url\":\"dtls4://127.0.0.1:%u\"}\n", nng_url_port(url));
	if (!probe) {
		uint8_t *buf = malloc(MAX_BODY);
		uint64_t ok = 0, bytes = 0;
		nng_time next = 0;
		if (buf == NULL) {
			return (NNG_ENOMEM);
		}
		while (!interrupted) {
			size_t len = MAX_BODY;
			rv         = nng_recv(sock, buf, &len, 0);
			if (rv == 0) {
				TRY(nng_send(sock, buf, len, 0));
				ok++;
				bytes += len;
			} else if (rv != NNG_ETIMEDOUT) {
				return (check(rv, "server receive"));
			}
			if (nng_clock() >= next) {
				nng_stat *stats;
				TRY(nng_stats_get(&stats));
				const nng_stat *ep =
				    nng_stat_find_listener(stats, listener);
				if (ep == NULL) {
					return (
					    NNG_ENOTSUP); // admission gauges
					                  // are required
				}
				printf("{\"event\":\"sample\",\"ok\":%" PRIu64
				       ",\"bytes\":%" PRIu64
				       ",\"pending\":%" PRIu64
				       ",\"alloc\":%" PRIu64
				       ",\"invalid\":%" PRIu64
				       ",\"rejected\":%" PRIu64
				       ",\"rate\":%" PRIu64 "}\n",
				    ok, bytes, stat_value(ep, "peer_pending"),
				    stat_value(ep, "peer_alloc"),
				    stat_value(ep, "peer_invalid"),
				    stat_value(ep, "peer_reject"),
				    stat_value(ep, "peer_rate"));
				nng_stats_free(stats);
				next = nng_clock() + HEARTBEAT;
			}
		}
		free(buf);
	}
	TRY(nng_socket_close(sock));
	nng_tls_config_free(cfg);
	return (0);
}

static bool
stopping(client *c)
{
	bool result;
	nng_mtx_lock(c->mtx);
	result = c->stop || c->error != 0;
	nng_mtx_unlock(c->mtx);
	return (result);
}

static int
connect_worker(worker *w, nng_socket *sock)
{
	nng_dialer d;
	TRY(nng_req0_open(sock));
	TRY(nng_socket_set_ms(*sock, NNG_OPT_SENDTIMEO, 1000));
	TRY(nng_socket_set_ms(*sock, NNG_OPT_RECVTIMEO, 1000));
	TRY(nng_socket_set_ms(*sock, NNG_OPT_REQ_RESENDTIME, 200));
	TRY(nng_socket_set_ms(*sock, NNG_OPT_RECONNMINT, 100));
	TRY(nng_socket_set_ms(*sock, NNG_OPT_RECONNMAXT, 1000));
	TRY(nng_dialer_create(&d, *sock, w->owner->url));
	TRY(nng_dialer_set_tls(d, w->owner->cfg));
	TRY(nng_dialer_start(d, NNG_FLAG_NONBLOCK));
	return (0);
}

static void
run_worker(void *arg)
{
	worker  *w        = arg;
	client  *c        = w->owner;
	uint64_t sequence = 0;
	int      rv       = 0;
	while (!stopping(c)) {
		nng_socket sock = NNG_SOCKET_INITIALIZER;
		if ((rv = connect_worker(w, &sock)) != 0) {
			nng_socket_close(sock);
			break;
		}
		nng_mtx_lock(c->mtx);
		w->cycles++;
		nng_mtx_unlock(c->mtx);
		for (unsigned attempt = 0; !stopping(c); attempt++) {
			static const size_t sizes[] = { 64, 256, 1024,
				MAX_BODY };
			size_t              size    = sizes[sequence % 4];
			size_t              got     = sizeof(w->reply);
			sequence++;
			for (size_t i = 0; i < size; i++) {
				w->request[i] =
				    (uint8_t) (i * 31 + w->id * 17 + sequence);
			}
			memcpy(w->request, &sequence, sizeof(sequence));
			rv = nng_send(sock, w->request, size, 0);
			if (rv == 0) {
				rv = nng_recv(sock, w->reply, &got, 0);
			}
			nng_mtx_lock(c->mtx);
			if (rv == 0) {
				if (got != size ||
				    memcmp(w->request, w->reply, size) != 0) {
					rv = NNG_EPROTO;
				} else {
					w->ok++;
					w->bytes += size;
				}
			} else if (rv == NNG_ETIMEDOUT) {
				w->timeouts++;
			}
			nng_mtx_unlock(c->mtx);
			if (rv != 0 && rv != NNG_ETIMEDOUT) {
				break;
			}
			nng_msleep(c->pace);
			if (w->id >= c->persistent && attempt >= 19) {
				break;
			}
		}
		nng_socket_close(sock);
		if (rv != 0 && rv != NNG_ETIMEDOUT) {
			break;
		}
	}
	if (rv != 0 && rv != NNG_ETIMEDOUT) {
		check(rv, "client worker");
		nng_mtx_lock(c->mtx);
		c->error = rv;
		nng_mtx_unlock(c->mtx);
	}
}

static int
run_client(nng_tls_version version, const char *url, unsigned persistent,
    unsigned churn, unsigned pace)
{
	client c = { .url   = url,
		.persistent = persistent,
		.count      = persistent + churn,
		.pace       = pace };
	TRY(nng_mtx_alloc(&c.mtx));
	TRY(configure(&c.cfg, false, version));
	if ((c.workers = calloc(c.count, sizeof(worker))) == NULL) {
		return (NNG_ENOMEM);
	}
	for (unsigned i = 0; i < c.count; i++) {
		c.workers[i].owner = &c;
		c.workers[i].id    = i;
		TRY(nng_thread_create(
		    &c.workers[i].thread, run_worker, &c.workers[i]));
	}
	while (!interrupted && !stopping(&c)) {
		nng_mtx_lock(c.mtx);
		printf("{\"event\":\"sample\",\"workers\":[");
		for (unsigned i = 0; i < c.count; i++) {
			worker *w = &c.workers[i];
			printf("%s{\"ok\":%" PRIu64 ",\"bytes\":%" PRIu64
			       ",\"cycles\":%" PRIu64 ",\"timeouts\":%" PRIu64
			       "}",
			    i == 0 ? "" : ",", w->ok, w->bytes, w->cycles,
			    w->timeouts);
		}
		printf("]}\n");
		nng_mtx_unlock(c.mtx);
		for (unsigned i = 0;
		    i < HEARTBEAT / 100 && !interrupted && !stopping(&c);
		    i++) {
			nng_msleep(100);
		}
	}
	nng_mtx_lock(c.mtx);
	c.stop = true;
	nng_mtx_unlock(c.mtx);
	for (unsigned i = 0; i < c.count; i++) {
		nng_thread_destroy(c.workers[i].thread);
	}
	int error = c.error;
	free(c.workers);
	nng_tls_config_free(c.cfg);
	nng_mtx_free(c.mtx);
	return (error);
}

static unsigned
number(const char *s, unsigned min, unsigned max)
{
	char         *end;
	unsigned long n = strtoul(s, &end, 10);
	if (*s == '\0' || *end != '\0' || n < min || n > max) {
		fprintf(stderr, "Invalid numeric argument: %s\n", s);
		exit(2);
	}
	return ((unsigned) n);
}

int
main(int argc, char **argv)
{
	if (argc < 3 ||
	    (strcmp(argv[1], "server") != 0 && strcmp(argv[1], "probe") != 0 &&
	        strcmp(argv[1], "client") != 0) ||
	    (strcmp(argv[2], "12") != 0 && strcmp(argv[2], "13") != 0) ||
	    (strcmp(argv[1], "client") == 0 ? argc != 7 : argc != 3)) {
		fprintf(stderr,
		    "usage: %s server|probe 12|13\n       %s client 12|13 URL "
		    "PERSISTENT CHURN PACE_MS\n",
		    argv[0], argv[0]);
		return (2);
	}
#ifndef NNG_ENABLE_STATS
	fprintf(stderr, "The soak peer requires NNG_ENABLE_STATS=ON\n");
	return (2);
#endif
#ifndef NNG_SUPP_DTLS_1_3
	if (strcmp(argv[2], "13") == 0) {
		return (77);
	}
#endif
	setvbuf(stdout, NULL, _IOLBF, 0);
	signal(SIGINT, on_signal);
	signal(SIGTERM, on_signal);
	nng_init_params params = { .num_task_threads = 2,
		.num_expire_threads                  = 1,
		.num_poller_threads                  = 1,
		.num_resolver_threads                = 1 };
	TRY(nng_init(&params));
	nng_log_set_logger(nng_stderr_logger);
	nng_log_set_level(getenv("NNG_DTLS_SOAK_DEBUG") == NULL
	        ? NNG_LOG_WARN
	        : NNG_LOG_DEBUG);
	nng_tls_version version =
	    strcmp(argv[2], "13") == 0 ? NNG_TLS_1_3 : NNG_TLS_1_2;
	int rv;
	if (strcmp(argv[1], "client") == 0) {
		unsigned persistent = number(argv[4], 1, MAX_WORKERS / 2);
		unsigned churn      = number(argv[5], 1, MAX_WORKERS / 2);
		rv = run_client(version, argv[3], persistent, churn,
		    number(argv[6], 1, 1000));
	} else {
		rv = serve(version, strcmp(argv[1], "probe") == 0);
	}
	nng_fini();
	return (rv == NNG_ENOTSUP ? 77 : rv == 0 ? 0 : 1);
}
