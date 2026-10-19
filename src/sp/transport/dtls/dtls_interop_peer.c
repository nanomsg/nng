//
// Copyright 2026 Staysail Systems, Inc. <info@staysail.tech>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

// A separate process permits interoperability tests between TLS engines.
#include <nng/nng.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
extern const char *nuts_server_crt, *nuts_server_key;
extern const char *nuts_client_crt, *nuts_client_key;
#define CHECK(x)                                                            \
	do {                                                                \
		int err = (x);                                              \
		if (err) {                                                  \
			fprintf(stderr, "%s: %s\n", #x, nng_strerror(err)); \
			exit(1);                                            \
		}                                                           \
	} while (0)
int
main(int argc, char **argv)
{
	if (argc < 2 || argc > 3 ||
	    (strcmp(argv[1], "12") != 0 && strcmp(argv[1], "13") != 0)) {
		return (2);
	}
	int             server = argc == 2;
	nng_tls_config *cfg;
	nng_socket      sock;
	char            buf[128];
	size_t          len = sizeof(buf);
	nng_tls_version version =
	    atoi(argv[1]) == 13 ? NNG_TLS_1_3 : NNG_TLS_1_2;
	CHECK(nng_init(NULL));
	nng_log_set_logger(nng_stderr_logger);
	nng_log_set_level(NNG_LOG_DEBUG);
	CHECK(nng_pair0_open(&sock));
	CHECK(nng_socket_set_ms(sock, NNG_OPT_RECVTIMEO, 10000));
	CHECK(nng_socket_set_ms(sock, NNG_OPT_SENDTIMEO, 10000));
	CHECK(nng_tls_config_alloc(
	    &cfg, server ? NNG_TLS_MODE_SERVER : NNG_TLS_MODE_CLIENT));
	CHECK(nng_tls_config_version(cfg, version, version));
	CHECK(nng_tls_config_own_cert(cfg,
	    server ? nuts_server_crt : nuts_client_crt,
	    server ? nuts_server_key : nuts_client_key, NULL));
	CHECK(nng_tls_config_ca_chain(cfg, nuts_server_crt, NULL));
	CHECK(nng_tls_config_auth_mode(cfg, NNG_TLS_AUTH_MODE_REQUIRED));
	if (server) {
		nng_listener   listener;
		const nng_url *url;
		CHECK(nng_listener_create(
		    &listener, sock, "dtls4://127.0.0.1:0"));
		CHECK(nng_listener_set_tls(listener, cfg));
		CHECK(nng_listener_start(listener, 0));
		CHECK(nng_listener_get_url(listener, &url));
		printf("dtls4://127.0.0.1:%u\n", nng_url_port(url));
		fflush(stdout);
		CHECK(nng_recv(sock, buf, &len, 0));
		CHECK(nng_send(sock, buf, len, 0));
	} else {
		nng_dialer dialer;
		CHECK(nng_tls_config_server_name(cfg, "localhost"));
		CHECK(nng_dialer_create(&dialer, sock, argv[2]));
		CHECK(nng_dialer_set_tls(dialer, cfg));
		CHECK(nng_dialer_start(dialer, 0));
		CHECK(nng_send(sock, "interop", 8, 0));
		CHECK(nng_recv(sock, buf, &len, 0));
		if (len != 8 || memcmp(buf, "interop", 8)) {
			return (2);
		}
	}
	nng_socket_close(sock);
	nng_tls_config_free(cfg);
	nng_fini();
	return (0);
}
