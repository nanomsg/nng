//
// Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "convey.h"
#include "nng.h"
#include "protocol/pair1/pair.h"
#include "transport/ws/websocket.h"
#include "trantest.h"

#include "stubs.h"
// TCP tests.

#ifndef _WIN32
#include <arpa/inet.h>
#endif

// These keys are for demonstration purposes ONLY.  DO NOT USE.
// The certificate is valid for 100 years, because I don't want to
// have to regenerate it ever again. The CN is 127.0.0.1, and self-signed.
//
// Generated using openssl:
//
// % openssl ecparam -name secp521r1 -noout -genkey -out key.key
// % openssl req -new -key key.key -out cert.csr
// % openssl x509 -req -in cert.csr -days 36500 -out cert.crt -signkey key.key
//
// Relevant metadata:
//
// Certificate:
//     Data:
//        Version: 1 (0x0)
//        Serial Number: 9808857926806240008 (0x882010509b8f7b08)
//    Signature Algorithm: ecdsa-with-SHA1
//        Issuer: C=US, ST=CA, L=San Diego, O=nanomsg, CN=127.0.0.1
//        Validity
//            Not Before: Nov 17 20:08:06 2017 GMT
//            Not After : Oct 24 20:08:06 2117 GMT
//        Subject: C=US, ST=CA, L=San Diego, O=nanomsg, CN=127.0.0.1
//
static const char server_cert[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIICIjCCAYMCCQDaC9ARg31kIjAKBggqhkjOPQQDAjBUMQswCQYDVQQGEwJVUzEL\n"
    "MAkGA1UECAwCQ0ExEjAQBgNVBAcMCVNhbiBEaWVnbzEQMA4GA1UECgwHbmFub21z\n"
    "ZzESMBAGA1UEAwwJMTI3LjAuMC4xMCAXDTE3MTExNzIwMjczMloYDzIxMTcxMDI0\n"
    "MjAyNzMyWjBUMQswCQYDVQQGEwJVUzELMAkGA1UECAwCQ0ExEjAQBgNVBAcMCVNh\n"
    "biBEaWVnbzEQMA4GA1UECgwHbmFub21zZzESMBAGA1UEAwwJMTI3LjAuMC4xMIGb\n"
    "MBAGByqGSM49AgEGBSuBBAAjA4GGAAQAN7vDK6GEiSguMsOuhfOvGyiVc37Sog0b\n"
    "UkpaiS6+SagTmXFSN1Rgh9isxKFYJvcCtAko3v0I8rAVQucdhf5B3hEBMQlbBIuM\n"
    "rMKT6ZQJ+eiwyb4O3Scgd7DoL3tc/kOqijwB/5hJ4sZdquDKP5DDFe5fAf4MNtzY\n"
    "4C+iApWlKq/LoXkwCgYIKoZIzj0EAwIDgYwAMIGIAkIBOuJAWmNSdd6Ovmr6Ebg3\n"
    "UF9ZrsNwARd9BfYbBk5OQhUOjCLB6d8aLi49WOm1WoRvOS5PaVvmvSfNhaw8b5nV\n"
    "hnYCQgC+EmJ6C3bEcZrndhfbqvCaOGkc7/SrKhC6fS7mJW4wL90QUV9WjQ2Ll6X5\n"
    "PxkSj7s0SvD6T8j7rju5LDgkdZc35A==\n"
    "-----END CERTIFICATE-----\n";

static const char server_key[] =
    "-----BEGIN EC PRIVATE KEY-----\n"
    "MIHcAgEBBEIB20OHMntU2UJW2yuQn2f+bLsuhTT5KRGorcocnqxatWLvxuF1cfUA\n"
    "TjQxRRS6BIUvFt1fMIklp9qedJF00JHy4qWgBwYFK4EEACOhgYkDgYYABAA3u8Mr\n"
    "oYSJKC4yw66F868bKJVzftKiDRtSSlqJLr5JqBOZcVI3VGCH2KzEoVgm9wK0CSje\n"
    "/QjysBVC5x2F/kHeEQExCVsEi4yswpPplAn56LDJvg7dJyB3sOgve1z+Q6qKPAH/\n"
    "mEnixl2q4Mo/kMMV7l8B/gw23NjgL6IClaUqr8uheQ==\n"
    "-----END EC PRIVATE KEY-----\n";

static int
check_props_v4(nng_msg *msg, nng_listener l, nng_dialer d)
{
	nng_pipe     p;
	size_t       z;
	nng_sockaddr la;
	nng_sockaddr ra;
	char *       buf;
	size_t       len;

	p = nng_msg_get_pipe(msg);
	So(p > 0);

	z = sizeof(nng_sockaddr);
	So(nng_pipe_getopt(p, NNG_OPT_LOCADDR, &la, &z) == 0);
	So(z == sizeof(la));
	So(la.s_un.s_family == NNG_AF_INET);
	So(la.s_un.s_in.sa_port == htons(trantest_port - 1));
	So(la.s_un.s_in.sa_port != 0);
	So(la.s_un.s_in.sa_addr == htonl(0x7f000001));

	z = sizeof(nng_sockaddr);
	So(nng_pipe_getopt(p, NNG_OPT_REMADDR, &ra, &z) == 0);
	So(z == sizeof(ra));
	So(ra.s_un.s_family == NNG_AF_INET);
	So(ra.s_un.s_in.sa_port != 0);
	So(ra.s_un.s_in.sa_addr == htonl(0x7f000001));

	// Request header
	z   = 0;
	buf = NULL;
	So(nng_pipe_getopt(p, NNG_OPT_WS_REQUEST_HEADERS, buf, &z) == 0);
	So(z > 0);
	len = z;
	So((buf = nni_alloc(len)) != NULL);
	So(nng_pipe_getopt(p, NNG_OPT_WS_REQUEST_HEADERS, buf, &z) == 0);
	So(strstr(buf, "Sec-WebSocket-Key") != NULL);
	So(z == len);
	nni_free(buf, len);

	// Response header
	z   = 0;
	buf = NULL;
	So(nng_pipe_getopt(p, NNG_OPT_WS_RESPONSE_HEADERS, buf, &z) == 0);
	So(z > 0);
	len = z;
	So((buf = nni_alloc(len)) != NULL);
	So(nng_pipe_getopt(p, NNG_OPT_WS_RESPONSE_HEADERS, buf, &z) == 0);
	So(strstr(buf, "Sec-WebSocket-Accept") != NULL);
	So(z == len);
	nni_free(buf, len);

	return (0);
}

static int
init_dialer_wss(trantest *tt, nng_dialer d)
{
	nng_tls_config *cfg;
	int             rv;

	if ((rv = nng_tls_config_alloc(&cfg, NNG_TLS_MODE_CLIENT)) != 0) {
		return (rv);
	}
	if ((rv = nng_tls_config_ca_cert(
	         cfg, (void *) server_cert, sizeof(server_cert))) != 0) {
		goto out;
	}
	if ((rv = nng_tls_config_server_name(cfg, "127.0.0.1")) != 0) {
		goto out;
	}
	nng_tls_config_auth_mode(cfg, NNG_TLS_AUTH_MODE_NONE);
	rv = nng_dialer_setopt_ptr(d, NNG_OPT_WSS_TLS_CONFIG, cfg);

out:
	nng_tls_config_free(cfg);
	return (rv);
}

static int
init_listener_wss(trantest *tt, nng_listener l)
{
	nng_tls_config *cfg;
	int             rv;

	if ((rv = nng_tls_config_alloc(&cfg, NNG_TLS_MODE_SERVER)) != 0) {
		return (rv);
	}
	if ((rv = nng_tls_config_cert(
	         cfg, (void *) server_cert, sizeof(server_cert))) != 0) {
		goto out;
	}
	if ((rv = nng_tls_config_key(
	         cfg, (void *) server_key, sizeof(server_key))) != 0) {
		goto out;
	}

	if ((rv = nng_listener_setopt_ptr(l, NNG_OPT_WSS_TLS_CONFIG, cfg)) !=
	    0) {
		// We can wind up with EBUSY from the server already running.
		if (rv == NNG_EBUSY) {
			rv = 0;
		}
	}

out:
	nng_tls_config_free(cfg);
	return (rv);
}

TestMain("WebSocket Secure (TLS) Transport", {
	static trantest tt;

	tt.dialer_init   = init_dialer_wss;
	tt.listener_init = init_listener_wss;
	tt.tmpl          = "wss://127.0.0.1:%u/test";
	tt.proptest      = check_props_v4;

	trantest_test(&tt);

	nng_fini();
})
