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
#include "supplemental/tls/tls.h"
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
// % openssl rsa -genkey -out key.key
// % openssl req -new -key key.key -out cert.csr -sha256
// % openssl x509 -req -in cert.csr -days 36500 -out cert.crt
//    -signkey key.key -sha256
//
// Relevant metadata:
//
// Certificate:
//    Data:
//        Version: 1 (0x0)
//        Serial Number: 17127835813110005400 (0xedb24becc3a2be98)
//    Signature Algorithm: sha256WithRSAEncryption
//        Issuer: C=US, ST=CA, L=San Diego, O=nanomsg.org, CN=localhost
//        Validity
//            Not Before: Jan 11 22:34:35 2018 GMT
//            Not After : Dec 18 22:34:35 2117 GMT
//        Subject: C=US, ST=CA, L=San Diego, O=nanomsg.org, CN=localhost
//        Subject Public Key Info:
//            Public Key Algorithm: rsaEncryption
//                Public-Key: (2048 bit)
//
static const char cert[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIDLjCCAhYCCQDtskvsw6K+mDANBgkqhkiG9w0BAQsFADBYMQswCQYDVQQGEwJV\n"
    "UzELMAkGA1UECAwCQ0ExEjAQBgNVBAcMCVNhbiBEaWVnbzEUMBIGA1UECgwLbmFu\n"
    "b21zZy5vcmcxEjAQBgNVBAMMCWxvY2FsaG9zdDAgFw0xODAxMTEyMjM0MzVaGA8y\n"
    "MTE3MTIxODIyMzQzNVowWDELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkNBMRIwEAYD\n"
    "VQQHDAlTYW4gRGllZ28xFDASBgNVBAoMC25hbm9tc2cub3JnMRIwEAYDVQQDDAls\n"
    "b2NhbGhvc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDMvoHdEnfO\n"
    "hmG3PTj6YC5qz6N5hgmcwf4EZkor4+R1Q5hDOKqOknWmVuGBD5mA61ObK76vycIT\n"
    "Tp+H+vKvfgunySZrlyYg8IbgoDbvVgj9RF8xFHdN0PVeqnkBCsCzLtSu6TP8PSgI\n"
    "SKiRMH0NUSakWqCPEc2E1r1CKdOpa7av/Na30LPsuKFcAUhu7QiVYfER86ktrO8G\n"
    "F2PeVy44Q8RkiLw8uhU0bpAflqkR1KCjOLajw1eL3C+Io75Io8qUOLxWc3LH0hl3\n"
    "oEI0jWu7JYlRAw/O7xm4pcGTwy5L8Odz4a7ZTAmuapFRarGOIcDg8Yr0tllRd1mH\n"
    "1T4Z2Wv7Rs0tAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAIfUXK7UonrYAOrlXUHH\n"
    "gfHNdOXMzQP2Ms6Sxov+1tCTfgsYE65Mggo7hRJUqmKpstpbdRBVXhTyht/xjyTz\n"
    "5sMjoeCyv1tXOHpLTfD3LBXwYZwsFdoLS1UHhD3qiYjCyyY2LWa6S786CtlcbCvu\n"
    "Uij2q8zJ4WFrNqAzxZtsTfg16/6JRFw9zpVSCNlHqCxNQxzWucbmUFTiWn9rnc/N\n"
    "r7utG4JsDPZbEI6QS43R7gGLDF7s0ftWKqzlQiZEtuDQh2p7Uejbft8XmZd/VuV/\n"
    "dFMXOO1rleU0lWAJcXWOWHH3er0fivu2ISL8fRjjikYvhRGxtkwC0kPDa2Ntzgd3\n"
    "Hsg=\n"
    "-----END CERTIFICATE-----\n";
static const char key[] =
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "MIIEpQIBAAKCAQEAzL6B3RJ3zoZhtz04+mAuas+jeYYJnMH+BGZKK+PkdUOYQziq\n"
    "jpJ1plbhgQ+ZgOtTmyu+r8nCE06fh/ryr34Lp8kma5cmIPCG4KA271YI/URfMRR3\n"
    "TdD1Xqp5AQrAsy7Urukz/D0oCEiokTB9DVEmpFqgjxHNhNa9QinTqWu2r/zWt9Cz\n"
    "7LihXAFIbu0IlWHxEfOpLazvBhdj3lcuOEPEZIi8PLoVNG6QH5apEdSgozi2o8NX\n"
    "i9wviKO+SKPKlDi8VnNyx9IZd6BCNI1ruyWJUQMPzu8ZuKXBk8MuS/Dnc+Gu2UwJ\n"
    "rmqRUWqxjiHA4PGK9LZZUXdZh9U+Gdlr+0bNLQIDAQABAoIBAC82HqvjfkzZH98o\n"
    "9uKFGy72AjQbfEvxT6mkDKZiPmPr2khl4K5Ph2F71zPzbOoVWYoGZEoUs/PPxWmN\n"
    "rDhbUES4VWupxtkBnZheWUyHAjukcG7Y0UnYTTwvAwgCerzWp6RNkfcwAvMmDfis\n"
    "vak8dTSg0TUsXb+r5KhFDNGcTNv3f7R0cJmaZ/t9FT7SerXf1LW7itvTjRor8/ZK\n"
    "KPwT4oklp1o6RFXSenn/e2e3rAjI+TEwJA3Zp5dqO/M/AhaZKVaxL4voDVdVVkT+\n"
    "LHJWVhjLY5ilPkmPWqmZ2reTaF+gGSSjAQ+t/ahGWFqEdWIz9UoXhBBOd1ibeyvd\n"
    "Kyxp1QECgYEA8KcDkmwPrhqFlQe/U+Md27OhrQ4cecLCa6EVLsCXN1bFyCi3NSo2\n"
    "o5zFCC699KOL0ZwSmYlaQP4xjnqv4Gsa0s3uL7tqOJR2UuEtGK/MPMluGHVaWsGt\n"
    "zbnWH3xgsvvsxdt6hInFhcABLDupW336tJ8EcH7mOKoIP+azwF4kPiUCgYEA2c09\n"
    "zJBUW6SZXhgJ5vgENYc+UwDT7pfhIWZaRL+wXnwSoa7igodTKJtQp/KfFBJK4RA0\n"
    "prvwj4Wr/1ScaboR2hYZApbqXU5zkEkjC1hHIbg1fBe0EcnhP7ojMXrk6B5ed+Lq\n"
    "OVdYhUuvtdL/perelmbTJLnb8S214+tzVyg7EGkCgYEA6JLwX8zxpnhZSztOjBr9\n"
    "2zuSb7YojQBNd0kZOLLGMaQ5xwSactYWMi8rOIo76Lc6RFxKmXnl8NP5PtKRMRkx\n"
    "tjNxE05UDNRmOhkGxUn433JoZVjc9sMhXqZQKuPAbJoOLPW9RWQEsgtq1r3eId7x\n"
    "sSfRWYs6od6p1F/4rlwNOMUCgYEAtJmqf+DCAoe3IL3gICRSISy28k7CbZqE9JQR\n"
    "j+Y/Uemh7W29pyydOROoysq1PAh7DKrKbeNzcx8NYxh+5nCC8wrVzD7lsV8nFmJ+\n"
    "655UxVIhD3f8Oa/j1lr7acEU5KCiBtkjDU8vOMBsv+FpWOQrlB1JQa/X/+G+bHLF\n"
    "XmUerNkCgYEAv7R8vIKgJ1f69imgHdB31kue3wnOO/6NlfY3GTcaZcTdChY8SZ5B\n"
    "xits8xog0VcaxXhWlfO0hyCnZ9YRQbyDu0qp5eBU2p3qcE01x4ljJBZUOTweG06N\n"
    "cL9dYcwse5FhNMjrQ/OKv6B38SIXpoKQUtjgkaMtmpK8cXX1eqEMNkM=\n"
    "-----END RSA PRIVATE KEY-----\n";

static int
validloopback(nng_sockaddr *sa)
{
	char ipv6[16];
	memset(ipv6, 0, sizeof(ipv6));
	ipv6[15] = 1;

	switch (sa->s_family) {
	case NNG_AF_INET:
		if (sa->s_in.sa_port == 0) {
			return (0);
		}
		if (sa->s_in.sa_addr != htonl(0x7f000001)) {
			return (0);
		}
		return (1);

	case NNG_AF_INET6:
		if (sa->s_in6.sa_port == 0) {
			return (0);
		}
		if (memcmp(sa->s_in6.sa_addr, ipv6, sizeof(ipv6)) != 0) {
			return (0);
		}
		return (1);

	default:
		return (0);
	}
}

static int
check_props(nng_msg *msg)
{
	nng_pipe     p;
	size_t       z;
	nng_sockaddr la;
	nng_sockaddr ra;
	char *       buf;
	size_t       len;

	p = nng_msg_get_pipe(msg);
	So(nng_pipe_id(p) > 0);

	// Typed
	z = sizeof(nng_sockaddr);
	So(nng_pipe_getopt_sockaddr(p, NNG_OPT_LOCADDR, &la) == 0);
	So(z == sizeof(la));
	So(validloopback(&la));

	// Untyped
	z = sizeof(nng_sockaddr);
	So(nng_pipe_getopt(p, NNG_OPT_REMADDR, &ra, &z) == 0);
	So(z == sizeof(ra));
	So(validloopback(&ra));

	// Bad type
	So(nng_pipe_getopt_size(p, NNG_OPT_LOCADDR, &z) == NNG_EBADTYPE);

	// Request header
	z   = 0;
	buf = NULL;
	So(nng_pipe_getopt(p, NNG_OPT_WS_REQUEST_HEADERS, buf, &z) ==
	    NNG_EINVAL);
	So(z > 0);
	len = z;
	So((buf = nng_alloc(len)) != NULL);
	So(nng_pipe_getopt(p, NNG_OPT_WS_REQUEST_HEADERS, buf, &z) == 0);
	So(strstr(buf, "Sec-WebSocket-Key") != NULL);
	So(z == len);
	nng_free(buf, len);
	So(nng_pipe_getopt_string(p, NNG_OPT_WS_REQUEST_HEADERS, &buf) == 0);
	So(strlen(buf) == len - 1);
	nng_strfree(buf);

	// Response header
	z   = 0;
	buf = NULL;
	So(nng_pipe_getopt(p, NNG_OPT_WS_RESPONSE_HEADERS, buf, &z) ==
	    NNG_EINVAL);
	So(z > 0);
	len = z;
	So((buf = nng_alloc(len)) != NULL);
	So(nng_pipe_getopt(p, NNG_OPT_WS_RESPONSE_HEADERS, buf, &z) == 0);
	So(strstr(buf, "Sec-WebSocket-Accept") != NULL);
	So(z == len);
	nng_free(buf, len);
	So(nng_pipe_getopt_string(p, NNG_OPT_WS_RESPONSE_HEADERS, &buf) == 0);
	So(strlen(buf) == len - 1);
	nng_strfree(buf);

	return (0);
}

static int
init_dialer_wss_file(nng_dialer d)
{
	int   rv;
	char *tmpdir;
	char *pth;

	if ((tmpdir = nni_plat_temp_dir()) == NULL) {
		return (NNG_ENOTSUP);
	}
	if ((pth = nni_file_join(tmpdir, "wss_test_cacert.pem")) == NULL) {
		nni_strfree(tmpdir);
		return (NNG_ENOMEM);
	}
	nni_strfree(tmpdir);

	if ((rv = nni_file_put(pth, cert, strlen(cert))) != 0) {
		nni_strfree(pth);
		return (rv);
	}

	rv = nng_dialer_setopt_string(d, NNG_OPT_TLS_CA_FILE, pth);
	nni_file_delete(pth);
	nni_strfree(pth);

	return (rv);
}

static int
init_listener_wss_file(nng_listener l)
{
	int   rv;
	char *tmpdir;
	char *pth;
	char *certkey;

	if ((tmpdir = nni_plat_temp_dir()) == NULL) {
		return (NNG_ENOTSUP);
	}

	if ((pth = nni_file_join(tmpdir, "wss_test_certkey.pem")) == NULL) {
		nni_strfree(tmpdir);
		return (NNG_ENOMEM);
	}
	nni_strfree(tmpdir);

	if ((rv = nni_asprintf(&certkey, "%s\r\n%s\r\n", cert, key)) != 0) {
		nni_strfree(pth);
		return (rv);
	}

	rv = nni_file_put(pth, certkey, strlen(certkey));
	nni_strfree(certkey);
	if (rv != 0) {
		nni_strfree(pth);
		return (rv);
	}

	rv = nng_listener_setopt_string(l, NNG_OPT_TLS_CERT_KEY_FILE, pth);
	if (rv != 0) {
		// We can wind up with EBUSY from the server already
		// running.
		if (rv == NNG_EBUSY) {
			rv = 0;
		}
	}

	nni_file_delete(pth);
	nni_strfree(pth);
	return (rv);
}

TestMain("WebSocket Secure (TLS) Transport (file based)", {

	static trantest tt;

	tt.dialer_init   = init_dialer_wss_file;
	tt.listener_init = init_listener_wss_file;
	tt.tmpl          = "wss://localhost:%u/test";
	tt.proptest      = check_props;

	trantest_test(&tt);

	Convey("Invalid verify works", {
		nng_socket   s1;
		nng_socket   s2;
		nng_listener l;
		char         addr[NNG_MAXADDRLEN];

		So(nng_pair_open(&s1) == 0);
		So(nng_pair_open(&s2) == 0);
		Reset({
			nng_close(s2);
			nng_close(s1);
		});
		trantest_next_address(addr, "wss://:%u/test");
		So(nng_listener_create(&l, s1, addr) == 0);
		So(init_listener_wss_file(l) == 0);
		So(nng_listener_start(l, 0) == 0);
		nng_msleep(100);

		// reset port back one
		trantest_prev_address(addr, "wss://127.0.0.1:%u/test");
		So(nng_setopt_int(s2, NNG_OPT_TLS_AUTH_MODE,
		       NNG_TLS_AUTH_MODE_REQUIRED) == 0);

		So(nng_dial(s2, addr, NULL, 0) == NNG_EPEERAUTH);
	});

	Convey("No verify works", {
		nng_socket   s1;
		nng_socket   s2;
		nng_listener l;
		nng_dialer   d;
		char         addr[NNG_MAXADDRLEN];
		nng_msg *    msg;
		nng_pipe     p;
		bool         b;

		So(nng_pair_open(&s1) == 0);
		So(nng_pair_open(&s2) == 0);
		Reset({
			nng_close(s2);
			nng_close(s1);
		});
		trantest_next_address(addr, "wss://:%u/test");
		So(nng_listener_create(&l, s1, addr) == 0);
		So(init_listener_wss_file(l) == 0);
		So(nng_listener_start(l, 0) == 0);
		nng_msleep(100);

		// reset port back one
		trantest_prev_address(addr, "wss://127.0.0.1:%u/test");
		So(nng_setopt_ms(s2, NNG_OPT_RECVTIMEO, 200) == 0);
		So(nng_dialer_create(&d, s2, addr) == 0);
		So(init_dialer_wss_file(d) == 0);
		So(nng_dialer_setopt_int(d, NNG_OPT_TLS_AUTH_MODE,
		       NNG_TLS_AUTH_MODE_OPTIONAL) == 0);
		So(nng_dialer_setopt_string(
		       d, NNG_OPT_TLS_SERVER_NAME, "example.com") == 0);
		So(nng_dialer_start(d, 0) == 0);
#if 0
		So(nng_setopt_int(s2, NNG_OPT_TLS_AUTH_MODE,
		       NNG_TLS_AUTH_MODE_OPTIONAL) == 0);
		So(nng_setopt_ms(s2, NNG_OPT_RECVTIMEO, 200) == 0);
		So(nng_dial(s2, addr, NULL, 0) == 0);
#endif
		nng_msleep(100);

		So(nng_send(s1, "hello", 6, 0) == 0);
		So(nng_recvmsg(s2, &msg, 0) == 0);
		So(msg != NULL);
		So(nng_msg_len(msg) == 6);
		So(strcmp(nng_msg_body(msg), "hello") == 0);
		p = nng_msg_get_pipe(msg);
		So(nng_pipe_id(p) > 0);
		So(nng_pipe_getopt_bool(p, NNG_OPT_TLS_VERIFIED, &b) == 0);
		So(b == false);
		nng_msg_free(msg);
	});

	Convey("Valid verify works", {
		nng_socket   s1;
		nng_socket   s2;
		nng_listener l;
		nng_dialer   d;
		char         addr[NNG_MAXADDRLEN];
		nng_msg *    msg;
		nng_pipe     p;
		bool         b;

		So(nng_pair_open(&s1) == 0);
		So(nng_pair_open(&s2) == 0);
		Reset({
			nng_close(s2);
			nng_close(s1);
		});
		trantest_next_address(addr, "wss://:%u/test");
		So(nng_listener_create(&l, s1, addr) == 0);
		So(init_listener_wss_file(l) == 0);
		So(nng_listener_start(l, 0) == 0);
		nng_msleep(100);

		// reset port back one
		trantest_prev_address(addr, "wss://localhost:%u/test");
		So(nng_dialer_create(&d, s2, addr) == 0);
		So(init_dialer_wss_file(d) == 0);
		So(nng_setopt_ms(s2, NNG_OPT_RECVTIMEO, 200) == 0);
		So(nng_dialer_start(d, 0) == 0);
		nng_msleep(100);

		So(nng_send(s1, "hello", 6, 0) == 0);
		So(nng_recvmsg(s2, &msg, 0) == 0);
		So(msg != NULL);
		So(nng_msg_len(msg) == 6);
		So(strcmp(nng_msg_body(msg), "hello") == 0);
		p = nng_msg_get_pipe(msg);
		So(nng_pipe_id(p) > 0);
		So(nng_pipe_getopt_bool(p, NNG_OPT_TLS_VERIFIED, &b) == 0);
		So(b == true);
		nng_msg_free(msg);
	});

	nng_fini();
})
