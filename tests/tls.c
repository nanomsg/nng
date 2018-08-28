//
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
// Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
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
#include "transport/tls/tls.h"

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
check_props_v4(nng_msg *msg)
{
	nng_pipe     p;
	size_t       z;
	bool         b;
	nng_sockaddr la;
	nng_sockaddr ra;

	p = nng_msg_get_pipe(msg);
	So(nng_pipe_id(p) > 0);

	// Typed access
	So(nng_pipe_getopt_sockaddr(p, NNG_OPT_LOCADDR, &la) == 0);
	So(la.s_family == NNG_AF_INET);
	So(la.s_in.sa_port == htons(trantest_port - 1));
	So(la.s_in.sa_port != 0);
	So(la.s_in.sa_addr == htonl(0x7f000001));

	// Untyped access
	z = sizeof(nng_sockaddr);
	So(nng_pipe_getopt(p, NNG_OPT_REMADDR, &ra, &z) == 0);
	So(z == sizeof(ra));
	So(ra.s_family == NNG_AF_INET);
	So(ra.s_in.sa_port != 0);
	So(ra.s_in.sa_addr == htonl(0x7f000001));

	So(nng_pipe_getopt_bool(p, NNG_OPT_TCP_KEEPALIVE, &b) == 0);
	So(b == false); // default

	So(nng_pipe_getopt_bool(p, NNG_OPT_TCP_NODELAY, &b) == 0);
	So(b == true); // default

	// Check for type enforcement
	int i;
	So(nng_pipe_getopt_int(p, NNG_OPT_REMADDR, &i) == NNG_EBADTYPE);

	z = 1;
	So(nng_pipe_getopt(p, NNG_OPT_REMADDR, &ra, &z) == NNG_EINVAL);

	return (0);
}

static int
init_dialer_tls(nng_dialer d)
{
	nng_tls_config *cfg;
	int             rv;

	if ((rv = nng_tls_config_alloc(&cfg, NNG_TLS_MODE_CLIENT)) != 0) {
		return (rv);
	}

	if ((rv = nng_tls_config_ca_chain(cfg, cert, NULL)) != 0) {
		goto out;
	}

	if ((rv = nng_tls_config_server_name(cfg, "127.0.0.1")) != 0) {
		goto out;
	}
	nng_tls_config_auth_mode(cfg, NNG_TLS_AUTH_MODE_NONE);
	rv = nng_dialer_setopt_ptr(d, NNG_OPT_TLS_CONFIG, cfg);

out:
	nng_tls_config_free(cfg);
	return (rv);
}

static int
init_listener_tls(nng_listener l)
{
	nng_tls_config *cfg;
	int             rv;

	if ((rv = nng_tls_config_alloc(&cfg, NNG_TLS_MODE_SERVER)) != 0) {
		return (rv);
	}
	if ((rv = nng_tls_config_own_cert(cfg, cert, key, NULL)) != 0) {
		goto out;
	}
	if ((rv = nng_listener_setopt_ptr(l, NNG_OPT_TLS_CONFIG, cfg)) != 0) {
		goto out;
	}
out:
	nng_tls_config_free(cfg);
	return (0);
}

static int
init_dialer_tls_file(nng_dialer d)
{
	int   rv;
	char *tmpdir;
	char *pth;

	if ((tmpdir = nni_plat_temp_dir()) == NULL) {
		return (NNG_ENOTSUP);
	}
	if ((pth = nni_file_join(tmpdir, "tls_test_cacert.pem")) == NULL) {
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
init_listener_tls_file(nng_listener l)
{
	int   rv;
	char *tmpdir;
	char *pth;
	char *certkey;

	if ((tmpdir = nni_plat_temp_dir()) == NULL) {
		return (NNG_ENOTSUP);
	}

	if ((pth = nni_file_join(tmpdir, "tls_test_certkey.pem")) == NULL) {
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

TestMain("TLS Transport", {

	static trantest tt;

	tt.dialer_init   = init_dialer_tls;
	tt.listener_init = init_listener_tls;
	tt.tmpl          = "tls+tcp://127.0.0.1:%u";
	tt.proptest      = check_props_v4;
	atexit(nng_fini);

	trantest_test(&tt);

	Convey("We can register the TLS transport",
	    { So(nng_tls_register() == 0); });

	Convey("We cannot connect to wild cards", {
		nng_socket s;
		char       addr[NNG_MAXADDRLEN];

		So(nng_tls_register() == 0);
		So(nng_pair_open(&s) == 0);
		Reset({ nng_close(s); });
		trantest_next_address(addr, "tls+tcp://*:%u");
		So(nng_dial(s, addr, NULL, 0) == NNG_EADDRINVAL);
	});

	Convey("We can bind to wild card", {
		nng_socket s1;
		nng_socket s2;
		char       addr[NNG_MAXADDRLEN];

		So(nng_tls_register() == 0);
		So(nng_pair_open(&s1) == 0);
		So(nng_pair_open(&s2) == 0);
		Reset({
			nng_close(s2);
			nng_close(s1);
		});
		trantest_next_address(addr, "tls+tcp://*:%u");
		So(nng_listen(s1, addr, NULL, 0) == 0);
		// reset port back one
		trantest_prev_address(addr, "tls+tcp://127.0.0.1:%u");
		So(nng_dial(s2, addr, NULL, 0) == 0);
	});

	Convey("We can bind to port zero", {
		nng_socket   s1;
		nng_socket   s2;
		nng_listener l;
		char *       addr;
		size_t       sz;

		So(nng_tls_register() == 0);
		So(nng_pair_open(&s1) == 0);
		So(nng_pair_open(&s2) == 0);
		Reset({
			nng_close(s2);
			nng_close(s1);
		});
		So(nng_listen(s1, "tls+tcp://127.0.0.1:0", &l, 0) == 0);
		sz = NNG_MAXADDRLEN;
		So(nng_listener_getopt_string(l, NNG_OPT_URL, &addr) == 0);
		So(nng_dial(s2, addr, NULL, 0) == 0);
		nng_strfree(addr);
	});

	Convey("Malformed TLS addresses do not panic", {
		nng_socket s1;

		So(nng_tls_register() == 0);
		So(nng_pair_open(&s1) == 0);
		Reset({ nng_close(s1); });

		// Note that if we listen to an unspecified port, then we
		// get a random port.  So we don't look at that.  This allows
		// a user to obtain a port at random and then query to see
		// which one was chosen.

		So(nng_dial(s1, "tls+tcp://127.0.0.1", NULL, 0) ==
		    NNG_EADDRINVAL);
		So(nng_dial(s1, "tls+tcp://127.0.0.1.32", NULL, 0) ==
		    NNG_EADDRINVAL);
		So(nng_dial(s1, "tls+tcp://127.0.x.1.32", NULL, 0) ==
		    NNG_EADDRINVAL);
		So(nng_listen(s1, "tls+tcp://127.0.0.1.32", NULL, 0) ==
		    NNG_EADDRINVAL);
		So(nng_listen(s1, "tls+tcp://127.0.x.1.32", NULL, 0) ==
		    NNG_EADDRINVAL);
	});

#if 0
// We really need to have pipe start/negotiate as one of the key steps during
// connect establish.  Until that happens, we cannot verify the peer.
// See bug #208.
	Convey("Verify works", {
		nng_socket   s1;
		nng_socket   s2;
		nng_listener l;
		char *       buf;
		size_t       sz;
		char         addr[NNG_MAXADDRLEN];

		So(nng_pair_open(&s1) == 0);
		So(nng_pair_open(&s2) == 0);
		Reset({
			nng_close(s2);
			nng_close(s1);
		});
		trantest_next_address(addr, "tls+tcp://:%u");
		So(nng_listener_create(&l, s1, addr) == 0);
		So(init_listener_tls_file(NULL, l) == 0);
		So(nng_listener_start(l, 0) == 0);
		nng_msleep(100);

		// reset port back one
		trantest_prev_address(addr, "tls+tcp://127.0.0.1:%u");
		So(nng_setopt_int(s2, NNG_OPT_TLS_AUTH_MODE,
		       NNG_TLS_AUTH_MODE_REQUIRED) == 0);

		So(nng_dial(s2, addr, NULL, 0) == NNG_EPEERAUTH);
	});
#endif

	Convey("No verify works", {
		nng_socket   s1;
		nng_socket   s2;
		nng_listener l;
		char         addr[NNG_MAXADDRLEN];
		nng_msg *    msg;
		nng_pipe     p;
		bool         b;
		nng_dialer   d;

		So(nng_pair_open(&s1) == 0);
		So(nng_pair_open(&s2) == 0);
		Reset({
			nng_close(s2);
			nng_close(s1);
		});
		trantest_next_address(addr, "tls+tcp://*:%u");
		So(nng_listener_create(&l, s1, addr) == 0);
		So(init_listener_tls_file(l) == 0);
		So(nng_listener_start(l, 0) == 0);
		nng_msleep(100);

		// reset port back one
		trantest_prev_address(addr, "tls+tcp://127.0.0.1:%u");
		So(nng_setopt_ms(s2, NNG_OPT_RECVTIMEO, 200) == 0);
		So(nng_dialer_create(&d, s2, addr) == 0);
		So(init_dialer_tls_file(d) == 0);
		So(nng_dialer_setopt_int(d, NNG_OPT_TLS_AUTH_MODE,
		       NNG_TLS_AUTH_MODE_OPTIONAL) == 0);
		So(nng_dialer_setopt_string(
		       d, NNG_OPT_TLS_SERVER_NAME, "example.com") == 0);
		So(nng_dialer_start(d, 0) == 0);

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
		trantest_next_address(addr, "tls+tcp://*:%u");
		So(nng_listener_create(&l, s1, addr) == 0);
		So(init_listener_tls_file(l) == 0);
		So(nng_listener_start(l, 0) == 0);
		nng_msleep(100);

		// reset port back one
		trantest_prev_address(addr, "tls+tcp://localhost:%u");
		So(nng_dialer_create(&d, s2, addr) == 0);
		So(init_dialer_tls_file(d) == 0);
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
		int i;
		So(nng_pipe_getopt_int(p, NNG_OPT_TLS_VERIFIED, &i) ==
		    NNG_EBADTYPE);
		nng_msg_free(msg);
	});

	Convey("No delay option", {
		nng_socket   s;
		nng_dialer   d;
		nng_listener l;
		bool         v;
		int          x;

		So(nng_pair_open(&s) == 0);
		Reset({ nng_close(s); });
		So(nng_getopt_bool(s, NNG_OPT_TCP_NODELAY, &v) == 0);
		So(v == true);
		So(nng_dialer_create(&d, s, "tcp://127.0.0.1:4999") == 0);
		So(nng_dialer_getopt_bool(d, NNG_OPT_TCP_NODELAY, &v) == 0);
		So(v == true);
		So(nng_dialer_setopt_bool(d, NNG_OPT_TCP_NODELAY, false) == 0);
		So(nng_dialer_getopt_bool(d, NNG_OPT_TCP_NODELAY, &v) == 0);
		So(v == false);
		So(nng_dialer_getopt_int(d, NNG_OPT_TCP_NODELAY, &x) ==
		    NNG_EBADTYPE);
		x = 0;
		So(nng_dialer_setopt_int(d, NNG_OPT_TCP_NODELAY, x) ==
		    NNG_EBADTYPE);
		// This assumes sizeof (bool) != sizeof (int)
		So(nng_dialer_setopt(d, NNG_OPT_TCP_NODELAY, &x, sizeof(x)) ==
		    NNG_EINVAL);

		So(nng_listener_create(&l, s, "tcp://127.0.0.1:4999") == 0);
		So(nng_listener_getopt_bool(l, NNG_OPT_TCP_NODELAY, &v) == 0);
		So(v == true);
		x = 0;
		So(nng_listener_setopt_int(l, NNG_OPT_TCP_NODELAY, x) ==
		    NNG_EBADTYPE);
		// This assumes sizeof (bool) != sizeof (int)
		So(nng_listener_setopt(
		       l, NNG_OPT_TCP_NODELAY, &x, sizeof(x)) == NNG_EINVAL);

		nng_dialer_close(d);
		nng_listener_close(l);

		// Make sure socket wide defaults apply.
		So(nng_setopt_bool(s, NNG_OPT_TCP_NODELAY, true) == 0);
		v = false;
		So(nng_getopt_bool(s, NNG_OPT_TCP_NODELAY, &v) == 0);
		So(v == true);
		So(nng_setopt_bool(s, NNG_OPT_TCP_NODELAY, false) == 0);
		So(nng_dialer_create(&d, s, "tcp://127.0.0.1:4999") == 0);
		So(nng_dialer_getopt_bool(d, NNG_OPT_TCP_NODELAY, &v) == 0);
		So(v == false);
	});

	Convey("Keepalive option", {
		nng_socket   s;
		nng_dialer   d;
		nng_listener l;
		bool         v;
		int          x;

		So(nng_pair_open(&s) == 0);
		Reset({ nng_close(s); });
		So(nng_getopt_bool(s, NNG_OPT_TCP_KEEPALIVE, &v) == 0);
		So(v == false);
		So(nng_dialer_create(&d, s, "tcp://127.0.0.1:4999") == 0);
		So(nng_dialer_getopt_bool(d, NNG_OPT_TCP_KEEPALIVE, &v) == 0);
		So(v == false);
		So(nng_dialer_setopt_bool(d, NNG_OPT_TCP_KEEPALIVE, true) ==
		    0);
		So(nng_dialer_getopt_bool(d, NNG_OPT_TCP_KEEPALIVE, &v) == 0);
		So(v == true);
		So(nng_dialer_getopt_int(d, NNG_OPT_TCP_KEEPALIVE, &x) ==
		    NNG_EBADTYPE);
		x = 1;
		So(nng_dialer_setopt_int(d, NNG_OPT_TCP_KEEPALIVE, x) ==
		    NNG_EBADTYPE);

		So(nng_listener_create(&l, s, "tcp://127.0.0.1:4999") == 0);
		So(nng_listener_getopt_bool(l, NNG_OPT_TCP_KEEPALIVE, &v) ==
		    0);
		So(v == false);
		x = 1;
		So(nng_listener_setopt_int(l, NNG_OPT_TCP_KEEPALIVE, x) ==
		    NNG_EBADTYPE);

		nng_dialer_close(d);
		nng_listener_close(l);

		// Make sure socket wide defaults apply.
		So(nng_setopt_bool(s, NNG_OPT_TCP_KEEPALIVE, false) == 0);
		v = true;
		So(nng_getopt_bool(s, NNG_OPT_TCP_KEEPALIVE, &v) == 0);
		So(v == false);
		So(nng_setopt_bool(s, NNG_OPT_TCP_KEEPALIVE, true) == 0);
		So(nng_dialer_create(&d, s, "tcp://127.0.0.1:4999") == 0);
		So(nng_dialer_getopt_bool(d, NNG_OPT_TCP_KEEPALIVE, &v) == 0);
		So(v == true);
	});

})
