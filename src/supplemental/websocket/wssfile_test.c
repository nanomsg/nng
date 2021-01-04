//
// Copyright 2020 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "core/nng_impl.h"

#include <nuts.h>

#ifdef NNG_SUPP_TLS
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

#define CACERT "wss_test_ca_cert.pem"
#define CERT_KEY "wss_test_cert_key.pem"

static void
init_dialer_wss_file(nng_dialer d)
{
	char *tmpdir;
	char *pth;

	NUTS_ASSERT((tmpdir = nni_plat_temp_dir()) != NULL);
	NUTS_ASSERT((pth = nni_file_join(tmpdir, CACERT)) != NULL);
	nng_strfree(tmpdir);
	NUTS_PASS(nni_file_put(pth, cert, strlen(cert)));
	NUTS_PASS(nng_dialer_set_string(d, NNG_OPT_TLS_CA_FILE, pth));
	nni_file_delete(pth);
	nng_strfree(pth);
}

static void
init_listener_wss_file(nng_listener l)
{
	char *tmpdir;
	char *pth;
	char *cert_key;

	NUTS_ASSERT((tmpdir = nni_plat_temp_dir()) != NULL);
	NUTS_ASSERT((pth = nni_file_join(tmpdir, CERT_KEY)) != NULL);
	nng_strfree(tmpdir);

	NUTS_PASS(nni_asprintf(&cert_key, "%s\r\n%s\r\n", cert, key));

	NUTS_PASS(nni_file_put(pth, cert_key, strlen(cert_key)));
	nng_strfree(cert_key);
	NUTS_PASS(nng_listener_set_string(l, NNG_OPT_TLS_CERT_KEY_FILE, pth));

	nni_file_delete(pth);
	nng_strfree(pth);
}

static void
test_invalid_verify(void)
{
	uint16_t     port = nuts_next_port();
	nng_socket   s1;
	nng_socket   s2;
	nng_listener l;
	nng_dialer   d;
	char         addr[40];

	(void) snprintf(addr, sizeof(addr), "wss4://:%u/test", port);

	NUTS_PASS(nng_pair_open(&s1));
	NUTS_PASS(nng_pair_open(&s2));
	NUTS_PASS(nng_listener_create(&l, s1, addr));
	init_listener_wss_file(l);
	NUTS_PASS(nng_listener_start(l, 0));

	nng_msleep(100);

	snprintf(addr, sizeof(addr), "wss://127.0.0.1:%u/test", port);

	// We find that sometimes this fails due to NNG_EPEERAUTH, but it
	// can also fail due to NNG_ECLOSED.  This seems to be timing
	// dependent, based on receive vs. send timing most likely.
	// Applications shouldn't really depend that much on this.
	int rv;

	NUTS_PASS(nng_dialer_create(&d, s2, addr));
	NUTS_PASS(nng_dialer_set_int(
	    d, NNG_OPT_TLS_AUTH_MODE, NNG_TLS_AUTH_MODE_REQUIRED));
	rv = nng_dialer_start(d, 0);

	NUTS_TRUE(rv != 0);
	NUTS_TRUE((rv == NNG_EPEERAUTH) || (rv == NNG_ECLOSED) ||
	    (rv == NNG_ECRYPTO));

	NUTS_PASS(nng_close(s1));
	NUTS_PASS(nng_close(s2));
}

static void
test_no_verify(void)
{
	nng_socket   s1;
	nng_socket   s2;
	nng_listener l;
	nng_dialer   d;
	char         addr[64];
	nng_msg *    msg;
	nng_pipe     p;
	bool         b;
	uint16_t     port;

	NUTS_PASS(nng_pair_open(&s1));
	NUTS_PASS(nng_pair_open(&s2));
	NUTS_PASS(nng_socket_set_ms(s1, NNG_OPT_SENDTIMEO, 5000));
	NUTS_PASS(nng_socket_set_ms(s2, NNG_OPT_RECVTIMEO, 5000));

	port = nuts_next_port();
	(void) snprintf(addr, sizeof(addr), "wss4://:%u/test", port);
	NUTS_PASS(nng_listener_create(&l, s1, addr));
	init_listener_wss_file(l);
	NUTS_PASS(nng_listener_start(l, 0));

	nng_msleep(100);
	snprintf(addr, sizeof(addr), "wss://127.0.0.1:%u/test", port);
	NUTS_PASS(nng_dialer_create(&d, s2, addr));
	init_dialer_wss_file(d);
	NUTS_PASS(nng_dialer_set_int(
	    d, NNG_OPT_TLS_AUTH_MODE, NNG_TLS_AUTH_MODE_OPTIONAL));
	NUTS_PASS(
	    nng_dialer_set_string(d, NNG_OPT_TLS_SERVER_NAME, "example.com"));

	NUTS_PASS(nng_dialer_start(d, 0));
	nng_msleep(100);

	NUTS_PASS(nng_send(s1, "hello", 6, 0));
	NUTS_PASS(nng_recvmsg(s2, &msg, 0));
	NUTS_ASSERT(msg != NULL);
	NUTS_TRUE(nng_msg_len(msg) == 6);
	NUTS_MATCH(nng_msg_body(msg), "hello");

	p = nng_msg_get_pipe(msg);
	NUTS_TRUE(nng_pipe_id(p) > 0);
	NUTS_PASS(nng_pipe_get_bool(p, NNG_OPT_TLS_VERIFIED, &b));
	NUTS_TRUE(b == false);

	nng_msg_free(msg);
	NUTS_CLOSE(s1);
	NUTS_CLOSE(s2);
}

static void
test_verify_works(void)
{
	nng_socket   s1;
	nng_socket   s2;
	nng_listener l;
	nng_dialer   d;
	char         addr[NNG_MAXADDRLEN];
	nng_msg *    msg;
	nng_pipe     p;
	bool         b;
	uint16_t     port;

	NUTS_PASS(nng_pair_open(&s1));
	NUTS_PASS(nng_pair_open(&s2));
	NUTS_PASS(nng_socket_set_ms(s1, NNG_OPT_SENDTIMEO, 5000));
	NUTS_PASS(nng_socket_set_ms(s2, NNG_OPT_RECVTIMEO, 5000));
	port = nuts_next_port();
	(void) snprintf(addr, sizeof(addr), "wss4://:%u/test", port);
	NUTS_PASS(nng_listener_create(&l, s1, addr));
	init_listener_wss_file(l);
	NUTS_PASS(nng_listener_start(l, 0));

	// It can take a bit for the listener to start up in clouds.
	nng_msleep(200);
	snprintf(addr, sizeof(addr), "wss4://localhost:%u/test", port);
	NUTS_PASS(nng_dialer_create(&d, s2, addr));
	init_dialer_wss_file(d);

	NUTS_PASS(nng_dialer_start(d, 0));
	nng_msleep(100);

	NUTS_SEND(s1, "hello");
	NUTS_PASS(nng_recvmsg(s2, &msg, 0));
	NUTS_ASSERT(msg != NULL);
	NUTS_TRUE(nng_msg_len(msg) == 6);
	NUTS_MATCH(nng_msg_body(msg), "hello");

	p = nng_msg_get_pipe(msg);
	NUTS_TRUE(nng_pipe_id(p) > 0);
	NUTS_PASS(nng_pipe_get_bool(p, NNG_OPT_TLS_VERIFIED, &b));
	NUTS_TRUE(b == true);

	nng_msg_free(msg);
	NUTS_PASS(nng_close(s1));
	NUTS_PASS(nng_close(s2));
}

static void
test_cert_file_not_present(void)
{
	nng_socket   s1;
	nng_listener l;

	NUTS_PASS(nng_pair_open(&s1));
	NUTS_PASS(nng_listener_create(&l, s1, "wss4://:0/test"));

	NUTS_FAIL(nng_listener_set_string(
	              l, NNG_OPT_TLS_CERT_KEY_FILE, "no-such-file.pem"),
	    NNG_ENOENT);

	NUTS_PASS(nng_close(s1));
}

#endif

NUTS_TESTS = {
#ifdef NNG_SUPP_TLS
	{ "wss file invalid verify", test_invalid_verify },
	{ "wss file no verify", test_no_verify },
	{ "wss file verify works", test_verify_works },
	{ "wss file ca cert missing", test_cert_file_not_present },
#endif
	{ NULL, NULL },
};
