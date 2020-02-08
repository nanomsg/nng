//
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
// Copyright 2020 Staysail Systems, Inc. <info@staysail.tech>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

// TLS tests.

#ifndef _WIN32
#include <arpa/inet.h>
#endif

#include <nng/nng.h>
#include <nng/protocol/pair1/pair.h>
#include <nng/supplemental/tls/tls.h>
#include <nng/transport/tls/tls.h>

#include "convey.h"
#include "stubs.h"
#include "trantest.h"

// These keys are for demonstration purposes ONLY.  DO NOT USE.
// The certificate is valid for 100 years, because I don't want to
// have to regenerate it ever again. The CN is 127.0.0.1, and self-signed.
//
// Generated using openssl:
//
// % openssl ecparam -name secp224r1 -genkey -out  key.key
// % openssl req -new -key key.key -out cert.csr -sha256
// % openssl x509 -req -in cert.csr -days 36500 -out cert.crt
//    -signkey key.key -sha256
//
// Secp224r1 chosen as a least common denominator recommended by NIST-800.
//
//

static const char cert[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBzDCCAXkCCQCNJMf8eYUHxTAKBggqhkjOPQQDAjB2MQswCQYDVQQGEwJVUzEL\n"
    "MAkGA1UECAwCQ0ExEjAQBgNVBAcMCVNhbiBEaWVnbzEUMBIGA1UECgwLbmFub21z\n"
    "Zy5vcmcxHDAaBgNVBAsME1NhbXBsZSBDZXJ0aWZpY2F0ZXMxEjAQBgNVBAMMCWxv\n"
    "Y2FsaG9zdDAgFw0yMDAyMjMxODMwMDZaGA8yMTIwMDEzMDE4MzAwNlowdjELMAkG\n"
    "A1UEBhMCVVMxCzAJBgNVBAgMAkNBMRIwEAYDVQQHDAlTYW4gRGllZ28xFDASBgNV\n"
    "BAoMC25hbm9tc2cub3JnMRwwGgYDVQQLDBNTYW1wbGUgQ2VydGlmaWNhdGVzMRIw\n"
    "EAYDVQQDDAlsb2NhbGhvc3QwTjAQBgcqhkjOPQIBBgUrgQQAIQM6AAS9hA5gYo10\n"
    "jx+gzJdzYbxHzigJYXawdHtyoAud/TT/dUCt0ycpOzTMiO3CoDNxep+/mkmgxjfp\n"
    "ujAKBggqhkjOPQQDAgNBADA+Ah0A9b+GcfbhzzmI2NcYb4auE6XTYJPkPzHt6Adi\n"
    "fwIdAMJO2LEr6WHH6JGLlishVqjF78TtkuB5t+kzneQ=\n"
    "-----END CERTIFICATE-----\n";

static const char key[] =
    "-----BEGIN EC PARAMETERS-----\n"
    "gUrgQQAIQ==\n"
    "-----END EC PARAMETERS-----\n"
    "-----BEGIN EC PRIVATE KEY-----\n"
    "MGgCAQEEHChK068x8MWcBzhpO7qANvW4iTo7E0yzMYFXGn+gBwYFK4EEACGhPAM6\n"
    "AAS9hA5gYo10jx+gzJdzYbxHzigJYXawdHtyoAud/TT/dUCt0ycpOzTMiO3CoDNx\n"
    "ep+/mkmgxjfpug==\n"
    "-----END EC PRIVATE KEY-----\n";

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
init_dialer_tls_ex(nng_dialer d, bool own_cert)
{
	nng_tls_config *cfg;
	int             rv;

	if ((rv = nng_tls_config_alloc(&cfg, NNG_TLS_MODE_CLIENT)) != 0) {
		return (rv);
	}

	if ((rv = nng_tls_config_ca_chain(cfg, cert, NULL)) != 0) {
		goto out;
	}

	if ((rv = nng_tls_config_server_name(cfg, "localhost")) != 0) {
		goto out;
	}
	nng_tls_config_auth_mode(cfg, NNG_TLS_AUTH_MODE_REQUIRED);

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
init_dialer_tls(nng_dialer d)
{
	return (init_dialer_tls_ex(d, false));
}

static int
init_listener_tls_ex(nng_listener l, int auth_mode)
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
	switch (auth_mode) {
	case NNG_TLS_AUTH_MODE_REQUIRED:
	case NNG_TLS_AUTH_MODE_OPTIONAL:
		if ((rv = nng_tls_config_ca_chain(cfg, cert, NULL)) != 0) {
			goto out;
		}
		break;
	default:
		break;
	}
	if ((rv = nng_tls_config_auth_mode(cfg, auth_mode)) != 0) {
		goto out;
	}
out:
	nng_tls_config_free(cfg);
	return (0);
}

static int
init_listener_tls(nng_listener l)
{
	return (init_listener_tls_ex(l, NNG_TLS_AUTH_MODE_NONE));
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

	if (strcmp(nng_tls_engine_name(), "none") == 0) {
		Skip("TLS not enabled");
	}

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
		nng_socket   s1;
		nng_socket   s2;
		char         addr[NNG_MAXADDRLEN];
		nng_listener l;
		nng_dialer   d;

		So(nng_tls_register() == 0);
		So(nng_pair_open(&s1) == 0);
		So(nng_pair_open(&s2) == 0);
		Reset({
			nng_close(s2);
			nng_close(s1);
		});
		trantest_next_address(addr, "tls+tcp://*:%u");
		So(nng_listener_create(&l, s1, addr) == 0);
		So(init_listener_tls(l) == 0);
		// reset port back one
		trantest_prev_address(addr, "tls+tcp://127.0.0.1:%u");
		So(nng_dialer_create(&d, s2, addr) == 0);
		So(init_dialer_tls(d) == 0);
		So(nng_dialer_setopt_int(
		       d, NNG_OPT_TLS_AUTH_MODE, NNG_TLS_AUTH_MODE_NONE) == 0);
		So(nng_listener_start(l, 0) == 0);
		So(nng_dialer_start(d, 0) == 0);
	});

	SkipConvey("We can bind to port zero", {
		nng_socket   s1;
		nng_socket   s2;
		nng_listener l;
		nng_dialer   d;
		char *       addr;

		So(nng_tls_register() == 0);
		So(nng_pair_open(&s1) == 0);
		So(nng_pair_open(&s2) == 0);
		Reset({
			nng_close(s2);
			nng_close(s1);
		});
		So(nng_listener_create(&l, s1, "tls+tcp://127.0.0.1:0") == 0);
		So(init_listener_tls(l) == 0);
		So(nng_listener_start(l, 0) == 0);
		So(nng_listener_getopt_string(l, NNG_OPT_URL, &addr) == 0);
		So(nng_dialer_create(&d, s2, addr) == 0);
		So(init_dialer_tls(d) == 0);
		So(nng_dialer_setopt_int(
		       d, NNG_OPT_TLS_AUTH_MODE, NNG_TLS_AUTH_MODE_NONE) == 0);
		So(nng_dialer_start(d, 0) == 0);
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

	Convey("We can use local interface to connect", {
		nng_socket   s1;
		nng_socket   s2;
		nng_listener l;
		nng_dialer   d;
		char         addr[NNG_MAXADDRLEN];

		So(nng_pair_open(&s1) == 0);
		So(nng_pair_open(&s2) == 0);
		Reset({
			nng_close(s2);
			nng_close(s1);
		});
		trantest_next_address(addr, "tls+tcp://127.0.0.1:%u");
		So(nng_listener_create(&l, s1, addr) == 0);
		So(init_listener_tls(l) == 0);
		So(nng_listener_start(l, 0) == 0);
		// reset port back one
		trantest_prev_address(
		    addr, "tls+tcp://127.0.0.1;127.0.0.1:%u");
		So(nng_dialer_create(&d, s2, addr) == 0);
		So(init_dialer_tls(d) == 0);
		So(nng_dialer_start(d, 0) == 0);
	});

	Convey("Botched local interfaces fail reasonably", {
		nng_socket s1;

		So(nng_pair_open(&s1) == 0);
		Reset({ nng_close(s1); });
		So(nng_dial(s1, "tcp://1x.2;127.0.0.1:80", NULL, 0) ==
		    NNG_EADDRINVAL);
	});

	Convey("Can't specify address that isn't ours", {
		nng_socket s1;

		So(nng_pair_open(&s1) == 0);
		Reset({ nng_close(s1); });
		So(nng_dial(s1, "tcp://8.8.8.8;127.0.0.1:80", NULL, 0) ==
		    NNG_EADDRINVAL);
	});

	// We really need to have pipe start/negotiate as one of the key steps
	// during connect establish.  Until that happens, we cannot verify the
	// peer. See bug #208.
	SkipConvey("Verify works", {
		nng_socket   s1;
		nng_socket   s2;
		nng_listener l;
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

	Convey("No verify works", {
		nng_socket   s1; // server
		nng_socket   s2; // client
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
		So(nng_listener_setopt_int(l, NNG_OPT_TLS_AUTH_MODE,
		       NNG_TLS_AUTH_MODE_OPTIONAL) == 0);
		So(nng_listener_start(l, 0) == 0);
		nng_msleep(100);

		// reset port back one
		trantest_prev_address(addr, "tls+tcp://127.0.0.1:%u");
		So(nng_setopt_ms(s2, NNG_OPT_RECVTIMEO, 200) == 0);
		So(nng_dialer_create(&d, s2, addr) == 0);
		So(init_dialer_tls_file(d) == 0);
		So(nng_dialer_setopt_string(
		       d, NNG_OPT_TLS_SERVER_NAME, "localhost") == 0);
		So(nng_dialer_start(d, 0) == 0);

		So(nng_send(s2, "hello", 6, 0) == 0);
		So(nng_recvmsg(s1, &msg, 0) == 0);
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
		trantest_next_address(addr, "tls+tcp4://*:%u");
		So(nng_listener_create(&l, s1, addr) == 0);
		So(init_listener_tls_ex(l, NNG_TLS_AUTH_MODE_REQUIRED) == 0);
		So(nng_listener_start(l, 0) == 0);

		nng_msleep(100);

		// reset port back one
		trantest_prev_address(addr, "tls+tcp4://localhost:%u");
		So(nng_dialer_create(&d, s2, addr) == 0);
		So(init_dialer_tls_ex(d, true) == 0);

		So(nng_setopt_ms(s2, NNG_OPT_RECVTIMEO, 200) == 0);
		So(nng_dialer_start(d, 0) == 0);
		nng_msleep(100);

		// send from the server to the client-- the client always
		// verifies the server.
		So(nng_send(s2, "hello", 6, 0) == 0);
		So(nng_recvmsg(s1, &msg, 0) == 0);
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
