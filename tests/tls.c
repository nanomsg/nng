//
// Copyright 2017 Garrett D'Amore <garrett@damore.org>
// Copyright 2017 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "convey.h"
#include "nng.h"
#include "protocol/pair1/pair.h"

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
	nng_pipe p;
	size_t   z;
	p = nng_msg_get_pipe(msg);
	So(p > 0);

	Convey("Local address property works", {
		nng_sockaddr la;
		z = sizeof(nng_sockaddr);
		So(nng_pipe_getopt(p, NNG_OPT_LOCADDR, &la, &z) == 0);
		So(z == sizeof(la));
		So(la.s_un.s_family == NNG_AF_INET);
		So(la.s_un.s_in.sa_port == htons(trantest_port - 1));
		So(la.s_un.s_in.sa_port != 0);
		So(la.s_un.s_in.sa_addr == htonl(0x7f000001));
	});

	Convey("Remote address property works", {
		nng_sockaddr ra;
		z = sizeof(nng_sockaddr);
		So(nng_pipe_getopt(p, NNG_OPT_REMADDR, &ra, &z) == 0);
		So(z == sizeof(ra));
		So(ra.s_un.s_family == NNG_AF_INET);
		So(ra.s_un.s_in.sa_port != 0);
		So(ra.s_un.s_in.sa_addr == htonl(0x7f000001));
	});

	return (0);
}

static int
init_tls(trantest *tt)
{
	const char *own[3];

	So(nng_setopt(tt->reqsock, NNG_OPT_TLS_CA_CERT, server_cert,
	       sizeof(server_cert)) == 0);
	own[0] = server_cert;
	own[1] = server_key;
	own[2] = NULL;
	So(nng_setopt(tt->repsock, NNG_OPT_TLS_CERT, server_cert,
	       sizeof(server_cert)) == 0);
	So(nng_setopt(tt->repsock, NNG_OPT_TLS_PRIVATE_KEY, server_key,
	       sizeof(server_key)) == 0);

	return (0);
}

TestMain("TLS Transport", {

	static trantest tt;

	tt.init = init_tls;
	tt.tmpl = "tls://127.0.0.1:%u";

	trantest_test(&tt);

	Convey("We can register the TLS transport",
	    { So(nng_tls_register() == 0); });

	Convey("We cannot connect to wild cards", {
		nng_socket s;
		char       addr[NNG_MAXADDRLEN];

		So(nng_tls_register() == 0);
		So(nng_pair_open(&s) == 0);
		Reset({ nng_close(s); });
		trantest_next_address(addr, "tls://*:%u");
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
		trantest_next_address(addr, "tls://*:%u");
		So(nng_listen(s1, addr, NULL, 0) == 0);
		// reset port back one
		trantest_prev_address(addr, "tls://127.0.0.1:%u");
		So(nng_dial(s2, addr, NULL, 0) == 0);
	});

	Convey("Malformed TLS addresses do not panic", {
		nng_socket s1;

		So(nng_tls_register() == 0);
		So(nng_pair_open(&s1) == 0);
		Reset({ nng_close(s1); });
		So(nng_dial(s1, "tls://127.0.0.1", NULL, 0) == NNG_EADDRINVAL);
		So(nng_dial(s1, "tls://127.0.0.1.32", NULL, 0) ==
		    NNG_EADDRINVAL);
		So(nng_dial(s1, "tls://127.0.x.1.32", NULL, 0) ==
		    NNG_EADDRINVAL);
		So(nng_listen(s1, "tls://127.0.0.1", NULL, 0) ==
		    NNG_EADDRINVAL);
		So(nng_listen(s1, "tls://127.0.0.1.32", NULL, 0) ==
		    NNG_EADDRINVAL);
		So(nng_listen(s1, "tls://127.0.x.1.32", NULL, 0) ==
		    NNG_EADDRINVAL);
	});

	nng_fini();
})
