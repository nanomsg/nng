//
// Copyright 2024 Staysail Systems, Inc. <info@staysail.tech>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//
// If this software is used with a commercially licensed version of
// wolfSSL, please consider either sponsoring the project on our
// GitHub repository (github.com/nanomsg/nng) or purchasing commercial
// support from Staysail Systems, Inc.  (Contact info@staysail.tech for
// more information about commercial licensing or support packages.)
//
// This software was produced without any contribution or support from wolfSSL.

// Caveats:
//
// 1. WolfSSL has a lot of optional configurations.  We recommend enabling
//    the OpenSSL extra flag to ensure that full support of TLS versions
//    and options are present.
// 2. WolfSSL does not support limiting the "maximum" TLS version.
// 3. WolfSSL does not support checking the validation state of connections.
//    Thus if NNG_TLS_AUTH_MODE_OPTIONAL is requested, then the check
//    for verification will return false because we don't know.

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <wolfssl/ssl.h>

#include "../../../core/nng_impl.h"
#include "nng/nng.h"

#include "../tls_engine.h"

struct nng_tls_engine_conn {
	void        *tls; // parent conn
	WOLFSSL_CTX *ctx;
	WOLFSSL     *ssl;
	int          auth_mode;
};

struct nng_tls_engine_cert {
	WOLFSSL_X509 *crt;
	char         *subject;
	char         *issuer;
	char          serial[64]; // maximum binary serial is 20 bytes
};

typedef struct psk {
	// NB: Technically RFC 4279 requires this be UTF-8 string, although
	// others suggest making it opaque bytes.  We treat it as a C string,
	// so we cannot support embedded zero bytes.
	char         *identity;
	uint8_t      *key;
	size_t        keylen;
	nni_list_node node;
} psk;

#ifdef NNG_WOLF_HAVE_DH
// We supply this as default, because WolfSSL does not include
// it preloaded as some other SSL libraries do.  It's needed if
// DH is in use (and DH algorithms are in the default set).
const char *dh2048 =
    "\n"
    "-----BEGIN DH PARAMETERS-----\n"
    "MIIBCAKCAQEAsKEIBpwIE7pZBjy8MNX1AMFPRKfW70rGJScc6NKWUwpckd2iwpSE\n"
    "v32yRJ+b0sGKxb5yXKfnkebUn3MHhVtmSMdw+rTuAsk9mkraPcFGPhlp0RdGB6NN\n"
    "nyuWFzltMI0q85TTdc+gdebykh8acAWqBINXMPvadpM4UOgn/WPuPOW3yAmub1A1\n"
    "joTOSgDpEn5aMdcz/CETdswWMNsM/MVipzW477ewrMA29tnJRkj5QJAAKxuqbOMa\n"
    "wwsDnhvCRuRITiJzb8Nf1JrWMAdI1oyQq9T28eNI01hLprnNKb9oHwhLY4YvXGvW\n"
    "tgZl96bcAGdru8OpQYP7x/rI4h5+rwA/kwIBAg==\n"
    "-----END DH PARAMETERS-----\n";
#endif

static void
psk_free(psk *p)
{
	if (p != NULL) {
		NNI_ASSERT(!nni_list_node_active(&p->node));
		if (p->identity != NULL) {
			nni_strfree(p->identity);
			p->identity = NULL;
		}
		if (p->key != NULL && p->keylen != 0) {
			nni_free(p->key, p->keylen);
			p->key    = NULL;
			p->keylen = 0;
		}
		NNI_FREE_STRUCT(p);
	}
}

struct nng_tls_engine_config {
	WOLFSSL_CTX *ctx;
	nng_tls_mode mode;
	char        *pass;
	char        *server_name;
	int          auth_mode;
	nni_list     psks;
};

static void
tls_log_err(const char *msgid, const char *context, int errnum)
{
	char errbuf[256];
	wolfSSL_ERR_error_string(errnum, errbuf);
	nng_log_err(msgid, "%s: %s", context, errbuf);
}

static int
wolf_net_send(WOLFSSL *ssl, char *buf, int len, void *ctx)
{
	size_t  sz = len;
	nng_err rv;
	(void) ssl;

	rv = nng_tls_engine_send(ctx, (const uint8_t *) buf, &sz);
	switch (rv) {
	case 0:
		return ((int) sz);
	case NNG_EAGAIN:
		return (WOLFSSL_CBIO_ERR_WANT_WRITE);
	case NNG_ECLOSED:
		return (WOLFSSL_CBIO_ERR_CONN_CLOSE);
	case NNG_ECONNSHUT:
		return (WOLFSSL_CBIO_ERR_CONN_RST);
	default:
		return (WOLFSSL_CBIO_ERR_GENERAL);
	}
}

static int
wolf_net_recv(WOLFSSL *ssl, char *buf, int len, void *ctx)
{
	size_t  sz = len;
	nng_err rv;
	(void) ssl;

	rv = nng_tls_engine_recv(ctx, (uint8_t *) buf, &sz);
	switch (rv) {
	case 0:
		return ((int) sz);
	case NNG_EAGAIN:
		return (WOLFSSL_CBIO_ERR_WANT_READ);
	case NNG_ECLOSED:
		return (WOLFSSL_CBIO_ERR_CONN_CLOSE);
	case NNG_ECONNSHUT:
		return (WOLFSSL_CBIO_ERR_CONN_RST);
	default:
		return (WOLFSSL_CBIO_ERR_GENERAL);
	}
}

static void
wolf_conn_fini(nng_tls_engine_conn *ec)
{
	wolfSSL_free(ec->ssl);
}

static int
wolf_conn_init(nng_tls_engine_conn *ec, void *tls, nng_tls_engine_config *cfg,
    const nng_sockaddr *sa)
{
	NNI_ARG_UNUSED(sa); // for now... revisit if we support DTLS ?
	ec->tls       = tls;
	ec->auth_mode = cfg->auth_mode;

	if ((ec->ssl = wolfSSL_new(cfg->ctx)) == NULL) {
		return (NNG_ENOMEM); // most likely
	}
	if (cfg->server_name != NULL) {
		if (wolfSSL_check_domain_name(ec->ssl, cfg->server_name) !=
		    WOLFSSL_SUCCESS) {
			wolfSSL_free(ec->ssl);
			ec->ssl = NULL;
			return (NNG_ENOMEM);
		}
	}
	wolfSSL_SetIOReadCtx(ec->ssl, ec->tls);
	wolfSSL_SetIOWriteCtx(ec->ssl, ec->tls);
	return (0);
}

static void
wolf_conn_close(nng_tls_engine_conn *ec)
{
	(void) wolfSSL_shutdown(ec->ssl);
}

static int
wolf_conn_recv(nng_tls_engine_conn *ec, uint8_t *buf, size_t *szp)
{
	int rv;
	if ((rv = wolfSSL_read(ec->ssl, buf, (int) *szp)) < 0) {
		rv = wolfSSL_get_error(ec->ssl, rv);
		switch (rv) {

		case SSL_ERROR_WANT_READ:
		case SSL_ERROR_WANT_WRITE:
			return (NNG_EAGAIN);
		case SSL_ERROR_SSL:
			return (NNG_ECRYPTO);
		case SSL_ERROR_SYSCALL:
			return (NNG_ESYSERR);
		default:
			return (NNG_EINTERNAL);
		}
	}
	*szp = (size_t) rv;
	return (0);
}

static int
wolf_conn_send(nng_tls_engine_conn *ec, const uint8_t *buf, size_t *szp)
{
	int rv;

	if ((rv = wolfSSL_write(ec->ssl, buf, (int) (*szp))) <= 0) {
		rv = wolfSSL_get_error(ec->ssl, rv);
		switch (rv) {
		case SSL_ERROR_WANT_READ:
		case SSL_ERROR_WANT_WRITE:
			return (NNG_EAGAIN);
		case SSL_ERROR_SSL:
			return (NNG_ECRYPTO);
		case SSL_ERROR_SYSCALL:
			return (NNG_ESYSERR);
		default:
			return (NNG_EINTERNAL);
		}
	}
	*szp = (size_t) rv;
	return (0);
}

static int
wolf_conn_handshake(nng_tls_engine_conn *ec)
{
	int rv;

	rv = wolfSSL_negotiate(ec->ssl);
	if (rv != WOLFSSL_SUCCESS) {
		rv = wolfSSL_get_error(ec->ssl, rv);
		switch (rv) {
		case WOLFSSL_SUCCESS:
			return (0);
		case WOLFSSL_ERROR_WANT_WRITE:
		case WOLFSSL_ERROR_WANT_READ:
			return (NNG_EAGAIN);
		default:
			// This can fail if we do not have a certificate
			// for the peer.  This will manifest as a failure
			// during nng_dialer_start typically.
			tls_log_err("NNG-TLS-CONN-FAIL",
			    "Failed to setup TLS connection", rv);
			return (NNG_ECRYPTO);
		}
	}
	return (0);
}

static bool
wolf_conn_verified(nng_tls_engine_conn *ec)
{
	switch (ec->auth_mode) {
	case NNG_TLS_AUTH_MODE_NONE:
		return (false);
	case NNG_TLS_AUTH_MODE_REQUIRED:
		return (true);
	case NNG_TLS_AUTH_MODE_OPTIONAL:
#ifdef NNG_WOLFSSL_HAVE_PEER_CERT
		if (wolfSSL_get_peer_certificate(ec->ssl) != NULL) {
			return (true);
		}
#endif
		// If we don't have support for verification, we will
		// just return false, because we can't do anything else.
		return (false);
	default:
		// The client might have supplied us a cert, but wolfSSL
		// is not configured to provide us that information.
		// We ignore it.
		return (false);
	}
}

static nng_err
wolf_conn_peer_cert(nng_tls_engine_conn *ec, nng_tls_engine_cert **certp)
{
#ifdef NNG_WOLFSSL_HAVE_PEER_CERT
	nng_tls_engine_cert *cert;

	WOLFSSL_X509 *wc;
	if ((wc = wolfSSL_get_peer_certificate(ec->ssl)) == NULL) {
		return (NNG_ENOENT);
	}
	if ((cert = nni_zalloc(sizeof(*cert))) == NULL) {
		wolfSSL_X509_free(wc);
		return (NNG_ENOMEM);
	}
	cert->crt = wc;
	*certp    = cert;
	return (NNG_OK);
#else
	NNI_ARG_UNUSED(ec);
	NNI_ARG_UNUSED(certp);
	return (NNG_ENOTSUP);
#endif
}

static char *
wolf_conn_peer_cn(nng_tls_engine_conn *ec)
{
#ifdef NNG_WOLFSSL_HAVE_PEER_CERT
	WOLFSSL_X509 *cert;
	char         *cn;

	if ((cert = wolfSSL_get_peer_certificate(ec->ssl)) == NULL) {
		return (NULL);
	}
	cn = wolfSSL_X509_get_subjectCN(cert);
	if (cn != NULL) {
		cn = nng_strdup(cn);
	}
	return (cn);
#else
	NNI_ARG_UNUSED(ec);
	return (NULL);
#endif
}

static void
wolf_config_fini(nng_tls_engine_config *cfg)
{
	psk *psk;
	wolfSSL_CTX_free(cfg->ctx);
	if (cfg->server_name != NULL) {
		nng_strfree(cfg->server_name);
	}
	if (cfg->pass != NULL) {
		nng_strfree(cfg->pass);
	}

	while ((psk = nni_list_first(&cfg->psks)) != NULL) {
		nni_list_remove(&cfg->psks, psk);
		psk_free(psk);
	}
}

static int
wolf_config_init(nng_tls_engine_config *cfg, enum nng_tls_mode mode)
{
	int             auth_mode;
	int             nng_auth;
	WOLFSSL_METHOD *method;
	int             rv;

	char buf[4096];
	wolfSSL_get_ciphers(buf, sizeof(buf));

	cfg->mode = mode;
	NNI_LIST_INIT(&cfg->psks, psk, node);
	if (mode == NNG_TLS_MODE_SERVER) {
		method    = wolfSSLv23_server_method();
		auth_mode = SSL_VERIFY_NONE;
		nng_auth  = NNG_TLS_AUTH_MODE_NONE;
	} else {
		method    = wolfSSLv23_client_method();
		auth_mode = SSL_VERIFY_PEER;
		nng_auth  = NNG_TLS_AUTH_MODE_REQUIRED;
	}

	cfg->ctx = wolfSSL_CTX_new(method);
	if (cfg->ctx == NULL) {
		return (NNG_ENOMEM);
	}

#ifdef NNG_WOLF_HAVE_DH
	rv = wolfSSL_CTX_SetTmpDH_buffer(cfg->ctx, (uint8_t *) dh2048,
	    strlen(dh2048), WOLFSSL_FILETYPE_PEM);
	if (rv != WOLFSSL_SUCCESS) {
		tls_log_err("NNG-TLS-DH", "Failed loading DH parameter", rv);
		return (NNG_ECRYPTO);
	}
#endif

	// By default we require TLS 1.2.
	rv = wolfSSL_CTX_SetMinVersion(cfg->ctx, WOLFSSL_TLSV1_2);
	if (rv != WOLFSSL_SUCCESS) {
		tls_log_err(
		    "NNG-TLS-VERSION", "Failed setting min TLS version", rv);
		return (NNG_ECRYPTO);
	}
	wolfSSL_CTX_set_verify(cfg->ctx, auth_mode, NULL);

	wolfSSL_SetIORecv(cfg->ctx, wolf_net_recv);
	wolfSSL_SetIOSend(cfg->ctx, wolf_net_send);

	cfg->auth_mode = nng_auth;
	return (0);
}

static int
wolf_config_server(nng_tls_engine_config *cfg, const char *name)
{
	char *dup;
	if ((dup = nng_strdup(name)) == NULL) {
		return (NNG_ENOMEM);
	}
	if (cfg->server_name) {
		nng_strfree(cfg->server_name);
	}
	cfg->server_name = dup;
	return (0);
}

#ifdef NNG_SUPP_TLS_PSK

static unsigned int
psk_client_cb(WOLFSSL *ssl, const char *hint, char *identity,
    unsigned int id_max_len, unsigned char *key, unsigned int max_len)
{
	WOLFSSL_CTX           *ctx;
	nng_tls_engine_config *cfg;
	psk                   *psk;
	NNI_ARG_UNUSED(hint);

	ctx = wolfSSL_get_SSL_CTX(ssl);
	cfg = wolfSSL_CTX_get_psk_callback_ctx(ctx);

	// we ignore the "hint" (its not widely used, and we are electing not
	// to support it)
	if ((psk = nni_list_first(&cfg->psks)) != NULL) {
		strncpy(identity, psk->identity, id_max_len);
		if (max_len < psk->keylen) {
			// key overrun
			nng_log_warn(
			    "NNG-TLS-PSK-LEN", "Preshared key too long");
			return (0);
		}
		memcpy(key, psk->key, psk->keylen);
		return (psk->keylen);
	}
	nng_log_warn("NNG-TLS-PSK-MISSING", "Preshared key missing");
	return (0);
}

static unsigned int
psk_server_cb(
    WOLFSSL *ssl, const char *identity, uint8_t *key, unsigned int max_len)
{
	WOLFSSL_CTX           *ctx;
	nng_tls_engine_config *cfg;
	psk                   *psk;
	ctx = wolfSSL_get_SSL_CTX(ssl);
	cfg = wolfSSL_CTX_get_psk_callback_ctx(ctx);

	// we ignore the "hint" (its not widely used, and we are electing not
	// to support it)
	NNI_LIST_FOREACH (&cfg->psks, psk) {

		if (strcmp(psk->identity, identity) == 0) {
			if (max_len < psk->keylen) {
				// key overrun
				nng_log_warn("NNG-TLS-PSK-LEN",
				    "Preshared key too long");
				return (0);
			}
			nng_log_info("NNG-TLS-PSK-IDENTITY",
			    "TLS client using PSK identity %s", psk->identity);
			memcpy(key, psk->key, psk->keylen);
			return (psk->keylen);
		}
	}
	nng_log_warn(
	    "NNG-TLS-PSK-NO-IDENTITY", "TLS client PSK identity not found");
	return (0);
}
#endif

static int
wolf_config_psk(nng_tls_engine_config *cfg, const char *identity,
    const uint8_t *key, size_t key_len)
{
#ifndef NNG_SUPP_TLS_PSK
	NNI_ARG_UNUSED(cfg);
	NNI_ARG_UNUSED(identity);
	NNI_ARG_UNUSED(key);
	NNI_ARG_UNUSED(key_len);
	return (NNG_ENOTSUP);
#else
	psk *psk, *srch;

	if (key_len > 64) {
		// not exactly sure where the wolfSSL limits are, but this is
		// enough for 512 bits of data.
		nng_log_warn(
		    "NNG-TLS-PSK-TOO-BIG", "PSK key length too large");
		return (NNG_ECRYPTO);
	}
	if (((psk = NNI_ALLOC_STRUCT(psk)) == NULL) ||
	    ((psk->identity = nni_strdup(identity)) == NULL) ||
	    ((psk->key = nni_alloc(key_len)) == NULL)) {
		psk_free(psk);
		return (NNG_ENOMEM);
	}
	memcpy(psk->key, key, key_len);
	psk->keylen = key_len;

	if (nni_list_empty(&cfg->psks)) {
		wolfSSL_CTX_set_psk_callback_ctx(cfg->ctx, cfg);
		if (cfg->mode == NNG_TLS_MODE_SERVER) {
			wolfSSL_CTX_set_psk_server_callback(
			    cfg->ctx, psk_server_cb);
		} else { // client
			wolfSSL_CTX_set_psk_client_callback(
			    cfg->ctx, psk_client_cb);
		}
	}

	// If the identity was previously configured, replace it.
	// The rule here is that last one wins, so we always append.
	NNI_LIST_FOREACH (&cfg->psks, srch) {
		if (strcmp(srch->identity, identity) == 0) {
			nni_list_remove(&cfg->psks, srch);
			psk_free(srch);
			break;
		}
	}

	nni_list_append(&cfg->psks, psk);
	return (0);
#endif
}

static int
wolf_config_auth_mode(nng_tls_engine_config *cfg, nng_tls_auth_mode mode)
{
	cfg->auth_mode = mode;
	// XXX: REMOVE ME
	return (0);
	switch (mode) {
	case NNG_TLS_AUTH_MODE_NONE:
		wolfSSL_CTX_set_verify(cfg->ctx, SSL_VERIFY_NONE, NULL);
		return (0);
	case NNG_TLS_AUTH_MODE_OPTIONAL:
		wolfSSL_CTX_set_verify(cfg->ctx, SSL_VERIFY_PEER, NULL);
		return (0);
	case NNG_TLS_AUTH_MODE_REQUIRED:
		wolfSSL_CTX_set_verify(cfg->ctx,
		    SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
		return (0);
	}
	return (NNG_EINVAL);
}

static int
wolf_config_ca_chain(
    nng_tls_engine_config *cfg, const char *certs, const char *crl)
{
	size_t len;
	int    rv;

	// Certs and CRL are in PEM data, with terminating NUL byte.
	len = strlen(certs);

	rv = wolfSSL_CTX_load_verify_buffer(
	    cfg->ctx, (void *) certs, len, SSL_FILETYPE_PEM);
	if (rv != SSL_SUCCESS) {
		return (NNG_ECRYPTO);
	}
	if (crl == NULL) {
		return (0);
	}

#ifdef NNG_WOLFSSL_HAVE_CRL
	len = strlen(crl);
	rv  = wolfSSL_CTX_LoadCRLBuffer(
            cfg->ctx, (void *) crl, len, SSL_FILETYPE_PEM);
	if (rv != SSL_SUCCESS) {
		return (NNG_ECRYPTO);
	}
#endif

	return (0);
}

#if NNG_WOLFSSL_HAVE_PASSWORD
static int
wolf_get_password(char *passwd, int size, int rw, void *ctx)
{
	// password is *not* NUL terminated in wolf
	nng_tls_engine_config *cfg = ctx;
	size_t                 len;

	(void) rw;

	if (cfg->pass == NULL) {
		return (0);
	}
	len = strlen(cfg->pass); // Our "ctx" is really the password.
	if (len > (size_t) size) {
		len = size;
	}
	memcpy(passwd, cfg->pass, len);
	return (len);
}
#endif

static int
wolf_config_own_cert(nng_tls_engine_config *cfg, const char *cert,
    const char *key, const char *pass)
{
	int rv;

#if NNG_WOLFSSL_HAVE_PASSWORD
	char *dup = NULL;
	if (pass != NULL) {
		if ((dup = nng_strdup(pass)) == NULL) {
			return (NNG_ENOMEM);
		}
	}
	if (cfg->pass != NULL) {
		nng_strfree(cfg->pass);
	}
	cfg->pass = dup;
	wolfSSL_CTX_set_default_passwd_cb_userdata(cfg->ctx, cfg);
	wolfSSL_CTX_set_default_passwd_cb(cfg->ctx, wolf_get_password);
#else
	(void) pass;
#endif

	rv = wolfSSL_CTX_use_certificate_buffer(
	    cfg->ctx, (void *) cert, strlen(cert), SSL_FILETYPE_PEM);
	if (rv != SSL_SUCCESS) {
		return (NNG_EINVAL);
	}
	rv = wolfSSL_CTX_use_PrivateKey_buffer(
	    cfg->ctx, (void *) key, strlen(key), SSL_FILETYPE_PEM);
	if (rv != SSL_SUCCESS) {
		return (NNG_EINVAL);
	}
	return (0);
}

static int
wolf_config_version(nng_tls_engine_config *cfg, nng_tls_version min_ver,
    nng_tls_version max_ver)
{
	int rv;

	if ((min_ver > max_ver) || (max_ver > NNG_TLS_1_3)) {
		return (NNG_ENOTSUP);
	}
	switch (min_ver) {
	case NNG_TLS_1_2:
		rv = wolfSSL_CTX_SetMinVersion(cfg->ctx, WOLFSSL_TLSV1_2);
		break;
	case NNG_TLS_1_3:
		rv = wolfSSL_CTX_SetMinVersion(cfg->ctx, WOLFSSL_TLSV1_3);
		break;
	default:
		return (NNG_ENOTSUP);
	}

	// wolfSSL does not let us restrict the maximum version.

	if (rv != WOLFSSL_SUCCESS) {
		// This happens if the library is missing support for the
		// version.  By default WolfSSL builds with only TLS v1.2
		// and newer enabled.
		return (NNG_ENOTSUP);
	}
	return (0);
}

static void
wolf_cert_free(nng_tls_engine_cert *cert)
{
#ifdef NNG_WOLFSSL_HAVE_PEER_CERT
	if (cert->subject != NULL) {
		wolfSSL_Free(cert->subject);
	}
	if (cert->issuer != NULL) {
		wolfSSL_Free(cert->issuer);
	}
	if (cert->crt != NULL) {
		wolfSSL_X509_free(cert->crt);
	}
	nni_free(cert, sizeof(*cert));
#else
	NNI_ARG_UNUSED(cert);
#endif
}

// In struct nng_tls_engine_cert_ops_s
static nng_err
wolf_cert_get_der(nng_tls_engine_cert *cert, uint8_t *buf, size_t *sz)
{
#ifdef NNG_WOLFSSL_HAVE_PEER_CERT
	const uint8_t *der;
	int            derSz;
	der = wolfSSL_X509_get_der(cert->crt, &derSz);
	if (*sz < (size_t) derSz) {
		*sz = (size_t) derSz;
		return (NNG_ENOSPC);
	}
	*sz = (size_t) derSz;
	memcpy(buf, der, *sz);
	return (NNG_OK);
#else
	NNI_ARG_UNUSED(cert);
	NNI_ARG_UNUSED(buf);
	NNI_ARG_UNUSED(sz);
	return (NNG_ENOTSUP);
#endif
}

static nng_err
wolf_cert_parse_der(
    nng_tls_engine_cert **crtp, const uint8_t *der, size_t size)
{
#ifdef NNG_WOLFSSL_HAVE_PEER_CERT
	WOLFSSL_X509        *x;
	nng_tls_engine_cert *cert;

	if ((cert = nni_zalloc(sizeof(*cert))) == NULL) {
		return (NNG_ENOMEM);
	}
	if ((cert->crt = wolfSSL_X509_d2i(&x, der, size)) == NULL) {
		nni_free(cert, sizeof(*cert));
		return (NNG_ENOMEM);
	}
	*crtp = cert;
	return (NNG_OK);
#else
	NNI_ARG_UNUSED(crtp);
	NNI_ARG_UNUSED(der);
	NNI_ARG_UNUSED(size);
	return (NNG_ENOTSUP);
#endif
}

static nng_err
wolf_cert_parse_pem(nng_tls_engine_cert **crtp, const char *pem, size_t size)
{
	nng_err  rv;
	uint8_t *derBuf;
	int      derSize;

	// DER files are smaller than PEM (PEM is base64 encoded and includes
	// headers)
	if ((derBuf = nni_alloc(size)) == NULL) {
		return (NNG_ENOMEM);
	}

	derSize = wc_CertPemToDer(
	    (const uint8_t *) pem, size, derBuf, size, 0 /* cert type */);
	if (derSize < 0) {
		nni_free(derBuf, size);
		return (NNG_ECRYPTO);
	}

	rv = wolf_cert_parse_der(crtp, derBuf, derSize);
	nni_free(derBuf, size);
	return (rv);
}

static nng_err
wolf_cert_subject(nng_tls_engine_cert *cert, char **subject)
{
#ifdef NNG_WOLFSSL_HAVE_PEER_CERT
	WOLFSSL_X509_NAME *xn;

	if (cert->subject != NULL) {
		*subject = cert->subject;
		return (NNG_OK);
	}

	xn = wolfSSL_X509_get_subject_name(cert->crt);
	if (xn == NULL) {
		return (NNG_ENOENT);
	}
	cert->subject = wolfSSL_X509_NAME_oneline(xn, NULL, 0);
	*subject      = cert->subject;
	return (NNG_OK);
#else
	NNI_ARG_UNUSED(cert);
	NNI_ARG_UNUSED(subject);
	return (NNG_ENOTSUP);
#endif
}

static nng_err
wolf_cert_issuer(nng_tls_engine_cert *cert, char **issuer)
{
#ifdef NNG_WOLFSSL_HAVE_PEER_CERT
	WOLFSSL_X509_NAME *xn;

	if (cert->issuer != NULL) {
		*issuer = cert->issuer;
		return (NNG_OK);
	}

	xn = wolfSSL_X509_get_issuer_name(cert->crt);
	if (xn == NULL) {
		return (NNG_ENOENT);
	}
	cert->issuer = wolfSSL_X509_NAME_oneline(xn, NULL, 0);
	*issuer      = cert->issuer;
	return (NNG_OK);
#else
	NNI_ARG_UNUSED(cert);
	NNI_ARG_UNUSED(issuer);
	return (NNG_ENOTSUP);
#endif
}

static nng_err
wolf_cert_serial(nng_tls_engine_cert *cert, char **serial)
{
#ifdef NNG_WOLFSSL_HAVE_PEER_CERT
	uint8_t num[20]; // max is 20 bytes per RFC
	char   *s;
	int     len;

	if (cert->serial[0] != 0) {
		*serial = cert->serial;
		return (NNG_OK);
	}

	len = sizeof(num);
	wolfSSL_X509_get_serial_number(cert->crt, num, &len);

	s = cert->serial;
	for (int i = 0; i < len; i++) {
		snprintf(s, 4, "%s%02X", i > 0 ? ":" : "", num[i]);
		s += strlen(s);
	}
	*serial = cert->serial;
	return (NNG_OK);
#else
	NNI_ARG_UNUSED(cert);
	NNI_ARG_UNUSED(serial);
	return (NNG_ENOTSUP);
#endif
}

static nng_err
wolf_cert_subject_cn(nng_tls_engine_cert *cert, char **cn)
{
#ifdef NNG_WOLFSSL_HAVE_PEER_CERT
	*cn = wolfSSL_X509_get_subjectCN(cert->crt);
	if (*cn == NULL) {
		return (NNG_ENOENT);
	}
	return (NNG_OK);
#else
	NNI_ARG_UNUSED(cert);
	NNI_ARG_UNUSED(cn);
	return (NNG_ENOTSUP);
#endif
}

static nng_err
wolf_cert_next_alt(nng_tls_engine_cert *cert, char **alt)
{
#ifdef NNG_WOLFSSL_HAVE_PEER_CERT
	*alt = wolfSSL_X509_get_next_altname(cert->crt);
	if (*alt == NULL) {
		return (NNG_ENOENT);
	}
	return (NNG_OK);
#else
	NNI_ARG_UNUSED(cert);
	NNI_ARG_UNUSED(alt);
	return (NNG_ENOTSUP);
#endif
}

static nng_err
wolf_cert_not_before(nng_tls_engine_cert *cert, struct tm *tmp)
{
#ifdef NNG_WOLFSSL_HAVE_PEER_CERT
	WOLFSSL_ASN1_TIME *when;
	when = wolfSSL_X509_get_notBefore(cert->crt);
	wolfSSL_ASN1_TIME_to_tm(when, tmp);
	return (NNG_OK);
#else
	NNI_ARG_UNUSED(cert);
	NNI_ARG_UNUSED(tmp);
	return (NNG_ENOTSUP);
#endif
}

static nng_err
wolf_cert_not_after(nng_tls_engine_cert *cert, struct tm *tmp)
{
#ifdef NNG_WOLFSSL_HAVE_PEER_CERT
	WOLFSSL_ASN1_TIME *when;
	when = wolfSSL_X509_get_notAfter(cert->crt);
	wolfSSL_ASN1_TIME_to_tm(when, tmp);
	return (NNG_OK);
#else
	NNI_ARG_UNUSED(cert);
	NNI_ARG_UNUSED(tmp);
	return (NNG_ENOTSUP);
#endif
}

static void
wolf_logging_cb(const int level, const char *msg)
{
	switch (level) {
	case ERROR_LOG:
		nng_log_err("NNG-WOLFSSL", msg);
		break;
	case INFO_LOG:
		nng_log_info("NNG-WOLFSSL", msg);
		break;
	case ENTER_LOG:
		nng_log_debug("NNG-WOLFSSL-ENTER", msg);
		break;
	case LEAVE_LOG:
		nng_log_debug("NNG-WOLFSSL-ENTER", msg);
		break;
	case OTHER_LOG:
		nng_log_debug("NNG-WOLFSSL", msg);
		break;
	}
}

static nng_err
tls_engine_init(void)
{
	switch (wolfSSL_Init()) {
	case WOLFSSL_SUCCESS:
		break;
	default:
		// Best guess...
		wolfSSL_Cleanup();
		return (NNG_EINTERNAL);
	}
	wolfSSL_SetLoggingCb(wolf_logging_cb);
	// Uncomment for full debug (also WolfSSL needs to be a debug build)
	//
	// wolfSSL_Debugging_ON();
	return (NNG_OK);
}

static void
tls_engine_fini(void)
{
	(void) wolfSSL_Cleanup();
}

static bool
fips_mode(void)
{
	return (false); // TODO: Support FIPS mode.
}

static nng_tls_engine_config_ops wolf_config_ops = {
	.init     = wolf_config_init,
	.fini     = wolf_config_fini,
	.size     = sizeof(nng_tls_engine_config),
	.auth     = wolf_config_auth_mode,
	.ca_chain = wolf_config_ca_chain,
	.own_cert = wolf_config_own_cert,
	.server   = wolf_config_server,
	.psk      = wolf_config_psk,
	.version  = wolf_config_version,
};

static nng_tls_engine_conn_ops wolf_conn_ops = {
	.size      = sizeof(nng_tls_engine_conn),
	.init      = wolf_conn_init,
	.fini      = wolf_conn_fini,
	.close     = wolf_conn_close,
	.recv      = wolf_conn_recv,
	.send      = wolf_conn_send,
	.handshake = wolf_conn_handshake,
	.verified  = wolf_conn_verified,
	.peer_cn   = wolf_conn_peer_cn,
	.peer_cert = wolf_conn_peer_cert,
};

static nng_tls_engine_cert_ops wolf_cert_ops = {
	.fini          = wolf_cert_free,
	.get_der       = wolf_cert_get_der,
	.parse_der     = wolf_cert_parse_der,
	.parse_pem     = wolf_cert_parse_pem,
	.subject       = wolf_cert_subject,
	.issuer        = wolf_cert_issuer,
	.serial_number = wolf_cert_serial,
	.subject_cn    = wolf_cert_subject_cn,
	.next_alt_name = wolf_cert_next_alt,
	.not_before    = wolf_cert_not_before,
	.not_after     = wolf_cert_not_after,
};

nng_tls_engine nng_tls_engine_ops = {
	.version     = NNG_TLS_ENGINE_VERSION,
	.config_ops  = &wolf_config_ops,
	.conn_ops    = &wolf_conn_ops,
	.cert_ops    = &wolf_cert_ops,
	.name        = "wolf",
	.description = "wolfSSL " LIBWOLFSSL_VERSION_STRING,
	.init        = tls_engine_init,
	.fini        = tls_engine_fini,
	.fips_mode   = fips_mode,
};
