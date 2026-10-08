//
// Copyright 2026 Staysail Systems, Inc. <info@staysail.tech>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "../../../core/defs.h"
#include "../../../core/list.h"
#include "../../../core/strs.h"
#include "../tls_common.h"
#include "../tls_engine.h"
#include "nng/nng.h"

// library code for openssl
static int ossl_libcode;

// ex data index
static int ossl_ex_index;

// table of openssl errors
static ERR_STRING_DATA ossl_errs[64];

static BIO_METHOD *ossl_tcpm; // TCP stream method
static BIO_METHOD *ossl_udpm; // UDP datagram method

static long ossl_bio_ctrl(BIO *, int, long, void *);

struct nng_tls_engine_conn {
	void        *tls; // parent conn
	SSL_CTX     *ctx;
	SSL         *ssl;
	int          auth_mode;
	nng_tls_mode mode;
	bool         datagram;
	bool         closed;
	bool         timer_active;
	nni_aio      timer;
};

struct nng_tls_engine_cert {
	X509 *crt;
	char *subject;
	char *issuer;
	char  serial[64]; // maximum binary serial is 20 bytes
	int   next_alt;
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

static int
ossl_error(nng_err err)
{
	if ((err & NNG_ESYSERR) == NNG_ESYSERR) {
		return NNG_ESYSERR;
	}
	if ((err & NNG_ETRANERR) == NNG_ETRANERR) {
		return NNG_ETRANERR;
	}
	return (err);
}

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
	SSL_CTX     *ctx;
	X509_STORE  *ca;
	X509        *cert;
	EVP_PKEY    *key;
	nng_tls_mode mode;
	char        *pass;
	char        *server_name;
	int          auth_mode;
	int          min_ver;
	int          max_ver;
	nni_list     psks;
};

static void
tls_log_err(const char *msgid, const char *context, int errnum)
{
	char errbuf[256];
	ERR_error_string_n(errnum, errbuf, sizeof(errbuf));
	nng_log_err(msgid, "%s: %s", context, errbuf);
}

static int
ossl_net_send(BIO *bio, const char *buf, size_t len, size_t *lenp)
{
	void   *ctx = BIO_get_data(bio);
	nng_err rv;
	BIO_clear_retry_flags(bio);

	switch (rv = nng_tls_engine_send(ctx, (const uint8_t *) buf, &len)) {
	case NNG_OK:
		*lenp = len;
		return (1);
	case NNG_EAGAIN:
		BIO_set_retry_write(bio);
		return (-1);
	default:
		ERR_raise(ossl_libcode, ossl_error(rv));
		return (0);
	}
}

static int
ossl_net_recv(BIO *bio, char *buf, size_t len, size_t *lenp)
{
	void   *ctx = BIO_get_data(bio);
	nng_err rv;
	BIO_clear_retry_flags(bio);

	switch (rv = nng_tls_engine_recv(ctx, (uint8_t *) buf, &len)) {
	case NNG_OK:
		*lenp = len;
		return (1);
	case NNG_EAGAIN:
		BIO_set_retry_read(bio);
		return (-1);
	default:
		ERR_raise(ossl_libcode, ossl_error(rv));
		return (0);
	}
}

static long
ossl_dgram_ctrl(BIO *bio, int cmd, long num, void *ptr)
{
	// The transport supplies complete UDP payloads, with room for a full
	// TLS record. Handshake retransmissions use our asynchronous timer,
	// rather than a blocking socket receive timeout.
	switch (cmd) {
	case BIO_CTRL_DGRAM_QUERY_MTU:
	case BIO_CTRL_DGRAM_GET_MTU:
	case BIO_CTRL_DGRAM_GET_FALLBACK_MTU:
		return (NNG_TLS_MAX_SEND_SIZE);
	case BIO_CTRL_DGRAM_SET_MTU:
		return (num);
	case BIO_CTRL_DGRAM_GET_MTU_OVERHEAD:
	case BIO_CTRL_DGRAM_MTU_EXCEEDED:
	case BIO_CTRL_DGRAM_GET_RECV_TIMER_EXP:
	case BIO_CTRL_DGRAM_GET_SEND_TIMER_EXP:
		return (0);
	case BIO_CTRL_DGRAM_SET_NEXT_TIMEOUT:
		return (1);
	default:
		return (ossl_bio_ctrl(bio, cmd, num, ptr));
	}
}

static long
ossl_bio_ctrl(BIO *bio, int cmd, long num, void *ptr)
{
	NNI_ARG_UNUSED(bio);
	NNI_ARG_UNUSED(ptr);
	switch (cmd) {
	case BIO_CTRL_PUSH:
	case BIO_CTRL_FLUSH:
	case BIO_CTRL_POP:
		return (1);
	case BIO_CTRL_GET_KTLS_SEND:
	case BIO_CTRL_GET_KTLS_RECV:
	case BIO_CTRL_PENDING:
	case BIO_CTRL_WPENDING:
		// not supported
		return (0);

	default:
		nng_log_err(
		    "NNG-TLS-BIO", "Unsupported BIO CMD %d num %ld", cmd, num);
		return (0);
	}
}

static void
ossl_init_nng(void)
{
	nng_err i;

	if (ossl_libcode == 0) {
		ossl_libcode = ERR_get_next_error_library();
		// minus 3 to leave room for tran error, sys error, and
		// sentinel
		for (i = 0; i < 64 - 3; i++) {
			const char *err = nng_strerror(i);
			if (strncmp(err, "Unknown error",
			        strlen("Unknown error")) == 0) {
				break;
			}
			ossl_errs[i].error  = ERR_PACK(ossl_libcode, 0, i);
			ossl_errs[i].string = err;
		}
		ossl_errs[i].error  = ERR_PACK(ossl_libcode, 0, NNG_ETRANERR);
		ossl_errs[i].string = "Transport error";
		i++;
		ossl_errs[i].error  = ERR_PACK(ossl_libcode, 0, NNG_ESYSERR);
		ossl_errs[i].string = "Other system error";
		i++;
		ossl_errs[i].error  = 0;
		ossl_errs[i].string = NULL;
		ERR_load_strings(ossl_libcode, ossl_errs);
	}

	if (ossl_tcpm == NULL) {
		int tcpid = BIO_get_new_index();
		ossl_tcpm =
		    BIO_meth_new(tcpid | BIO_TYPE_SOURCE_SINK, "nng_tcp");
		BIO_meth_set_read_ex(ossl_tcpm, ossl_net_recv);
		BIO_meth_set_write_ex(ossl_tcpm, ossl_net_send);
		BIO_meth_set_ctrl(ossl_tcpm, ossl_bio_ctrl);
	}
	if (ossl_udpm == NULL) {
		ossl_udpm = BIO_meth_new(BIO_TYPE_DGRAM, "nng_udp");
		BIO_meth_set_read_ex(ossl_udpm, ossl_net_recv);
		BIO_meth_set_write_ex(ossl_udpm, ossl_net_send);
		BIO_meth_set_ctrl(ossl_udpm, ossl_dgram_ctrl);
	}

	if (ossl_ex_index == 0) {
		ossl_ex_index = CRYPTO_get_ex_new_index(
		    CRYPTO_EX_INDEX_APP, 0, NULL, NULL, NULL, NULL);
	}
}

// Called with the common connection lock held. An earlier wakeup is harmless:
// OpenSSL checks its own deadline before retransmitting.
static void
ossl_timer_schedule(nng_tls_engine_conn *ec)
{
	struct timeval tv;
	nng_duration   ms;
	if (!ec->datagram || ec->closed || ec->timer_active ||
	    !DTLSv1_get_timeout(ec->ssl, &tv)) {
		return;
	}
	ms = (nng_duration) (tv.tv_sec * 1000 + (tv.tv_usec + 999) / 1000);
	ec->timer_active = true;
	nni_sleep_aio(ms, &ec->timer);
}

static void
ossl_timer_cb(void *arg)
{
	nng_tls_engine_conn *ec   = arg;
	nni_tls_conn        *conn = ec->tls;
	int                  rv   = 0;
	if (nni_aio_result(&ec->timer) != NNG_OK) {
		return;
	}
	nni_mtx_lock(&conn->lock);
	ec->timer_active = false;
	if (!ec->closed) {
		ERR_clear_error();
		rv = DTLSv1_handle_timeout(ec->ssl);
		ossl_timer_schedule(ec);
	}
	nni_mtx_unlock(&conn->lock);
	if (rv < 0) {
		nni_tls_close(conn);
	}
}

static void
ossl_conn_fini(nng_tls_engine_conn *ec)
{
	nni_aio_fini(&ec->timer);
	if (ec->ssl != NULL) {
		SSL_free(ec->ssl);
		ec->ssl = NULL;
	}
}

static int
ossl_conn_init(nng_tls_engine_conn *ec, void *tls, nng_tls_engine_config *cfg,
    const nng_sockaddr *sa)
{
	BIO *bio;
	NNI_ARG_UNUSED(sa);
	ec->tls       = tls;
	ec->auth_mode = cfg->auth_mode;
	ec->mode      = cfg->mode;
	ec->datagram  = ((nni_tls_conn *) tls)->msg_oriented;
	nni_aio_init(&ec->timer, ossl_timer_cb, ec);

	if ((bio = BIO_new(ec->datagram ? ossl_udpm : ossl_tcpm)) == NULL) {
		return (NNG_ENOMEM);
	}
	BIO_set_data(bio, tls);
	BIO_set_init(bio, 1);

	if ((ec->ssl = SSL_new(cfg->ctx)) == NULL) {
		BIO_free(bio);
		return (NNG_ENOMEM); // most likely
	}
	switch (ec->mode) {
	case NNG_TLS_MODE_CLIENT:
		SSL_set_connect_state(ec->ssl);
		break;
	case NNG_TLS_MODE_SERVER:
		SSL_set_accept_state(ec->ssl);
		break;
	}

	SSL_set_bio(ec->ssl, bio, bio);
	SSL_set_dh_auto(ec->ssl, true);
	if (ec->datagram) {
		SSL_set_options(ec->ssl, SSL_OP_NO_QUERY_MTU);
		SSL_set_mtu(ec->ssl, NNG_TLS_MAX_SEND_SIZE);
	}

	if (cfg->server_name != NULL) {

		if ((!SSL_set_tlsext_host_name(ec->ssl, cfg->server_name)) ||
		    (!SSL_set1_host(ec->ssl, cfg->server_name))) {

			SSL_free(ec->ssl);
			ec->ssl = NULL;
			return (NNG_ENOMEM);
		}
	}

	return (NNG_OK);
}

static void
ossl_conn_close(nng_tls_engine_conn *ec)
{
	ec->closed = true;
	nni_aio_close(&ec->timer);
	if (ec->ssl != NULL) {
		ERR_clear_error();
		(void) SSL_shutdown(ec->ssl);
	}
}

static int
ossl_conn_recv(nng_tls_engine_conn *ec, uint8_t *buf, size_t *szp)
{
	int    rv;
	size_t n = *szp;
	// SSL_get_error inspects this thread's queue, not just this SSL.
	// Worker threads can retain errors from a different connection.
	ERR_clear_error();
	if ((rv = SSL_read_ex(ec->ssl, buf, n, szp)) <= 0) {
		rv = SSL_get_error(ec->ssl, rv);
		switch (rv) {

		case SSL_ERROR_WANT_READ:
		case SSL_ERROR_WANT_WRITE:
			return (NNG_EAGAIN);
		case SSL_ERROR_ZERO_RETURN:
			// TLS Close Notify.  TCP might still be open.
			nng_log_debug(
			    "NNG-TLS-RECV", "TLS peer closed connection");
			return (NNG_ECONNRESET);
		case SSL_ERROR_SSL:
			tls_log_err("NNG-TLS-RECV", "Receive TLS error",
			    ERR_get_error());
			return (NNG_ECRYPTO);
		case SSL_ERROR_SYSCALL:
			tls_log_err("NNG-TLS-RECV",
			    "Receive TLS SYSCALL error", ERR_get_error());
			return (NNG_ESYSERR);
		default:
			return (NNG_EINTERNAL);
		}
	}
	return (0);
}

static int
ossl_conn_send(nng_tls_engine_conn *ec, const uint8_t *buf, size_t *szp)
{
	int rv;

	ERR_clear_error();
	if ((rv = SSL_write_ex(ec->ssl, buf, (*szp), szp)) <= 0) {
		rv = SSL_get_error(ec->ssl, rv);
		switch (rv) {
		case SSL_ERROR_WANT_READ:
		case SSL_ERROR_WANT_WRITE:
			return (NNG_EAGAIN);
		case SSL_ERROR_SSL:
			tls_log_err(
			    "NNG-TLS-SEND", "Send TLS error", ERR_get_error());
			return (NNG_ECRYPTO);
		case SSL_ERROR_SYSCALL:
			return (NNG_ESYSERR);
		case SSL_ERROR_ZERO_RETURN:
			// TLS Close Notify.  TCP might still be open.
			return (NNG_ECONNRESET);
		default:
			return (NNG_EINTERNAL);
		}
	}
	return (NNG_OK);
}

static int
ossl_conn_handshake(nng_tls_engine_conn *ec)
{
	int rv, err;

	ERR_clear_error();
	rv = SSL_do_handshake(ec->ssl);
	// No other OpenSSL calls may intervene before SSL_get_error.
	err = rv == 1 ? SSL_ERROR_NONE : SSL_get_error(ec->ssl, rv);
	ossl_timer_schedule(ec);
	if (rv == 1) {
		nng_log_debug("NNG-TLS-HS", "TLS handshake complete %s",
		    ec->mode == NNG_TLS_MODE_CLIENT ? "client" : "server");
		return (NNG_OK);
	}
	switch (err) {
	case SSL_ERROR_WANT_WRITE:
	case SSL_ERROR_WANT_READ:
		return (NNG_EAGAIN);
	case SSL_ERROR_ZERO_RETURN:
		tls_log_err("NNG-TLS-CONN-FAIL",
		    "Failed to establish TLS connection", ERR_get_error());
		return (NNG_ECONNRESET);
	case SSL_ERROR_SYSCALL:
		tls_log_err("NNG-TLS-CONN-FAIL",
		    "Failed to setup TLS connection due to system error",
		    ERR_get_error());
		return (NNG_ESYSERR);
	case SSL_ERROR_SSL:
	default:
		// This can fail if we do not have a certificate
		// for the peer.  This will manifest as a failure
		// during nng_dialer_start typically.
		tls_log_err("NNG-TLS-CONN-FAIL",
		    "Failed to setup TLS connection", ERR_get_error());
		return (NNG_ECRYPTO);
	}
	return (0);
}

static bool
ossl_conn_verified(nng_tls_engine_conn *ec)
{
	switch (ec->auth_mode) {
	case NNG_TLS_AUTH_MODE_NONE:
		return (false);
	case NNG_TLS_AUTH_MODE_REQUIRED:
		return (true);
	case NNG_TLS_AUTH_MODE_OPTIONAL:
		if (SSL_get_verify_result(ec->ssl) == X509_V_OK &&
		    SSL_get_peer_certificate(ec->ssl) != NULL) {
			return (true);
		}
		return (false);
	default:
		return (false);
	}
}

static nng_err
ossl_conn_peer_cert(nng_tls_engine_conn *ec, nng_tls_engine_cert **certp)
{
	nng_tls_engine_cert *cert;

	X509 *wc;
	if ((wc = SSL_get_peer_certificate(ec->ssl)) == NULL) {
		return (NNG_ENOENT);
	}
	if ((cert = nni_zalloc(sizeof(*cert))) == NULL) {
		X509_free(wc);
		return (NNG_ENOMEM);
	}
	cert->crt = wc;
	*certp    = cert;
	return (NNG_OK);
}

static char *
ossl_conn_peer_cn(nng_tls_engine_conn *ec)
{
	X509      *cert;
	X509_NAME *xn;
	char      *cn;
	if ((cert = SSL_get_peer_certificate(ec->ssl)) == NULL) {
		return (NULL);
	}
	xn = X509_get_subject_name(cert);
	if (xn == NULL) {
		return (NULL);
	}
	int pos = -1;
	for (;;) {
		X509_NAME_ENTRY *entry;
		pos = X509_NAME_get_index_by_NID(xn, NID_commonName, pos);
		if (pos == -1) {
			return (NULL);
		}
		entry = X509_NAME_get_entry(xn, pos);
		if (entry == NULL) {
			continue;
		}
		ASN1_STRING *as;
		if ((as = X509_NAME_ENTRY_get_data(entry)) == NULL) {
			continue;
		}
		unsigned char *us;
		if (ASN1_STRING_to_UTF8(&us, as) <= 0) {
			continue;
		}
		// We need to use nng_strdup so that nng_strfree works.
		// This is probably not particularly needed for most platforms
		// where nng_free / nng_strfree are thin wrappers around free,
		// but let's be pedantic about it.
		cn = nng_strdup((char *) us);
		free(us);
		return (cn);
	}
	return (NULL);
}

static void
ossl_config_fini(nng_tls_engine_config *cfg)
{
	psk *psk;
	SSL_CTX_free(cfg->ctx);
	X509_STORE_free(cfg->ca);
	X509_free(cfg->cert);
	EVP_PKEY_free(cfg->key);
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
ossl_config_init(nng_tls_engine_config *cfg, enum nng_tls_mode mode)
{
	cfg->mode      = mode;
	cfg->min_ver   = TLS1_2_VERSION;
	cfg->max_ver   = TLS1_3_VERSION;
	cfg->auth_mode = mode == NNG_TLS_MODE_SERVER
	    ? NNG_TLS_AUTH_MODE_NONE
	    : NNG_TLS_AUTH_MODE_REQUIRED;
	NNI_LIST_INIT(&cfg->psks, psk, node);
	// The method is selected on first use, before creating the one
	// context.
	return (NNG_OK);
}

static int
ossl_config_server(nng_tls_engine_config *cfg, const char *name)
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

static unsigned int
psk_client_cb(SSL *ssl, const char *hint, char *identity,
    unsigned int id_max_len, unsigned char *key, unsigned int max_len)
{
	SSL_CTX               *ctx;
	nng_tls_engine_config *cfg;
	psk                   *psk;
	NNI_ARG_UNUSED(hint);

	ctx = SSL_get_SSL_CTX(ssl);
	cfg = SSL_CTX_get_ex_data(ctx, ossl_ex_index);

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
    SSL *ssl, const char *identity, uint8_t *key, unsigned int max_len)
{
	SSL_CTX               *ctx;
	nng_tls_engine_config *cfg;
	psk                   *psk;

	ctx = SSL_get_SSL_CTX(ssl);
	cfg = SSL_CTX_get_ex_data(ctx, ossl_ex_index);

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

static int
ossl_config_psk(nng_tls_engine_config *cfg, const char *identity,
    const uint8_t *key, size_t key_len)
{
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
}

static int
ossl_config_auth_mode(nng_tls_engine_config *cfg, nng_tls_auth_mode mode)
{
	switch (mode) {
	case NNG_TLS_AUTH_MODE_NONE:
	case NNG_TLS_AUTH_MODE_OPTIONAL:
	case NNG_TLS_AUTH_MODE_REQUIRED:
		cfg->auth_mode = mode;
		return (NNG_OK);
	default:
		return (NNG_EINVAL);
	}
}

static int
ossl_get_password(char *passwd, int size, int rw, void *ctx)
{
	NNI_ARG_UNUSED(rw);
	nng_tls_engine_config *cfg = ctx;
	size_t                 len;

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

static int
ossl_config_ca_chain(
    nng_tls_engine_config *cfg, const char *certs, const char *crl)
{
	X509_STORE *cert_store = X509_STORE_new();

	BIO *crtb = BIO_new_mem_buf(certs, -1);

	// certificates first
	X509 *cert;
	while ((cert = PEM_read_bio_X509(crtb, NULL, 0, NULL)) != NULL) {
		X509_STORE_add_cert(cert_store, cert);
		X509_free(cert); // X509_STORE_add_cert takes a reference
	}
	BIO_free(crtb);

	if (crl != NULL) {
		BIO      *crlb = BIO_new_mem_buf(crl, -1);
		X509_CRL *xcrl = PEM_read_bio_X509_CRL(crlb, NULL, NULL, NULL);
		if (xcrl != NULL) {
			X509_STORE_add_crl(cert_store, xcrl);
		}
		BIO_free(crlb);
	}
	X509_STORE_free(cfg->ca);
	cfg->ca = cert_store;

	return (NNG_OK);
}

static int
ossl_config_own_cert(nng_tls_engine_config *cfg, const char *cert,
    const char *key, const char *pass)
{
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

	BIO *crtb = BIO_new_mem_buf(cert, -1);
	BIO *keyb = BIO_new_mem_buf(key, -1);

	X509 *xc = PEM_read_bio_X509(crtb, NULL, 0, NULL);

	if (xc == NULL) {
		BIO_free(crtb);
		BIO_free(keyb);
		tls_log_err(
		    "NNG-TLS-KEY", "Failed to load own cert", ERR_get_error());
		return (NNG_ECRYPTO);
	}

	EVP_PKEY *pkey =
	    PEM_read_bio_PrivateKey(keyb, NULL, ossl_get_password, cfg);
	if (pkey == NULL) {
		BIO_free(crtb);
		BIO_free(keyb);
		X509_free(xc);
		tls_log_err(
		    "NNG-TLS-KEY", "Failed to load own key", ERR_get_error());
		return (NNG_ECRYPTO);
	}

	if (X509_check_private_key(xc, pkey) != 1) {
		BIO_free(crtb);
		BIO_free(keyb);
		X509_free(xc);
		EVP_PKEY_free(pkey);
		return (NNG_ECRYPTO);
	}
	X509_free(cfg->cert);
	EVP_PKEY_free(cfg->key);
	cfg->cert = xc;
	cfg->key  = pkey;
	BIO_free(crtb);
	BIO_free(keyb);
	return (NNG_OK);
}

static int
ossl_config_version(nng_tls_engine_config *cfg, nng_tls_version min_ver,
    nng_tls_version max_ver)
{
	if (min_ver > max_ver || min_ver < NNG_TLS_1_2 ||
	    max_ver > NNG_TLS_1_3) {
		return (NNG_ENOTSUP);
	}
	cfg->min_ver =
	    min_ver == NNG_TLS_1_2 ? TLS1_2_VERSION : TLS1_3_VERSION;
	cfg->max_ver =
	    max_ver == NNG_TLS_1_2 ? TLS1_2_VERSION : TLS1_3_VERSION;
	return (NNG_OK);
}

static int
ossl_config_prepare(nng_tls_engine_config *cfg, bool datagram)
{
	SSL_CTX          *ctx;
	const SSL_METHOD *method;
	int               auth    = SSL_VERIFY_NONE;
	int               min_ver = cfg->min_ver;
	int               max_ver = cfg->max_ver;
	if (datagram) {
		if (min_ver > TLS1_2_VERSION) {
			return (NNG_ENOTSUP);
		}
		method  = cfg->mode == NNG_TLS_MODE_SERVER
		     ? DTLS_server_method()
		     : DTLS_client_method();
		min_ver = max_ver = DTLS1_2_VERSION;
	} else {
		method = cfg->mode == NNG_TLS_MODE_SERVER
		    ? TLS_server_method()
		    : TLS_client_method();
	}
	if ((ctx = SSL_CTX_new(method)) == NULL) {
		return (NNG_ENOMEM);
	}
	if (!SSL_CTX_set_min_proto_version(ctx, min_ver) ||
	    !SSL_CTX_set_max_proto_version(ctx, max_ver) ||
	    (cfg->cert != NULL &&
	        SSL_CTX_use_cert_and_key(ctx, cfg->cert, cfg->key, NULL, 1) !=
	            1)) {
		SSL_CTX_free(ctx);
		return (NNG_ECRYPTO);
	}
	SSL_CTX_set_ex_data(ctx, ossl_ex_index, cfg);
	SSL_CTX_set_dh_auto(ctx, true);
	if (cfg->ca != NULL) {
		SSL_CTX_set1_cert_store(ctx, cfg->ca);
	}
	if (cfg->auth_mode != NNG_TLS_AUTH_MODE_NONE) {
		auth = SSL_VERIFY_PEER;
		if (cfg->auth_mode == NNG_TLS_AUTH_MODE_REQUIRED) {
			auth |= SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
		}
	}
	SSL_CTX_set_verify(ctx, auth, NULL);
	if (!nni_list_empty(&cfg->psks)) {
		if (cfg->mode == NNG_TLS_MODE_SERVER) {
			SSL_CTX_set_psk_server_callback(ctx, psk_server_cb);
		} else {
			SSL_CTX_set_psk_client_callback(ctx, psk_client_cb);
		}
	}
	cfg->ctx = ctx;
	// SSL_CTX now owns its references to the parsed credentials.
	X509_STORE_free(cfg->ca);
	cfg->ca = NULL;
	X509_free(cfg->cert);
	cfg->cert = NULL;
	EVP_PKEY_free(cfg->key);
	cfg->key = NULL;
	nni_strfree(cfg->pass);
	cfg->pass = NULL;
	return (NNG_OK);
}

static void
ossl_cert_free(nng_tls_engine_cert *cert)
{
	if (cert->subject != NULL) {
		OPENSSL_free(cert->subject);
	}
	if (cert->issuer != NULL) {
		OPENSSL_free(cert->issuer);
	}
	if (cert->crt != NULL) {
		X509_free(cert->crt);
	}
	nni_free(cert, sizeof(*cert));
}

static nng_err
ossl_cert_get_der(nng_tls_engine_cert *cert, uint8_t *buf, size_t *sz)
{
	uint8_t *der;
	int      derSz;
	derSz = i2d_X509(cert->crt, &der);
	if (*sz < (size_t) derSz) {
		*sz = (size_t) derSz;
		return (NNG_ENOSPC);
	}
	*sz = (size_t) derSz;
	memcpy(buf, der, *sz);
	OPENSSL_free(der);
	return (NNG_OK);
}

static nng_err
ossl_cert_parse_der(
    nng_tls_engine_cert **crtp, const uint8_t *der, size_t size)
{
	nng_tls_engine_cert *cert;

	if ((cert = nni_zalloc(sizeof(*cert))) == NULL) {
		return (NNG_ENOMEM);
	}
	if ((cert->crt = d2i_X509(NULL, &der, size)) == NULL) {
		nni_free(cert, sizeof(*cert));
		return (NNG_ENOMEM);
	}
	*crtp = cert;
	return (NNG_OK);
}

static nng_err
ossl_cert_parse_pem(nng_tls_engine_cert **crtp, const char *pem, size_t size)
{
	nng_tls_engine_cert *cert;

	if ((cert = nni_zalloc(sizeof(*cert))) == NULL) {
		return (NNG_ENOMEM);
	}
	BIO  *certb = BIO_new_mem_buf(pem, size);
	X509 *xc    = PEM_read_bio_X509(certb, NULL, NULL, NULL);
	BIO_free(certb);

	if (xc == NULL) {
		nni_free(cert, sizeof(*cert));
		return (NNG_ECRYPTO);
	}
	cert->crt = xc;
	*crtp     = cert;
	return (NNG_OK);
}

static nng_err
ossl_cert_subject(nng_tls_engine_cert *cert, char **subject)
{
	X509_NAME *xn;

	if (cert->subject != NULL) {
		*subject = cert->subject;
		return (NNG_OK);
	}

	xn = X509_get_subject_name(cert->crt);
	if (xn == NULL) {
		return (NNG_ENOENT);
	}
	cert->subject = X509_NAME_oneline(xn, NULL, 0);
	*subject      = cert->subject;
	return (NNG_OK);
}

static nng_err
ossl_cert_issuer(nng_tls_engine_cert *cert, char **issuer)
{
	X509_NAME *xn;

	if (cert->issuer != NULL) {
		*issuer = cert->issuer;
		return (NNG_OK);
	}

	xn = X509_get_issuer_name(cert->crt);
	if (xn == NULL) {
		return (NNG_ENOENT);
	}
	cert->issuer = X509_NAME_oneline(xn, NULL, 0);
	*issuer      = cert->issuer;
	return (NNG_OK);
}

static nng_err
ossl_cert_serial(nng_tls_engine_cert *cert, char **serial)
{
	if (cert->serial[0] != 0) {
		*serial = cert->serial;
		return (NNG_OK);
	}

	const ASN1_INTEGER *as  = X509_get0_serialNumber(cert->crt);
	BIGNUM             *bn  = ASN1_INTEGER_to_BN(as, NULL);
	char               *hex = BN_bn2hex(bn);

	if ((as = X509_get0_serialNumber(cert->crt)) == NULL) {
		return (NNG_ENOENT);
	}
	if ((bn = ASN1_INTEGER_to_BN(as, NULL)) == NULL) {
		return (NNG_ENOMEM);
	}
	if ((hex = BN_bn2hex(bn)) == NULL) {
		BN_free(bn);
		return (NNG_ENOMEM);
	}
	snprintf(cert->serial, sizeof(cert->serial), "%s", hex);
	BN_free(bn);
	OPENSSL_free(hex);

	*serial = cert->serial;
	return (NNG_OK);
}

static nng_err
ossl_cert_subject_cn(nng_tls_engine_cert *cert, char **cn)
{
	X509_NAME *xn  = X509_get_subject_name(cert->crt);
	int        pos = -1;
	for (;;) {
		X509_NAME_ENTRY *entry;
		pos = X509_NAME_get_index_by_NID(xn, NID_commonName, pos);
		if (pos == -1) {
			return (NNG_ENOENT);
		}
		entry = X509_NAME_get_entry(xn, pos);
		if (entry == NULL) {
			continue;
		}
		ASN1_STRING *as;
		if ((as = X509_NAME_ENTRY_get_data(entry)) == NULL) {
			continue;
		}
		unsigned char *us;
		if (ASN1_STRING_to_UTF8(&us, as) <= 0) {
			continue;
		}
		// We need to use nng_strdup so that nng_strfree works.
		// This is probably not particularly needed for most platforms
		// where nng_free / nng_strfree are thin wrappers around free,
		// but let's be pedantic about it.
		*cn = nng_strdup((char *) us);
		free(us);
		return (*cn == NULL ? NNG_ENOMEM : NNG_OK);
	}
	return (NNG_ENOENT);
}

static nng_err
ossl_cert_next_alt(nng_tls_engine_cert *cert, char **alt)
{
	GENERAL_NAMES *names = NULL;
	GENERAL_NAME  *san;
	int            num_names;
	nng_err        rv;

	names = X509_get_ext_d2i(cert->crt, NID_subject_alt_name, NULL, NULL);
	if (names == NULL) {
		return (NNG_ENOENT);
	}
	num_names = sk_GENERAL_NAME_num(names);
	if (cert->next_alt >= num_names) {
		sk_GENERAL_NAME_free(names);
		return (NNG_ENOENT);
	}

	san = sk_GENERAL_NAME_value(names, cert->next_alt);
	if (san == NULL) {
		sk_GENERAL_NAME_free(names);
		return (NNG_ENOENT);
	}

	cert->next_alt++;

	*alt = NULL;
	rv   = NNG_OK;

	char                     ip_str[46]; // enough for IPv6
	enum nng_sockaddr_family af = NNG_AF_INET;

	switch (san->type) {
	case GEN_DNS:
		if (san->d.dNSName != NULL && san->d.dNSName->data != NULL) {
			*alt = nng_strdup((char *) san->d.dNSName->data);
		}
		break;
	case GEN_IPADD:
		if (san->d.iPAddress->length == 16) {
			af = NNG_AF_INET6;
		}
		nni_inet_ntop(af, san->d.iPAddress->data, ip_str);
		*alt = nng_strdup(ip_str);
		break;
	// NB: We only return DNS or IP names for now, not emails or other
	// strings.
	default:
		rv = NNG_ENOENT;
		break;
	}
	sk_GENERAL_NAME_free(names);

	if ((*alt == NULL) && (rv == NNG_OK)) {
		rv = NNG_ENOMEM;
	}
	return (rv);
}

static nng_err
ossl_cert_not_before(nng_tls_engine_cert *cert, struct tm *tmp)
{
	ASN1_TIME *when;
	when = X509_get_notBefore(cert->crt);
	ASN1_TIME_to_tm(when, tmp);
	return (NNG_OK);
}

static nng_err
ossl_cert_not_after(nng_tls_engine_cert *cert, struct tm *tmp)
{
	ASN1_TIME *when;
	when = X509_get_notAfter(cert->crt);
	ASN1_TIME_to_tm(when, tmp);
	return (NNG_OK);
}

static nng_err
tls_engine_init(void)
{
	SSL_library_init();
	ossl_init_nng();
	return (NNG_OK);
}

static void
tls_engine_fini(void)
{
}

static bool
fips_mode(void)
{
	return (false); // TODO: Support FIPS mode.
}

static nng_tls_engine_config_ops ossl_config_ops = {
	.init     = ossl_config_init,
	.prepare  = ossl_config_prepare,
	.fini     = ossl_config_fini,
	.size     = sizeof(nng_tls_engine_config),
	.auth     = ossl_config_auth_mode,
	.ca_chain = ossl_config_ca_chain,
	.own_cert = ossl_config_own_cert,
	.server   = ossl_config_server,
	.psk      = ossl_config_psk,
	.version  = ossl_config_version,
};

static nng_tls_engine_conn_ops ossl_conn_ops = {
	.size      = sizeof(nng_tls_engine_conn),
	.init      = ossl_conn_init,
	.fini      = ossl_conn_fini,
	.close     = ossl_conn_close,
	.recv      = ossl_conn_recv,
	.send      = ossl_conn_send,
	.handshake = ossl_conn_handshake,
	.verified  = ossl_conn_verified,
	.peer_cn   = ossl_conn_peer_cn,
	.peer_cert = ossl_conn_peer_cert,
};

static nng_tls_engine_cert_ops ossl_cert_ops = {
	.fini          = ossl_cert_free,
	.get_der       = ossl_cert_get_der,
	.parse_der     = ossl_cert_parse_der,
	.parse_pem     = ossl_cert_parse_pem,
	.subject       = ossl_cert_subject,
	.issuer        = ossl_cert_issuer,
	.serial_number = ossl_cert_serial,
	.subject_cn    = ossl_cert_subject_cn,
	.next_alt_name = ossl_cert_next_alt,
	.not_before    = ossl_cert_not_before,
	.not_after     = ossl_cert_not_after,
};

nng_tls_engine nng_tls_engine_ops = {
	.version     = NNG_TLS_ENGINE_VERSION,
	.config_ops  = &ossl_config_ops,
	.conn_ops    = &ossl_conn_ops,
	.cert_ops    = &ossl_cert_ops,
	.name        = "OpenSSL",
	.description = OPENSSL_VERSION_TEXT,
	.init        = tls_engine_init,
	.fini        = tls_engine_fini,
	.fips_mode   = fips_mode,
};
