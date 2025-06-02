//
// Copyright 2025 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
// Copyright 2019 Devolutions <info@devolutions.net>
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

#include "mbedtls/version.h" // Must be first in order to pick up version

#include "mbedtls/error.h"
#ifdef MBEDTLS_PSA_CRYPTO_C
#include "psa/crypto.h"
#endif

#include "nng/nng.h"

// We use a common cookie for our application.
#include "mbedtls/ssl_cookie.h"

#include "../tls_engine.h"

// mbedTLS renamed this header for 2.4.0.
#if MBEDTLS_VERSION_MAJOR > 2 || MBEDTLS_VERSION_MINOR >= 4
#include "mbedtls/net_sockets.h"
#else
#include "mbedtls/net.h"
#endif

#include "mbedtls/debug.h"
#include "mbedtls/ssl.h"

#include "core/nng_impl.h"

// pair holds a private key and the associated certificate.
typedef struct {
	mbedtls_x509_crt   crt;
	mbedtls_pk_context key;
	nni_list_node      node;
} pair;

// psk holds an identity and preshared key
typedef struct {
	// NB: Technically RFC 4279 requires this be UTF-8 string, although
	// others suggest making it opaque bytes.  We treat it as a C string,
	// so we cannot support embedded zero bytes.
	char         *identity;
	uint8_t      *key;
	size_t        keylen;
	nni_list_node node;
} psk;

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

#ifdef NNG_TLS_USE_CTR_DRBG
// Use a global RNG if we're going to override the builtin.
static mbedtls_ctr_drbg_context rng_ctx;
static nni_mtx                  rng_lock;
#endif

struct nng_tls_engine_conn {
	void               *tls; // parent conn
	mbedtls_ssl_context ctx;
	nng_time            exp1;
	nng_time            exp2;
};

struct nng_tls_engine_config {
	mbedtls_ssl_config cfg_ctx;
	char              *server_name;
	mbedtls_x509_crt   ca_certs;
	mbedtls_x509_crl   crl;
	int                min_ver;
	int                max_ver;
	nng_tls_mode       mode;
	nni_list           pairs;
	nni_list           psks;
};

static mbedtls_ssl_cookie_ctx mbed_ssl_cookie_ctx;

static void
tls_dbg(void *ctx, int level, const char *file, int line, const char *s)
{
	NNI_ARG_UNUSED(ctx);
	NNI_ARG_UNUSED(level);
	const char *f;
	while ((f = strchr(file, '/')) != NULL) {
		file = f + 1;
	}
	nng_log_debug("MBED", "%s: %d: %s", file, line, s);
}

static int
tls_get_entropy(void *arg, unsigned char *buf, size_t len)
{
	NNI_ARG_UNUSED(arg);
	while (len) {
		uint32_t x = nni_random();
		size_t   n;

		n = len < sizeof(x) ? len : sizeof(x);
		memcpy(buf, &x, n);
		len -= n;
		buf += n;
	}
	return (0);
}

static int
tls_random(void *arg, unsigned char *buf, size_t sz)
{
#ifdef NNG_TLS_USE_CTR_DRBG
	int rv;

	nni_mtx_lock(&rng_lock);
	rv = mbedtls_ctr_drbg_random(&rng_ctx, buf, sz);
	nni_mtx_unlock(&rng_lock);
	return (rv);
#else
	return (tls_get_entropy(arg, buf, sz));
#endif
}

static void
tls_log_err(const char *msgid, const char *context, int errnum)
{
	char errbuf[256];
	mbedtls_strerror(errnum, errbuf, sizeof(errbuf));
	nng_log_err(msgid, "%s: %s", context, errbuf);
}

static void
tls_log_warn(const char *msgid, const char *context, int errnum)
{
	char errbuf[256];
	mbedtls_strerror(errnum, errbuf, sizeof(errbuf));
	nng_log_warn(msgid, "%s: %d - %s", context, errnum, errbuf);
}

// tls_mk_err converts an mbed error to an NNG error.
static struct {
	int tls;
	int nng;
} tls_errs[] = {
#ifdef MBEDTLS_ERR_SSL_NO_CLIENT_CERTIFICATE
	{ MBEDTLS_ERR_SSL_NO_CLIENT_CERTIFICATE, NNG_EPEERAUTH },
#endif
#ifdef MBEDTLS_ERR_SSL_CA_CHAIN_REQUIRED
	{ MBEDTLS_ERR_SSL_CA_CHAIN_REQUIRED, NNG_EPEERAUTH },
#endif
#ifdef MBEDTLS_ERR_SSL_PEER_VERIFY_FAILED
	{ MBEDTLS_ERR_SSL_PEER_VERIFY_FAILED, NNG_EPEERAUTH },
#endif
#ifdef MBEDTLS_ERR_SSL_NO_USABLE_CIPHERSUITE
	{ MBEDTLS_ERR_SSL_NO_USABLE_CIPHERSUITE, NNG_EPEERAUTH },
#endif
	{ MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY, NNG_ECONNREFUSED },
	{ MBEDTLS_ERR_SSL_ALLOC_FAILED, NNG_ENOMEM },
	{ MBEDTLS_ERR_SSL_TIMEOUT, NNG_ETIMEDOUT },
	{ MBEDTLS_ERR_SSL_CONN_EOF, NNG_ECLOSED },
// MbedTLS 3.0 error codes
#ifdef MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE
	{ MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE, NNG_EPEERAUTH },
#endif
#ifdef MBEDTLS_ERR_SSL_BAD_CERTIFICATE
	{ MBEDTLS_ERR_SSL_BAD_CERTIFICATE, NNG_EPEERAUTH },
#endif
	// terminator
	{ 0, 0 },
};

static int
tls_mk_err(int err)
{
	for (int i = 0; tls_errs[i].tls != 0; i++) {
		if (tls_errs[i].tls == err) {
			return (tls_errs[i].nng);
		}
	}
	return (NNG_ECRYPTO);
}

static int
net_send(void *tls, const unsigned char *buf, size_t len)
{
	size_t sz = len;
	int    rv;

	rv = nng_tls_engine_send(tls, buf, &sz);
	switch (rv) {
	case 0:
		return ((int) sz);
	case NNG_EAGAIN:
		return (MBEDTLS_ERR_SSL_WANT_WRITE);
	default:
		return (MBEDTLS_ERR_NET_SEND_FAILED);
	}
}

static int
net_recv(void *tls, unsigned char *buf, size_t len)
{
	size_t sz = len;
	int    rv;

	rv = nng_tls_engine_recv(tls, buf, &sz);
	switch (rv) {
	case 0:
		return ((int) sz);
	case NNG_EAGAIN:
		return (MBEDTLS_ERR_SSL_WANT_READ);
	default:
		return (MBEDTLS_ERR_NET_RECV_FAILED);
	}
}

static void
conn_fini(nng_tls_engine_conn *ec)
{
	mbedtls_ssl_free(&ec->ctx);
}

static void
conn_set_timer(void *arg, unsigned int t1, unsigned int t2)
{
	nng_time             now = nng_clock();
	nng_tls_engine_conn *ec  = arg;
	ec->exp1                 = t1 ? now + t1 : 0;
	ec->exp2                 = t2 ? now + t2 : 0;
}

static int
conn_get_timer(void *arg)
{
	nng_tls_engine_conn *ec  = arg;
	nng_time             now = nng_clock();
	if (ec->exp2 == 0) {
		return -1;
	}
	if (now > ec->exp2) {
		return 2;
	}
	if (now > ec->exp1) {
		return 1;
	}
	return (0);
}

static int
conn_init(nng_tls_engine_conn *ec, void *tls, nng_tls_engine_config *cfg,
    const nng_sockaddr *sa)
{
	int  rv;
	char buf[NNG_MAXADDRSTRLEN];

	ec->tls = tls;

	mbedtls_ssl_init(&ec->ctx);
	mbedtls_ssl_set_bio(&ec->ctx, tls, net_send, net_recv, NULL);
	mbedtls_ssl_set_timer_cb(&ec->ctx, ec, conn_set_timer, conn_get_timer);

	if ((rv = mbedtls_ssl_setup(&ec->ctx, &cfg->cfg_ctx)) != 0) {
		tls_log_warn(
		    "NNG-TLS-CONN-FAIL", "Failed to setup TLS connection", rv);
		return (tls_mk_err(rv));
	}

	mbedtls_ssl_set_hostname(&ec->ctx, cfg->server_name);

	if (cfg->mode == NNG_TLS_MODE_SERVER) {
		nng_str_sockaddr(sa, buf, sizeof(buf));
		mbedtls_ssl_set_client_transport_id(
		    &ec->ctx, (const void *) buf, strlen(buf));
	}

	return (0);
}

static void
conn_close(nng_tls_engine_conn *ec)
{
	// This may succeed, or it may fail.  Either way we
	// don't care. Implementations that depend on
	// close-notify to mean anything are broken by design,
	// just like RFC.  Note that we do *NOT* close the TCP
	// connection at this point.
	(void) mbedtls_ssl_close_notify(&ec->ctx);
}

static int
conn_recv(nng_tls_engine_conn *ec, uint8_t *buf, size_t *szp)
{
	int rv;
	if ((rv = mbedtls_ssl_read(&ec->ctx, buf, *szp)) < 0) {
		switch (rv) {
		case MBEDTLS_ERR_SSL_WANT_READ:
		case MBEDTLS_ERR_SSL_WANT_WRITE:
			return (NNG_EAGAIN);
		default:
			return (tls_mk_err(rv));
		}
	}
	*szp = (size_t) rv;
	return (0);
}

static int
conn_send(nng_tls_engine_conn *ec, const uint8_t *buf, size_t *szp)
{
	int rv;

	if ((rv = mbedtls_ssl_write(&ec->ctx, buf, *szp)) < 0) {
		switch (rv) {
		case MBEDTLS_ERR_SSL_WANT_READ:
		case MBEDTLS_ERR_SSL_WANT_WRITE:
			return (NNG_EAGAIN);
		default:
			return (tls_mk_err(rv));
		}
	}
	*szp = (size_t) rv;
	return (0);
}

static int
conn_handshake(nng_tls_engine_conn *ec)
{
	int rv;

	rv = mbedtls_ssl_handshake(&ec->ctx);
	switch (rv) {
	case MBEDTLS_ERR_SSL_WANT_WRITE:
	case MBEDTLS_ERR_SSL_WANT_READ:
		// We have underlying I/O to complete first.  We will
		// be called again by a callback later.
		return (NNG_EAGAIN);
	case 0:
		// The handshake is done, yay!
		return (0);

	default:
		tls_log_warn("NNG-TLS-HANDSHAKE", "TLS handshake failed", rv);
		return (tls_mk_err(rv));
	}
}

static bool
conn_verified(nng_tls_engine_conn *ec)
{
	return (mbedtls_ssl_get_verify_result(&ec->ctx) == 0);
}

static char *
conn_peer_cn(nng_tls_engine_conn *ec)
{
	const mbedtls_x509_crt *crt = mbedtls_ssl_get_peer_cert(&ec->ctx);
	if (!crt) {
		return (NULL);
	}

	char buf[0x400];
	int  len = mbedtls_x509_dn_gets(buf, sizeof(buf), &crt->subject);
	if (len <= 0) {
		return (NULL);
	}

	const char *pos = strstr(buf, "CN=");
	if (!pos) {
		return (NULL);
	}

	pos += 3;
	len -= (int) (pos - buf - 1);
	if (len <= 1) {
		return (NULL);
	}

	char *rv = malloc(len);
	memcpy(rv, pos, len);
	return (rv);
}

static char **
conn_peer_alt_names(nng_tls_engine_conn *ec)
{
	const mbedtls_x509_crt *crt = mbedtls_ssl_get_peer_cert(&ec->ctx);
	if (!crt) {
		return (NULL);
	}

	const mbedtls_asn1_sequence *seq = &crt->subject_alt_names;

	// get count
	int count = 0;
	do {
		if (seq->buf.len > 0)
			++count;
		seq = seq->next;
	} while (seq);
	if (count == 0)
		return NULL;

	seq = &crt->subject_alt_names;

	// copy strings
	char **rv = malloc((count + 1) * sizeof(char *));
	int    i  = 0;
	do {
		if (seq->buf.len == 0)
			continue;

		rv[i] = malloc(seq->buf.len + 1);
		memcpy(rv[i], seq->buf.p, seq->buf.len);
		rv[i][seq->buf.len] = 0;
		++i;

		seq = seq->next;
	} while (seq);
	rv[i] = NULL;

	return rv;
}

static void
config_fini(nng_tls_engine_config *cfg)
{
	pair *p;
	psk  *psk;

	mbedtls_ssl_config_free(&cfg->cfg_ctx);
#ifdef NNG_TLS_USE_CTR_DRBG
	mbedtls_ctr_drbg_free(&cfg->rng_ctx);
#endif
	mbedtls_x509_crt_free(&cfg->ca_certs);
	mbedtls_x509_crl_free(&cfg->crl);
	if (cfg->server_name) {
		nni_strfree(cfg->server_name);
	}
	while ((p = nni_list_first(&cfg->pairs)) != NULL) {
		nni_list_remove(&cfg->pairs, p);
		mbedtls_x509_crt_free(&p->crt);
		mbedtls_pk_free(&p->key);

		NNI_FREE_STRUCT(p);
	}
	while ((psk = nni_list_first(&cfg->psks)) != NULL) {
		nni_list_remove(&cfg->psks, psk);
		psk_free(psk);
	}
}

static int
config_init(nng_tls_engine_config *cfg, enum nng_tls_mode mode)
{
	int rv;
	int ssl_mode;
	int auth_mode;

	if (mode == NNG_TLS_MODE_SERVER) {
		ssl_mode  = MBEDTLS_SSL_IS_SERVER;
		auth_mode = MBEDTLS_SSL_VERIFY_NONE;
	} else {
		ssl_mode  = MBEDTLS_SSL_IS_CLIENT;
		auth_mode = MBEDTLS_SSL_VERIFY_REQUIRED;
	}

	cfg->mode = mode;
	NNI_LIST_INIT(&cfg->pairs, pair, node);
	NNI_LIST_INIT(&cfg->psks, psk, node);
	mbedtls_ssl_config_init(&cfg->cfg_ctx);
	mbedtls_x509_crt_init(&cfg->ca_certs);
	mbedtls_x509_crl_init(&cfg->crl);

	rv = mbedtls_ssl_config_defaults(&cfg->cfg_ctx, ssl_mode,
	    MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
	if (rv != 0) {
		tls_log_err("NNG-TLS-CONFIG-INIT-FAIL",
		    "Failed to initialize TLS configuration", rv);
		config_fini(cfg);
		return (tls_mk_err(rv));
	}

	mbedtls_ssl_conf_authmode(&cfg->cfg_ctx, auth_mode);

	// We *require* TLS v1.2 or newer, which is also known as SSL
	// v3.3.
	cfg->min_ver = MBEDTLS_SSL_MINOR_VERSION_3;
#ifdef MBEDTLS_SSL_PROTO_TLS1_3
	cfg->max_ver = MBEDTLS_SSL_MINOR_VERSION_4;
#else
	cfg->max_ver = MBEDTLS_SSL_MINOR_VERSION_3;
#endif

	mbedtls_ssl_conf_min_version(
	    &cfg->cfg_ctx, MBEDTLS_SSL_MAJOR_VERSION_3, cfg->min_ver);
	mbedtls_ssl_conf_max_version(
	    &cfg->cfg_ctx, MBEDTLS_SSL_MAJOR_VERSION_3, cfg->max_ver);

	mbedtls_ssl_conf_rng(&cfg->cfg_ctx, tls_random, cfg);
	mbedtls_ssl_conf_dbg(&cfg->cfg_ctx, tls_dbg, cfg);

	if (cfg->mode == NNG_TLS_MODE_SERVER) {
		mbedtls_ssl_conf_dtls_cookies(&cfg->cfg_ctx,
		    mbedtls_ssl_cookie_write, mbedtls_ssl_cookie_check,
		    &mbed_ssl_cookie_ctx);
	}

	return (0);
}

static int
config_server_name(nng_tls_engine_config *cfg, const char *name)
{
	char *dup = NULL;
	if (name != NULL && ((dup = nni_strdup(name)) == NULL)) {
		return (NNG_ENOMEM);
	}
	if (cfg->server_name != NULL) {
		nni_strfree(cfg->server_name);
	}
	cfg->server_name = dup;
	return (0);
}

// callback used on the server side to select the right key
static int
config_psk_cb(void *arg, mbedtls_ssl_context *ssl,
    const unsigned char *identity, size_t id_len)
{
	nng_tls_engine_config *cfg = arg;
	psk                   *psk;
	NNI_LIST_FOREACH (&cfg->psks, psk) {
		if (id_len == strlen(psk->identity) &&
		    (memcmp(identity, psk->identity, id_len) == 0)) {
			nng_log_debug("NNG-TLS-PSK-IDENTITY",
			    "TLS client using PSK identity %s", psk->identity);
			return (mbedtls_ssl_set_hs_psk(
			    ssl, psk->key, psk->keylen));
		}
	}
	nng_log_warn(
	    "NNG-TLS-PSK-NO-IDENTITY", "TLS client PSK identity not found");
	return (MBEDTLS_ERR_SSL_UNKNOWN_IDENTITY);
}

static int
config_psk(nng_tls_engine_config *cfg, const char *identity,
    const uint8_t *key, size_t key_len)
{
	int  rv;
	psk *srch;
	psk *newpsk;

	if (((newpsk = NNI_ALLOC_STRUCT(newpsk)) == NULL) ||
	    ((newpsk->identity = nni_strdup(identity)) == NULL) ||
	    ((newpsk->key = nni_alloc(key_len)) == NULL)) {
		psk_free(newpsk);
		return (NNG_ENOMEM);
	}
	newpsk->keylen = key_len;
	memcpy(newpsk->key, key, key_len);

	if (cfg->mode == NNG_TLS_MODE_SERVER) {
		if (nni_list_empty(&cfg->psks)) {
			mbedtls_ssl_conf_psk_cb(
			    &cfg->cfg_ctx, config_psk_cb, cfg);
		}
	} else {
		if ((rv = mbedtls_ssl_conf_psk(&cfg->cfg_ctx, key, key_len,
		         (const unsigned char *) identity,
		         strlen(identity))) != 0) {
			psk_free(newpsk);
			tls_log_err("NNG-TLS-PSK-FAIL",
			    "Failed to configure PSK identity", rv);
			return (tls_mk_err(rv));
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
	nni_list_append(&cfg->psks, newpsk);
	return (0);
}

static int
config_auth_mode(nng_tls_engine_config *cfg, nng_tls_auth_mode mode)
{
	switch (mode) {
	case NNG_TLS_AUTH_MODE_NONE:
		mbedtls_ssl_conf_authmode(
		    &cfg->cfg_ctx, MBEDTLS_SSL_VERIFY_NONE);
		return (0);
	case NNG_TLS_AUTH_MODE_OPTIONAL:
		mbedtls_ssl_conf_authmode(
		    &cfg->cfg_ctx, MBEDTLS_SSL_VERIFY_OPTIONAL);
		return (0);
	case NNG_TLS_AUTH_MODE_REQUIRED:
		mbedtls_ssl_conf_authmode(
		    &cfg->cfg_ctx, MBEDTLS_SSL_VERIFY_REQUIRED);
		return (0);
	}
	return (NNG_EINVAL);
}

static int
config_ca_chain(nng_tls_engine_config *cfg, const char *certs, const char *crl)
{
	size_t         len;
	const uint8_t *pem;
	int            rv;

	// Certs and CRL are in PEM data, with terminating NUL byte.
	pem = (const uint8_t *) certs;
	len = strlen(certs) + 1;
	if ((rv = mbedtls_x509_crt_parse(&cfg->ca_certs, pem, len)) != 0) {
		tls_log_err("NNG-TLS-CA-FAIL",
		    "Failed to parse CA certificate(s)", rv);
		return (tls_mk_err(rv));
	}
	if (crl != NULL) {
		pem = (const uint8_t *) crl;
		len = strlen(crl) + 1;
		if ((rv = mbedtls_x509_crl_parse(&cfg->crl, pem, len)) != 0) {
			tls_log_err("NNG-TLS-CRL-FAIL",
			    "Failed to parse revocation list", rv);
			return (tls_mk_err(rv));
		}
	}

	mbedtls_ssl_conf_ca_chain(&cfg->cfg_ctx, &cfg->ca_certs, &cfg->crl);
	return (0);
}

static int
config_own_cert(nng_tls_engine_config *cfg, const char *cert, const char *key,
    const char *pass)
{
	size_t         len;
	const uint8_t *pem;
	pair          *p;
	int            rv;

	if ((p = NNI_ALLOC_STRUCT(p)) == NULL) {
		return (NNG_ENOMEM);
	}
	mbedtls_x509_crt_init(&p->crt);
	mbedtls_pk_init(&p->key);

	pem = (const uint8_t *) cert;
	len = strlen(cert) + 1;
	if ((rv = mbedtls_x509_crt_parse(&p->crt, pem, len)) != 0) {
		tls_log_err("NNG-TLS-CRT-FAIL",
		    "Failure parsing our own certificate", rv);
		rv = tls_mk_err(rv);
		goto err;
	}

	pem = (const uint8_t *) key;
	len = strlen(key) + 1;
#if MBEDTLS_VERSION_MAJOR < 3
	rv = mbedtls_pk_parse_key(&p->key, pem, len, (const uint8_t *) pass,
	    pass != NULL ? strlen(pass) : 0);
#else
	rv = mbedtls_pk_parse_key(&p->key, pem, len, (const uint8_t *) pass,
	    pass != NULL ? strlen(pass) : 0, tls_random, NULL);
#endif
	if (rv != 0) {
		tls_log_err("NNG-TLS-KEY", "Failure parsing private key", rv);
		rv = tls_mk_err(rv);
		goto err;
	}

	rv = mbedtls_ssl_conf_own_cert(&cfg->cfg_ctx, &p->crt, &p->key);
	if (rv != 0) {
		tls_log_err("NNG-TLS-SELF",
		    "Failure configuring self certificate", rv);
		rv = tls_mk_err(rv);
		goto err;
	}

	// Save this structure so we can free it with the context.
	nni_list_append(&cfg->pairs, p);
	return (0);

err:
	mbedtls_x509_crt_free(&p->crt);
	mbedtls_pk_free(&p->key);
	NNI_FREE_STRUCT(p);
	return (rv);
}

static int
config_version(nng_tls_engine_config *cfg, nng_tls_version min_ver,
    nng_tls_version max_ver)
{
	int v1, v2;
	int maj = MBEDTLS_SSL_MAJOR_VERSION_3;

	if (min_ver > max_ver) {
		nng_log_err("TLS-CFG-VER",
		    "TLS maximum version must be larger than mimumum version");
		return (NNG_ENOTSUP);
	}
	switch (min_ver) {
#ifdef MBEDTLS_SSL_MINOR_VERSION_3
	case NNG_TLS_1_2:
		v1 = MBEDTLS_SSL_MINOR_VERSION_3;
		break;
#endif
#ifdef MBEDTLS_SSL_PROTO_TLS1_3
	case NNG_TLS_1_3:
		v1 = MBEDTLS_SSL_MINOR_VERSION_4;
		break;
#endif
	default:
		nng_log_err(
		    "TLS-CFG-VER", "TLS minimum version not supported");
		return (NNG_ENOTSUP);
	}

	switch (max_ver) {
#ifdef MBEDTLS_SSL_MINOR_VERSION_3
	case NNG_TLS_1_2:
		v2 = MBEDTLS_SSL_MINOR_VERSION_3;
		break;
#endif
	case NNG_TLS_1_3: // We lack support for 1.3, so treat as 1.2.
#ifdef MBEDTLS_SSL_PROTO_TLS1_3
		v2 = MBEDTLS_SSL_MINOR_VERSION_4;
#else
		v2 = MBEDTLS_SSL_MINOR_VERSION_3;
#endif
		break;
	default:
		// Note that this means that if we ever TLS 1.4 or 2.0,
		// then this will break.  That's sufficiently far out
		// to justify not worrying about it.
		nng_log_err(
		    "TLS-CFG-VER", "TLS maximum version not supported");
		return (NNG_ENOTSUP);
	}

	cfg->min_ver = v1;
	cfg->max_ver = v2;
	mbedtls_ssl_conf_min_version(&cfg->cfg_ctx, maj, cfg->min_ver);
	mbedtls_ssl_conf_max_version(&cfg->cfg_ctx, maj, cfg->max_ver);
	return (0);
}

static nng_tls_engine_config_ops config_ops = {
	.init     = config_init,
	.fini     = config_fini,
	.size     = sizeof(nng_tls_engine_config),
	.auth     = config_auth_mode,
	.ca_chain = config_ca_chain,
	.own_cert = config_own_cert,
	.server   = config_server_name,
	.psk      = config_psk,
	.version  = config_version,
};

static nng_tls_engine_conn_ops conn_ops = {
	.size           = sizeof(nng_tls_engine_conn),
	.init           = conn_init,
	.fini           = conn_fini,
	.close          = conn_close,
	.recv           = conn_recv,
	.send           = conn_send,
	.handshake      = conn_handshake,
	.verified       = conn_verified,
	.peer_cn        = conn_peer_cn,
	.peer_alt_names = conn_peer_alt_names,
};

static nng_tls_engine tls_engine_mbed = {
	.version     = NNG_TLS_ENGINE_VERSION,
	.config_ops  = &config_ops,
	.conn_ops    = &conn_ops,
	.name        = "mbed",
	.description = MBEDTLS_VERSION_STRING_FULL,
	.fips_mode   = false,
};

int
nng_tls_engine_init_mbed(void)
{
	int rv;

#ifdef NNG_TLS_USE_CTR_DRBG
	nni_mtx_init(&rng_lock);

	mbedtls_ctr_drbg_init(&cfg->rng_ctx);
	rv = mbedtls_ctr_drbg_seed(&rng_ctx, tls_get_entropy, NULL, NULL, 0);
	if (rv != 0) {
		tls_log_err("NNG-TLS-RNG", "Failed initializing CTR DRBG", rv);
		nni_mtx_fini(&rng_lock);
		return (rv);
	}
#endif
#ifdef MBEDTLS_PSA_CRYPTO_C
	rv = psa_crypto_init();
	if (rv != 0) {
		tls_log_err(
		    "NNG-TLS-INIT", "Failed initializing PSA crypto", rv);
		return (rv);
	}
#endif
	// Uncomment the following to have noisy debug from mbedTLS.
	// This may be useful when trying to debug failures.
	// mbedtls_debug_set_threshold(9);

	mbedtls_ssl_cookie_init(&mbed_ssl_cookie_ctx);
	rv = mbedtls_ssl_cookie_setup(&mbed_ssl_cookie_ctx, tls_random, NULL);

	if (rv == 0) {
		rv = nng_tls_engine_register(&tls_engine_mbed);
	}

#ifdef NNG_TLS_USE_CTR_DRBG
	if (rv != 0) {
		nni_mtx_fini(&rng_lock);
	}
#endif

	return (rv);
}

void
nng_tls_engine_fini_mbed(void)
{
	mbedtls_ssl_cookie_free(&mbed_ssl_cookie_ctx);
#ifdef NNG_TLS_USE_CTR_DRBG
	mbedtls_ctr_drbg_free(&rng_ctx);
	nni_mtx_fini(&rng_lock);
#endif
#ifdef MBEDTLS_PSA_CRYPTO_C
	mbedtls_psa_crypto_free();
#endif
}
