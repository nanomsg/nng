//
// Copyright 2017 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2017 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#ifndef NNG_SUPPLEMENTAL_TLS_H
#define NNG_SUPPLEMENTAL_TLS_H

// nni_tls represents the context for a single TLS stream.
typedef struct nni_tls nni_tls;

// nni_tls_config is the context for full TLS configuration, normally
// associated with an endpoint, for example.
typedef struct nni_tls_config nni_tls_config;

#define NNI_TLS_CONFIG_SERVER 1
#define NNI_TLS_CONFIG_CLIENT 0

extern int  nni_tls_config_init(nni_tls_config **, int);
extern void nni_tls_config_fini(nni_tls_config *);

// nni_tls_config_server_name is used by clients to set the server name
// that they expect to be talking to.  This may also support the SNI
// extension for virtual hosting.
extern int nni_tls_config_server_name(nni_tls_config *, const char *);

// nni_tls_config_ca_cert configures one or more CAs used for validation
// of peer certificates.  Multiple CAs (and their chains) may be configured
// by either calling this multiple times, or by specifying a list of
// certificates as concatenated data.  The certs may be in PEM or DER
// format.
extern int nni_tls_config_ca_cert(nni_tls_config *, const uint8_t *, size_t);

// nni_tls_config_clr loads a certificate revocation list.  Again, these
// are in X.509 format (either PEM or DER).
extern int nni_tls_config_crl(nni_tls_config *, const uint8_t *, size_t);

// nni_tls_config_cert is used to load our own certificate.  For servers,
// this may be called more than once to configure multiple different keys,
// for example with different algorithms depending on what the peer supports.
// On the client, only a single option is available.
extern int nni_tls_config_cert(nni_tls_config *, const uint8_t *crt, size_t);
extern int nni_tls_config_key(nni_tls_config *, const uint8_t *, size_t);
extern int nni_tls_config_pass(nni_tls_config *, const char *);

// nni_tls_config_validate_peer is used to enable validation of the peer
// and it's certificate.  If disabled, the peer's certificate will still
// be available, but may not be valid.
extern int nni_tls_config_validate_peer(nni_tls_config *, bool);

// nni_tls_config_auth_mode is a read-ony option that is used to configure
// the authentication mode use.  The default is that servers have this off
// (i.e. no client authentication) and clients have it on (they verify
// the server), which matches typical practice.
extern int nni_tls_config_auth_mode(nni_tls_config *, int);
#define NNI_TLS_CONFIG_AUTH_MODE_NONE 0     // No verification is performed
#define NNI_TLS_CONFIG_AUTH_MODE_OPTIONAL 1 // Verify cert if presented
#define NNI_TLS_CONFIG_AUTH_MODE_REQUIRED 2 // Verify cert, close if invalid

extern int  nni_tls_init(nni_tls **, nni_tls_config *, nni_plat_tcp_pipe *);
extern void nni_tls_close(nni_tls *);
extern void nni_tls_fini(nni_tls *);
extern void nni_tls_send(nni_tls *, nni_aio *);
extern void nni_tls_recv(nni_tls *, nni_aio *);

// nni_tls_verified returns true if the peer, or false if the peer did not
// verify.  (During the handshake phase, the peer is not verified, so this
// might return false if executed too soon.  The verification status will
// be accurate once the handshake is finished, however.
extern int nni_tls_verified(nni_tls *);

// nni_tls_ciphersuite_name returns the name of the ciphersuite in use.
extern const char *nni_tls_ciphersuite_name(nni_tls *);

// TBD: getting additional peer certificate information...

extern void nni_tls_strerror(int, char *, size_t); // review this

#endif // NNG_SUPPLEMENTAL_TLS_H
