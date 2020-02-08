//
// Copyright 2020 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#ifndef NNG_SUPPLEMENTAL_TLS_TLS_H
#define NNG_SUPPLEMENTAL_TLS_TLS_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

// Note that TLS functions may be stubbed out if TLS is not enabled in
// the build.

// For some transports, we need TLS configuration, including certificates
// and so forth.  A TLS configuration cannot be changed once it is in use.
typedef struct nng_tls_config nng_tls_config;

typedef enum nng_tls_mode {
	NNG_TLS_MODE_CLIENT = 0,
	NNG_TLS_MODE_SERVER = 1,
} nng_tls_mode;

typedef enum nng_tls_auth_mode {
	NNG_TLS_AUTH_MODE_NONE     = 0, // No verification is performed
	NNG_TLS_AUTH_MODE_OPTIONAL = 1, // Verify cert if presented
	NNG_TLS_AUTH_MODE_REQUIRED = 2, // Verify cert, close if invalid
} nng_tls_auth_mode;

// TLS version numbers.  We encode the major number and minor number
// as separate byte fields.  No support for SSL 3.0 or earlier -- older
// versions are known to be insecure and should not be used.
// When possible applications should restrict themselves to TLS 1.2 or better.
typedef enum nng_tls_version {
	NNG_TLS_1_0 = 0x301,
	NNG_TLS_1_1 = 0x302,
	NNG_TLS_1_2 = 0x303,
	NNG_TLS_1_3 = 0x304
} nng_tls_version;

// nng_tls_config_alloc creates a TLS configuration using
// reasonable defaults.  This configuration can be shared
// with multiple pipes or services/servers.
NNG_DECL int nng_tls_config_alloc(nng_tls_config **, nng_tls_mode);

// nng_tls_config_hold increments the reference count on the TLS
// configuration object.  The hold can be dropped by calling
// nng_tls_config_free later.
NNG_DECL void nng_tls_config_hold(nng_tls_config *);

// nng_tls_config_free drops the reference count on the TLS
// configuration object, and if zero, deallocates it.
NNG_DECL void nng_tls_config_free(nng_tls_config *);

// nng_tls_config_server_name sets the server name.  This is
// called by clients to set the name that the server supplied
// certificate should be matched against.  This can also cause
// the SNI to be sent to the server to tell it which cert to
// use if it supports more than one.
NNG_DECL int nng_tls_config_server_name(nng_tls_config *, const char *);

// nng_tls_config_ca_cert configures one or more CAs used for validation
// of peer certificates.  Multiple CAs (and their chains) may be configured
// by either calling this multiple times, or by specifying a list of
// certificates as concatenated data.  The final argument is an optional CRL
// (revocation list) for the CA, also in PEM.  Both PEM strings are ASCIIZ
// format (except that the CRL may be NULL).
NNG_DECL int nng_tls_config_ca_chain(
    nng_tls_config *, const char *, const char *);

// nng_tls_config_own_cert is used to load our own certificate and public
// key.  For servers, this may be called more than once to configure multiple
// different keys, for example with different algorithms depending on what
// the peer supports. On the client, only a single option is available.
// The first two arguments are the cert (or validation chain) and the
// key as PEM format ASCIIZ strings.  The final argument is an optional
// password and may be NULL.
NNG_DECL int nng_tls_config_own_cert(
    nng_tls_config *, const char *, const char *, const char *);

// nng_tls_config_key is used to pass our own private key.
NNG_DECL int nng_tls_config_key(nng_tls_config *, const uint8_t *, size_t);

// nng_tls_config_pass is used to pass a password used to decrypt
// private keys that are encrypted.
NNG_DECL int nng_tls_config_pass(nng_tls_config *, const char *);

// nng_tls_config_auth_mode is used to configure the authentication mode use.
// The default is that servers have this off (i.e. no client authentication)
// and clients have it on (they verify the server), which matches typical
// practice.
NNG_DECL int nng_tls_config_auth_mode(nng_tls_config *, nng_tls_auth_mode);

// nng_tls_config_ca_file is used to pass a CA chain and optional CRL
// via the filesystem.  If CRL data is present, it must be contained
// in the file, along with the CA certificate data.  The format is PEM.
// The path name must be a legal file name.
NNG_DECL int nng_tls_config_ca_file(nng_tls_config *, const char *);

// nng_tls_config_cert_key_file is used to pass our own certificate and
// private key data via the filesystem.  Both the key and certificate
// must be present as PEM blocks in the same file.  A password is used to
// decrypt the private key if it is encrypted and the password supplied is not
// NULL. This may be called multiple times on servers, but only once on a
// client. (Servers can support multiple different certificates and keys for
// different cryptographic algorithms.  Clients only get one.)
NNG_DECL int nng_tls_config_cert_key_file(
    nng_tls_config *, const char *, const char *);

// Configure supported TLS version.  By default we usually restrict
// ourselves to TLS 1.2 and newer.  We do not support older versions.
// If the implementation cannot support any version (for example if
// the minimum requested is 1.3 but the TLS implementation lacks support
// for TLS 1.3) then NNG_ENOTSUP will be returned.
NNG_DECL int nng_tls_config_version(
    nng_tls_config *, nng_tls_version, nng_tls_version);

// nng_tls_engine_name returns the "name" of the TLS engine.  If no
// TLS engine support is enabled, then "none" is returned.
NNG_DECL const char *nng_tls_engine_name(void);

// nng_tls_engine_description returns the "description" of the TLS engine.
// If no TLS engine support is enabled, then an empty string is returned.
NNG_DECL const char *nng_tls_engine_description(void);

// nng_tls_engine_fips_mode returns true if the engine is in FIPS 140-2 mode.
NNG_DECL bool nng_tls_engine_fips_mode(void);

#ifdef __cplusplus
}
#endif

#endif // NNG_SUPPLEMENTAL_TLS_TLS_H
