//
// Copyright 2020 Staysail Systems, Inc. <info@staysail.tech>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

// This file is used to enable external TLS "engines", so
// that third party TLS libraries can be plugged in

#ifndef NNG_SUPPLEMENTAL_TLS_ENGINE_H
#define NNG_SUPPLEMENTAL_TLS_ENGINE_H

#include <nng/supplemental/tls/tls.h>

// nng_tls_engine_config represents the engine-specific private
// state for a TLS connection.  It is provided here for type
// safety.  Engine implementations should provide the structure
// definition locally.
typedef struct nng_tls_engine_conn nng_tls_engine_conn;

typedef struct nng_tls_engine_conn_ops_s {
	// size is the size of the engine's per-connection state.
	// The framework will allocate this on behalf of the engine.
	// Typically this will be sizeof (struct nng_tls_engine_conn).
	size_t size;

	// init is used to initialize a connection object.
	// The passed in connection state will be aligned naturally,
	// and zeroed.  On success this returns 0, else an NNG error code.
	int (*conn_init)(nng_tls_engine_conn *);

	// fini destroys a connection object.  This will
	// be called only when no other external use of the connection
	// object exists, and only on fully initialed connection objects.
	int (*fini)(nng_tls_engine_conn *);

	// conn_start is called to start a session using the given
	// configuration file and stream connection.  The stream connection
	// will probably be TCP (though in theory it could be also be
	// IPC, or some other stream oriented transport.
	int (*start)(
	    nng_tls_engine_conn *, nng_tls_engine_config *, nng_stream *);

	// close closes the connection object, but should not
	// deallocate any memory.  It may also issue a TLS close-notify.
	int (*close)(nng_tls_engine_conn *);

	// verified returns true if the connection is fully
	// TLS verified, false otherwise.
	bool (*verified)(nng_tls_engine_conn *);
} nng_tls_engine_conn_ops;

// nng_tls_engine_config represents the engine-specific private
// state for the TLS configuration.  It is provided here for type
// safety.  Engine implementations should provide the structure
// definition locally.
typedef struct nng_tls_engine_config nng_tls_engine_config;

typedef struct nng_tls_engine_config_ops_s {

	// size is the size of the engine's configuration object.
	// The framework will allocate this on behalf of the engine.
	// Typically this will be sizeof (struct nng_tls_engine_config).
	size_t size;

	// init prepares the configuration object object.
	// The mode indicates whether the object should be
	// initialized for use as a TLS server or client.
	// The config passed in will be aligned on a 64-bit boundary,
	// and will be initialized to zero.  On success this returns
	// 0, else an NNG error code.
	int (*init)(nng_tls_engine_config *, nng_tls_mode);

	// fini is used to tear down the configuration object.
	// This will only be called on objects that have been properly
	// initialized with nte_config_init.
	void (*fini)(nng_tls_engine_config *);

	// server is used to set the server name.  This can be used in SNI,
	// and will also be used on the client to validate the identity.
	// If this is not set, then no verification will be performed.
	int (*server)(nng_tls_engine_config *, const char *);

	// auth is used to configure the authentication mode.  Values:
	// NNG_AUTH_MODE_NONE
	//   No validation of the peer is performed.  Public facing
	//   servers often use this.
	// NNG_AUTH_MODE_OPTIONAL
	//   The peer's identity is validated if a certificate is presented.
	//   This is typically useful on servers.
	// NNG_AUTH_MODE_REQUIRED
	//   The peer's certificate must be present and is verified.
	//   This is standard for the client, and on servers it is used
	//   when client (mutual) authentication is needed.
	int (*auth)(nng_tls_engine_config *, nng_tls_auth_mode);

	// ca_chain sets the configuration authorities that will be
	// used to validate peers.  An optional CRL is supplied as well.
	// Both values are C strings (NUL terminated) containing
	// PEM data.  There may be multiple PEM blocks.  The
	// CRL may be NULL if not needed.
	int (*ca_chain)(
	    nng_tls_engine_config *, const char *CA, const char *CRL);

	// own_cert configures our identity -- the certificate containing
	// our public key, our private key (which might be encrypted), and
	// potentially a password used to decrypt the private key.
	// All of these are C strings.  The cert may actually be a chain
	// which will be presented to our peer.   This function may be
	// called multiple times to register different keys with different
	// parameters on a server.  (For example, once for RSA parameters,
	// and again later with EC parameters.)  The certificate and the
	// private key may be presented in the same file.  The implementation
	// is responsible for parsing out the relevant data.  If the password
	// is NULL, then the key file should be unencrypted.  The supplied
	// password may be ignored if the key is not encrypted.  Not all
	// engine implementations need support encryption of the key.
	int (*own_cert)(nng_tls_engine_config *, const char *cert,
	    const char *key, const char *password);

	// version configures the minimum and maximum TLS versions.  The
	// engine should default to supporting TLS1.0 through 1.2, and
	// optionally 1.3 if it can.  The engine should restrict the
	// the requested range to what it can support -- if no version
	// within the range is supported (such as if NNG_TLS_1_3 is
	// specified for both min and max, and the engine lacks support
	// for v1.3, then NNG_ENOTSUP should be returned.
	int (*version)(
	    nng_tls_engine_config *, nng_tls_version, nng_tls_version);
} nng_tls_engine_config_ops;

typedef enum nng_tls_engine_version {
	NNG_TLS_ENGINE_V0      = 0,
	NNG_TLS_ENGINE_VERSION = NNG_TLS_ENGINE_V0,
} nng_tls_engine_version;

typedef struct {
	// _version is the engine version.  This for now must
	// be NNG_TLS_ENGINE_VERSION.  If the version does not match
	// then registration of the engine will fail.
	nng_tls_engine_version version;

	// config_ops is the operations for TLS configuration objects.
	nng_tls_engine_config_ops *config_ops;

	// conn_ops is the operations for TLS connections (stream-oriented).
	nng_tls_engine_conn_ops *conn_ops;
	// nte_conn_size is the size of the engine's per-connection state.
	// The framework will allocate this on behalf of the engine.
	// Typically this will be sizeof (struct nng_tls_engine_conn).
	size_t nte_conn_size;

	// nte_config_size is the size of the engine's configuration object.
	// The framework will allocate this on behalf of the engine.
	// Typically this will be sizeof (struct nng_tls_engine_config).
	size_t nte_config_size;

	// nte_config_init prepares the configuration object object.
	// The mode indicates whether the object should be
	// initialized for use as a TLS server or client.
	// The config passed in will be aligned on a 64-bit boundary,
	// and will be initialized to zero.  On success this returns
	// 0, else an NNG error code.
	int (*nte_config_init)(nng_tls_engine_config *, nng_tls_mode);

	// nge_config_fini is used to tear down the configuration object.
	// This will only be called on objects that have been properly
	// initialized with nte_config_init.
	void (*nte_config_fini)(nng_tls_engine_config *);

	// nte_conn_init is used to initialize a connection object.
	// The passed in connection state will be aligned naturally,
	// and zeroed.  On success this returns 0, else an NNG error code.
	int (*nte_conn_init)(nng_tls_engine_conn *);

	// nte_conn_fini destroys a connection object.  This will
	// be called only when no other external use of the connection
	// object exists, and only on fully initialed connection objects.
	int (*nte_conn_fini)(nng_tls_engine_conn *);

	// nte_start is called to start a session using the given
	// configuration file and stream connection.  The stream connection
	// will probably be TCP (though in theory it could be also be
	// IPC, or some other stream oriented transport.
	int (*nte_conn_start)(
	    nng_tls_engine_conn *, nng_tls_engine_config *, nng_stream *);

	// nte_conn_close closes the connection object, but should not
	// deallocate any memory.  It may also issue a TLS close-notify.
	int (*nte_conn_close)(nng_tls_engine_conn *);

	// nte_conn_verified returns true if the connection is fully
	// TLS verified, false otherwise.
	bool (*nte_conn_verified)(nng_tls_engine_conn *);
} nng_tls_engine;

NNG_DECL int nng_tls_engine_register(nng_tls_engine *);

#endif // NNG_SUPPLEMENTAL_TLS_ENGINE_H
