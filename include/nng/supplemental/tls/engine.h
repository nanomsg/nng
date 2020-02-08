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

// Locking theory statement for TLS engines.  The engine is assumed
// operate only from the context of threads called by the common
// framework.  That is to say, the callbacks made by the engine
// should always be on a thread that has context from the framework
// calling into the engine.  This means that the lower level send
// and receive functions can assume that they have lock ownership
// inherited on the stack.

// nng_tls_engine_conn represents the engine-specific private
// state for a TLS connection.  It is provided here for type
// safety.  Engine implementations should provide the structure
// definition locally.
typedef struct nng_tls_engine_conn nng_tls_engine_conn;

// nng_tls_engine_config represents the engine-specific private
// state for the TLS configuration.  It is provided here for type
// safety.  Engine implementations should provide the structure
// definition locally.
typedef struct nng_tls_engine_config nng_tls_engine_config;

typedef struct nng_tls_engine_conn_ops_s {
	// size is the size of the engine's per-connection state.
	// The framework will allocate this on behalf of the engine.
	// Typically this will be sizeof (struct nng_tls_engine_conn).
	size_t size;

	// init is used to initialize a connection object.
	// The passed in connection state will be aligned naturally,
	// and zeroed.  On success this returns 0, else an NNG error code.
	int (*init)(nng_tls_engine_conn *, void *, nng_tls_engine_config *);

	// fini destroys a connection object.  This will
	// be called only when no other external use of the connection
	// object exists, and only on fully initialed connection objects.
	void (*fini)(nng_tls_engine_conn *);

	// close closes the connection object, but should not
	// deallocate any memory.  It may also issue a TLS close-notify.
	void (*close)(nng_tls_engine_conn *);

	// handshake attempts to complete the SSL handshake phase.
	// It returns zero on success, or an error if one occurred.
	// The value NNG_EAGAIN should be returned if underlying I/O
	// is required to be completed first.  The framework will
	// ensure that the handshake completes before sending any data
	// down.
	int (*handshake)(nng_tls_engine_conn *);

	// recv attempts to read data (decrypted) from the connection.
	// It returns 0 on success, otherwise an error.  The implementation
	// should return NNG_EAGAIN if I/O to the underlying stream is
	// required to complete the operation.  On success, the count
	// is updated to reflect the number of bytes actually received.
	int (*recv)(nng_tls_engine_conn *, uint8_t *, size_t *);

	// send attempts to write data to the underlying connection.
	// It returns zero on success, otherwise an error. The implementation
	// should return NNG_EAGAIN if I/O to the underlying stream is
	// required to complete the operation.  On success, the count
	// is updated to reflect the number of bytes actually sent.
	int (*send)(nng_tls_engine_conn *, const uint8_t *, size_t *);

	// verified returns true if the connection is fully
	// TLS verified, false otherwise.
	bool (*verified)(nng_tls_engine_conn *);
} nng_tls_engine_conn_ops;

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
	int (*ca_chain)(nng_tls_engine_config *, const char *, const char *);

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
	int (*own_cert)(
	    nng_tls_engine_config *, const char *, const char *, const char *);

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

typedef enum nng_tls_engine_version_e {
	NNG_TLS_ENGINE_V0      = 0,
	NNG_TLS_ENGINE_V1      = 1,
	NNG_TLS_ENGINE_VERSION = NNG_TLS_ENGINE_V1,
} nng_tls_engine_version;

typedef struct nng_tls_engine_s {
	// _version is the engine version.  This for now must
	// be NNG_TLS_ENGINE_VERSION.  If the version does not match
	// then registration of the engine will fail.
	nng_tls_engine_version version;

	// config_ops is the operations for TLS configuration objects.
	nng_tls_engine_config_ops *config_ops;

	// conn_ops is the operations for TLS connections (stream-oriented).
	nng_tls_engine_conn_ops *conn_ops;

	// name contains the name of the engine, for example "wolfSSL".
	// It is acceptable to append a version number as well.
	const char *name;

	// description contains a human readable description.  This can
	// supply information about the backing library, for example
	// "mbed TLS v2.7"
	const char *description;

	// fips_mode is true if the engine is in FIPS mode.
	// It is expected that this will be enabled either at compile
	// time, or via environment variables at engine initialization.
	// FIPS mode cannot be changed once the engine is registered.
	bool fips_mode;
} nng_tls_engine;

NNG_DECL int nng_tls_engine_register(const nng_tls_engine *);

// nng_tls_engine_send is called by the engine to send data over the
// underlying connection.  It returns zero on success, NNG_EAGAIN if
// the operation can't be completed yet (the transport is busy and cannot
// accept more data yet), or some other error.  On success the count is
// updated with the number of bytes actually sent.  The first argument
// is the context structure passed in when starting the engine.
NNG_DECL int nng_tls_engine_send(void *, const uint8_t *, size_t *);

// nng_tls_engine_recv is called byu the engine to receive data over
// the underlying connection.  It returns zero on success, NNG_EAGAIN
// if the operation can't be completed yet (there is no data available
// for reading), or some other error.  On success the count is updated
// with the number of bytes actually received.
NNG_DECL int nng_tls_engine_recv(void *, uint8_t *, size_t *);

#endif // NNG_SUPPLEMENTAL_TLS_ENGINE_H
