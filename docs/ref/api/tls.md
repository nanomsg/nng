# TLS

NNG provides {{i:TLS}} ({{i:Transport Layer Security}}) support for transports and
stream-based services that need encrypted and authenticated communication.
TLS is used by the [TLS transport], secure WebSocket transport, HTTP clients and servers,
and raw [streams] implementations that support it.

TLS support depends on a TLS engine being available when NNG is built.
If TLS support is not enabled, the TLS functions may be present as stubs and will return
[`NNG_ENOTSUP`] where appropriate.
The active engine can be inspected with [`nng_tls_engine_name`] and
[`nng_tls_engine_description`].
The public TLS declarations are available from `<nng/nng.h>`.

## Configuration Objects

```c
typedef struct nng_tls_config nng_tls_config;

typedef enum nng_tls_mode {
    NNG_TLS_MODE_CLIENT,
    NNG_TLS_MODE_SERVER
} nng_tls_mode;

nng_err nng_tls_config_alloc(nng_tls_config **cfgp, nng_tls_mode mode);
void nng_tls_config_hold(nng_tls_config *cfg);
void nng_tls_config_free(nng_tls_config *cfg);
```

{{hi:`nng_tls_config`}}
{{hi:`nng_tls_config_alloc`}}
{{hi:`nng_tls_config_hold`}}
{{hi:`nng_tls_config_free`}}
{{hi:`NNG_TLS_MODE_CLIENT`}}
{{hi:`NNG_TLS_MODE_SERVER`}}
A {{i:TLS configuration}} object represents the policy and key material used to create TLS sessions.
Configuration data includes the operating mode, certificate authorities used for peer validation,
the local certificate and private key, the expected server name, protocol version limits,
and pre-shared keys.

The `nng_tls_config_alloc` function allocates a configuration object and stores it in _cfgp_.
The _mode_ determines whether it will be used as a client or server.

A configuration object starts with a reference count of one.
The `nng_tls_config_hold` function increments that reference count, and
`nng_tls_config_free` decrements it, freeing the object when the last reference is released.

> [!NOTE]
> TLS configuration objects become read-only once they are used to create a connection or service.
> After that point, attempts to modify the configuration will fail with [`NNG_EBUSY`].

## Authentication Mode

```c
typedef enum nng_tls_auth_mode {
    NNG_TLS_AUTH_MODE_NONE,
    NNG_TLS_AUTH_MODE_OPTIONAL,
    NNG_TLS_AUTH_MODE_REQUIRED
} nng_tls_auth_mode;

nng_err nng_tls_config_auth_mode(nng_tls_config *cfg, nng_tls_auth_mode mode);
```

{{hi:`nng_tls_config_auth_mode`}}
{{hi:`NNG_TLS_AUTH_MODE_NONE`}}
{{hi:`NNG_TLS_AUTH_MODE_OPTIONAL`}}
{{hi:`NNG_TLS_AUTH_MODE_REQUIRED`}}
The `nng_tls_config_auth_mode` function configures how the remote peer is authenticated.

| Mode                         | Description                                                                                                  |
| ---------------------------- | ------------------------------------------------------------------------------------------------------------ |
| `NNG_TLS_AUTH_MODE_NONE`     | No TLS peer authentication is performed. This is the default for server configurations.                       |
| `NNG_TLS_AUTH_MODE_OPTIONAL` | A presented certificate is validated, but the session may proceed if the peer presents no valid certificate. |
| `NNG_TLS_AUTH_MODE_REQUIRED` | The peer must present a valid certificate. This is the default for client configurations.                     |

When authentication is required, the configuration must include certificate authority material that can validate
the peer certificate.

## Certificates and Keys

```c
nng_err nng_tls_config_ca_chain(nng_tls_config *cfg, const char *chain, const char *crl);
nng_err nng_tls_config_ca_file(nng_tls_config *cfg, const char *path);
nng_err nng_tls_config_own_cert(nng_tls_config *cfg, const char *cert,
    const char *key, const char *pass);
nng_err nng_tls_config_cert_key_file(nng_tls_config *cfg, const char *path,
    const char *pass);
nng_err nng_tls_config_server_name(nng_tls_config *cfg, const char *name);
```

{{hi:`nng_tls_config_ca_chain`}}
{{hi:`nng_tls_config_ca_file`}}
{{hi:`nng_tls_config_own_cert`}}
{{hi:`nng_tls_config_cert_key_file`}}
{{hi:`nng_tls_config_server_name`}}
The `nng_tls_config_ca_chain` function adds one or more certificate authority certificates,
and optionally a certificate revocation list, to _cfg_.
Both _chain_ and _crl_ use zero-terminated PEM data; _crl_ may be `NULL`.
The _chain_ may contain multiple certificates concatenated together.

The `nng_tls_config_ca_file` function loads certificate authority and optional revocation list material
from a file.
The file must contain at least one PEM X.509 certificate and may also contain PEM CRL objects.

The `nng_tls_config_own_cert` function configures the local certificate chain and associated private key
from zero-terminated PEM strings.
The _pass_ value is used to decrypt an encrypted private key, and may be `NULL`.
A configuration accepts only one local certificate and key; a second attempt will fail with [`NNG_EBUSY`].

The `nng_tls_config_cert_key_file` function loads the local certificate chain and private key from a file.
The certificate and private key must both be present in PEM form in that file.

The `nng_tls_config_server_name` function configures the expected remote server name for client configurations.
This name is used for certificate validation and may also be sent with {{i:Server Name Indication}} (SNI).

> [!TIP]
> Server configurations normally need a local certificate and private key.
> Client configurations normally need certificate authority material and a server name unless authentication is disabled.

## Pre-Shared Keys

```c
nng_err nng_tls_config_psk(nng_tls_config *cfg, const char *identity,
    const uint8_t *key, size_t key_len);
```

{{hi:`nng_tls_config_psk`}}
{{i:Pre-shared key}} (PSK) configurations use an identity string and a shared secret instead of certificate-based authentication.
The `nng_tls_config_psk` function configures a PSK identity and key.

Client configurations can call this function once.
Server configurations can call it multiple times to install keys for different client identities.
Support for PSK depends on the configured TLS engine.

## TLS Versions

```c
typedef enum nng_tls_version {
    NNG_TLS_1_2 = 0x303,
    NNG_TLS_1_3 = 0x304
} nng_tls_version;

nng_err nng_tls_config_version(nng_tls_config *cfg,
    nng_tls_version min, nng_tls_version max);
```

{{hi:`nng_tls_config_version`}}
{{hi:`NNG_TLS_1_2`}}
{{hi:`NNG_TLS_1_3`}}
The `nng_tls_config_version` function restricts the TLS protocol versions that may be used
when creating sessions with _cfg_.
By default, NNG attempts to use TLS v1.2 and TLS v1.3, subject to TLS engine support.
If the engine cannot support any version in the requested range, this function returns [`NNG_ENOTSUP`].

NNG does not support SSL v2.0, SSL v3.0, TLS v1.0, or TLS v1.1.
TLS v1.3 zero round trip time (0-RTT) and session resumption are not supported.

## Using Configuration Objects

```c
nng_err nng_dialer_get_tls(nng_dialer dialer, nng_tls_config **cfgp);
nng_err nng_dialer_set_tls(nng_dialer dialer, nng_tls_config *cfg);
nng_err nng_listener_get_tls(nng_listener listener, nng_tls_config **cfgp);
nng_err nng_listener_set_tls(nng_listener listener, nng_tls_config *cfg);
```

{{hi:`nng_dialer_get_tls`}}
{{hi:`nng_dialer_set_tls`}}
{{hi:`nng_listener_get_tls`}}
{{hi:`nng_listener_set_tls`}}
The `nng_dialer_set_tls` and `nng_listener_set_tls` functions configure TLS for Scalability Protocol
[dialer] and [listener] objects whose transports support TLS.
These functions must be called before the dialer or listener is started.
They take their own hold on the configuration object, so the caller may release its reference after a successful call.

The `nng_dialer_get_tls` and `nng_listener_get_tls` functions retrieve the associated configuration object.
They do not add a new hold; applications that need to retain the object independently should call
[`nng_tls_config_hold`].

The [Streams API][streams] has corresponding [`nng_stream_dialer_set_tls`],
[`nng_stream_dialer_get_tls`], [`nng_stream_listener_set_tls`], and
[`nng_stream_listener_get_tls`] functions.
HTTP clients and servers also use TLS configuration objects for HTTPS; see [`nng_http_client_set_tls`]
and related HTTP APIs.

## Examples

The following examples use Scalability Protocol [dialer] and [listener] objects.
For raw [streams], use the same configuration steps, but attach the configuration with
[`nng_stream_dialer_set_tls`] or [`nng_stream_listener_set_tls`].

The examples use certificate files for clarity.
Files passed to `nng_tls_config_cert_key_file` must contain both the certificate chain and the private key
in PEM form.
If the certificate and private key are stored separately, load them as strings and use
[`nng_tls_config_own_cert`] instead.

### Client Authentication of a Server

This is the usual client-side TLS configuration.
The client validates the server certificate against a trusted CA and verifies that the certificate
matches the expected server name.

```c
nng_tls_config *tls;

nng_tls_config_alloc(&tls, NNG_TLS_MODE_CLIENT);
nng_tls_config_ca_file(tls, "ca.pem");
nng_tls_config_server_name(tls, "server.example.com");
nng_dialer_set_tls(dialer, tls);
nng_tls_config_free(tls);
```

> [!TIP]
> If the URL uses a DNS name, NNG may use that name for verification by default.
> Calling `nng_tls_config_server_name` is still a good habit when the expected identity matters,
> especially when dialing an IP address, an alias, or a name that differs from the certificate.

### Server With a Certificate

This is the usual server-side TLS configuration.
The server presents its certificate and private key to clients.
By default, server configurations do not require client certificates.

```c
nng_tls_config *tls;

nng_tls_config_alloc(&tls, NNG_TLS_MODE_SERVER);
nng_tls_config_cert_key_file(tls, "server.pem", NULL);
nng_listener_set_tls(listener, tls);
nng_tls_config_free(tls);
```

### Mutual TLS

{{i:mutual TLS}}{{hi:mTLS}}
With mutual TLS, both sides present certificates and both sides validate the peer.
The server must require peer authentication and trust the CA that issued client certificates.
The client must trust the CA that issued the server certificate and must also provide its own certificate.

```c
nng_tls_config *tls;

// Server side.
nng_tls_config_alloc(&tls, NNG_TLS_MODE_SERVER);
nng_tls_config_cert_key_file(tls, "server.pem", NULL);
nng_tls_config_ca_file(tls, "client-ca.pem");
nng_tls_config_auth_mode(tls, NNG_TLS_AUTH_MODE_REQUIRED);
nng_listener_set_tls(listener, tls);
nng_tls_config_free(tls);

// Client side.
nng_tls_config_alloc(&tls, NNG_TLS_MODE_CLIENT);
nng_tls_config_ca_file(tls, "server-ca.pem");
nng_tls_config_server_name(tls, "server.example.com");
nng_tls_config_cert_key_file(tls, "client.pem", NULL);
nng_dialer_set_tls(dialer, tls);
nng_tls_config_free(tls);
```

### Pre-Shared Keys

{{i:pre-shared key}}{{i:PSK}}
Pre-shared key configurations use matching identity and key values on both sides.
They do not use certificate chains for peer authentication.
The server may install multiple identities; the client installs the identity it will present.

```c
nng_tls_config *tls;
uint8_t         key[32]; // Already provisioned securely.

// Server side.
nng_tls_config_alloc(&tls, NNG_TLS_MODE_SERVER);
nng_tls_config_psk(tls, "client-1", key, sizeof(key));
nng_listener_set_tls(listener, tls);
nng_tls_config_free(tls);

// Client side.
nng_tls_config_alloc(&tls, NNG_TLS_MODE_CLIENT);
nng_tls_config_psk(tls, "client-1", key, sizeof(key));
nng_dialer_set_tls(dialer, tls);
nng_tls_config_free(tls);
```

> [!NOTE]
> PSK support depends on TLS engine capabilities.
> If PSK is unavailable or the supplied identity or key is not acceptable to the engine,
> `nng_tls_config_psk` will fail.
> Real applications should provision high-entropy secret key material securely.

## Peer Certificates

```c
typedef struct nng_tls_cert_s nng_tls_cert;

nng_err nng_pipe_peer_cert(nng_pipe pipe, nng_tls_cert **certp);
nng_err nng_stream_peer_cert(nng_stream *stream, nng_tls_cert **certp);
nng_err nng_http_peer_cert(nng_http *conn, nng_tls_cert **certp);

nng_err nng_tls_cert_parse_pem(nng_tls_cert **certp, const char *pem, size_t size);
nng_err nng_tls_cert_parse_der(nng_tls_cert **certp, const uint8_t *der, size_t size);
void nng_tls_cert_der(nng_tls_cert *cert, uint8_t *buf, size_t *sizep);
void nng_tls_cert_free(nng_tls_cert *cert);

nng_err nng_tls_cert_subject(nng_tls_cert *cert, char **namep);
nng_err nng_tls_cert_issuer(nng_tls_cert *cert, char **namep);
nng_err nng_tls_cert_serial_number(nng_tls_cert *cert, char **serialp);
nng_err nng_tls_cert_subject_cn(nng_tls_cert *cert, char **namep);
nng_err nng_tls_cert_next_alt(nng_tls_cert *cert, char **namep);
nng_err nng_tls_cert_not_before(nng_tls_cert *cert, struct tm *timep);
nng_err nng_tls_cert_not_after(nng_tls_cert *cert, struct tm *timep);
```

{{hi:`nng_tls_cert`}}
{{hi:`nng_pipe_peer_cert`}}
{{hi:`nng_stream_peer_cert`}}
{{hi:`nng_http_peer_cert`}}
{{hi:`nng_tls_cert_parse_pem`}}
{{hi:`nng_tls_cert_parse_der`}}
{{hi:`nng_tls_cert_der`}}
{{hi:`nng_tls_cert_free`}}
{{hi:`nng_tls_cert_subject`}}
{{hi:`nng_tls_cert_issuer`}}
{{hi:`nng_tls_cert_serial_number`}}
{{hi:`nng_tls_cert_subject_cn`}}
{{hi:`nng_tls_cert_next_alt`}}
{{hi:`nng_tls_cert_not_before`}}
{{hi:`nng_tls_cert_not_after`}}
The `nng_tls_cert` object represents an X.509 certificate.
Peer certificates can be obtained from a TLS [pipe], [stream], or HTTP connection.
The certificate object must be released with `nng_tls_cert_free` when it is no longer needed.

The parse functions create certificate objects from PEM or DER encoded certificate data.
The `nng_tls_cert_der` function writes the DER form of a certificate into _buf_, using _sizep_
as both the input buffer size and output byte count.

The certificate information functions retrieve common X.509 fields.
`nng_tls_cert_next_alt` iterates through subject alternative names and returns [`NNG_ENOENT`]
when there are no more names.
Applications that need to keep returned string values after changing or freeing the certificate object
should copy those strings.

## TLS Engine

```c
const char *nng_tls_engine_name(void);
const char *nng_tls_engine_description(void);
bool nng_tls_engine_fips_mode(void);
```

{{hi:`nng_tls_engine_name`}}
{{hi:`nng_tls_engine_description`}}
{{hi:`nng_tls_engine_fips_mode`}}
The `nng_tls_engine_name` function returns a short name for the active TLS engine.
The `nng_tls_engine_description` function returns a short descriptive string.
These functions are principally useful for diagnostics.

The `nng_tls_engine_fips_mode` function returns `true` if the engine is operating in FIPS mode.
The default TLS engine does not support FIPS mode; alternative engines may provide that capability.

{{#include ../xref.md}}
