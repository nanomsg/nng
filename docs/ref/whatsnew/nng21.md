# What's New in NNG 2.1

NNG 2.1 adds hybrid post-quantum cryptography for TLS connections and support
for DTLS 1.3.

## Post-Quantum Cryptography

NNG now supports hybrid post-quantum key exchange for TLS 1.3 connections,
including the TLS transport, HTTPS, and secure WebSockets. Hybrid groups such
as `X25519MLKEM768` combine classical elliptic-curve key exchange with the
post-quantum ML-KEM key encapsulation mechanism. The same group configuration
can also be used with DTLS 1.3 when supported by the selected engine.

Applications can require hybrid post-quantum key exchange using the new
[`nng_tls_config_groups`] API with a hybrid-only group list and a TLS 1.3
version restriction. OpenSSL 3.5 and newer support these groups; wolfSSL
requires a build with ML-KEM and hybrid support enabled.

Hybrid key exchange works with existing RSA or ECDSA certificates; certificate
authentication continues to use those classical algorithms. See
[Requiring Hybrid Post-Quantum Key Exchange](../api/tls.md#requiring-hybrid-post-quantum-key-exchange)
for configuration examples and engine requirements.

## DTLS 1.3 Support

The [DTLS transport](../tran/dtls.md) now supports DTLS 1.3 as well as DTLS
1.2. DTLS 1.3 is available with wolfSSL 5.9.1 or newer built with DTLS 1.3
enabled, and with OpenSSL 4.1 or newer built with DTLS 1.3 enabled. Mbed TLS
and earlier OpenSSL releases continue to support DTLS 1.2.

The default TLS configuration negotiates the highest mutually supported DTLS
version. Applications can use [`nng_tls_config_version`] to require DTLS 1.3.
See the [DTLS transport](../tran/dtls.md) reference for engine requirements and
message size limits.

{{#include ../xref.md}}
