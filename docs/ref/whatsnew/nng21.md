# What's New in NNG 2.1

NNG 2.1 adds new capabilities and refinements across the library.

## DTLS 1.3 Support

The [DTLS transport](../tran/dtls.md) now supports DTLS 1.3 as well as DTLS
1.2. DTLS 1.3 is available with wolfSSL 5.9.1 or newer built with DTLS 1.3
enabled, and with OpenSSL 4.1 or newer built with DTLS 1.3 enabled. Mbed TLS
and earlier OpenSSL releases continue to support DTLS 1.2.

The default TLS configuration negotiates the highest mutually supported DTLS
version. Applications can use [`nng_tls_config_version`] to require DTLS 1.3.
See the [DTLS transport](../tran/dtls.md) reference for engine requirements and
message size limits.

## TLS Key Exchange Groups

[`nng_tls_config_groups`] accepts an array of named key exchange groups,
including hybrid ML-KEM groups when supported by the selected TLS engine.
Applications can require hybrid post-quantum key exchange by combining a
hybrid-only group list with a TLS 1.3 version restriction.

{{#include ../xref.md}}
