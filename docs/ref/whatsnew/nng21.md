# What's New in NNG 2.1

NNG 2.1 adds hybrid post-quantum cryptography for TLS connections and support
for DTLS 1.3. It also expands socket statistics with protocol-specific
counters for messaging activity and outcomes.

## Protocol Statistics

Protocol sockets now expose additional statistics through [`nng_stats_get`],
including protocol-boundary socket traffic counters and counters for
protocol-specific events such as retries, queueing, discarded messages, and
malformed input. These counters help distinguish normal protocol behavior
from transport-level activity. See [Protocol Counters](../api/stats.md#protocol-counters)
for the counters available for each protocol.

## WebSocket Redirects

WebSocket dialers can now opt in to following HTTP redirects during the
opening handshake with [`NNG_OPT_WS_FOLLOW_REDIRECTS`]. Redirect following is
disabled by default, supports relative and HTTP(S) locations, and is limited
to ten hops.

## Post-Quantum Cryptography

NNG now supports hybrid post-quantum key exchange for TLS 1.3 and DTLS 1.3
connections, including the TLS and DTLS transports, HTTPS, and secure
WebSockets. Hybrid groups such as `X25519MLKEM768` combine classical
elliptic-curve key exchange with the post-quantum ML-KEM key encapsulation
mechanism. Support depends on the selected TLS engine and its build
configuration.

Applications can require hybrid post-quantum key exchange using the new
[`nng_tls_config_groups`] API with a hybrid-only group list and a TLS or DTLS
1.3 version restriction. OpenSSL 3.5 and newer support these groups for TLS;
DTLS requires OpenSSL 4.1 or newer with DTLS 1.3 enabled. wolfSSL requires a
build with ML-KEM and hybrid support enabled, as well as DTLS 1.3 support
when using DTLS.

Hybrid key exchange works with existing RSA or ECDSA certificates; certificate
authentication continues to use those classical algorithms. See
[Requiring Hybrid Post-Quantum Key Exchange](../api/tls.md#requiring-hybrid-post-quantum-key-exchange)
for configuration examples and engine requirements.

## DTLS 1.3 Support

The [DTLS transport](../tran/dtls.md) is now supported rather than
experimental. It provides encrypted, authenticated, message-oriented
communication over unicast UDP when TLS support and the DTLS transport build
option are enabled. It supports DTLS 1.3 as well as DTLS 1.2. DTLS 1.3 is
available with wolfSSL 5.9.1 or newer built with DTLS 1.3 enabled, and with
OpenSSL 4.1 or newer built with DTLS 1.3 enabled. Mbed TLS and earlier OpenSSL
releases continue to support DTLS 1.2.

The default TLS configuration negotiates the highest mutually supported DTLS
version. Applications can use [`nng_tls_config_version`] to require DTLS 1.3.
See the [DTLS transport](../tran/dtls.md) reference for engine requirements and
message size limits.

{{#include ../xref.md}}
