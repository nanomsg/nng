//
// Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#ifndef NNG_SUPPLEMENTAL_TLS_TLS_API_H
#define NNG_SUPPLEMENTAL_TLS_TLS_API_H

#include <stdbool.h>

// nni_tls represents the context for a single TLS stream.
typedef struct nni_tls nni_tls;

// nni_tls_config_init creates a new TLS configuration object.
// The object is created with a reference count of one.
extern int nni_tls_config_init(nng_tls_config **, nng_tls_mode);

// nni_tls_config_fini drops the reference on the configuration
// object, deallocating if this was the last reference.
extern void nni_tls_config_fini(nng_tls_config *);

// nni_tls_config_hold is used to get a hold on the config
// object, preventing it from being released inadvertently.
// The hold is released with a call to nng_tls_config_fini().
// Note that a hold need not be acquired at creation, since
// the configuration object is created with a hold on it.
extern void nni_tls_config_hold(nng_tls_config *);

extern int  nni_tls_init(nni_tls **, nng_tls_config *, nni_tcp_conn *);
extern void nni_tls_close(nni_tls *);
extern void nni_tls_fini(nni_tls *);
extern void nni_tls_send(nni_tls *, nng_aio *);
extern void nni_tls_recv(nni_tls *, nng_aio *);
extern int  nni_tls_sockname(nni_tls *, nni_sockaddr *);
extern int  nni_tls_peername(nni_tls *, nni_sockaddr *);
extern int  nni_tls_set_nodelay(nni_tls *, bool);
extern int  nni_tls_set_keepalive(nni_tls *, bool);

// nni_tls_verified returns true if the peer, or false if the peer did not
// verify.  (During the handshake phase, the peer is not verified, so this
// might return false if executed too soon.  The verification status will
// be accurate once the handshake is finished, however.
extern bool nni_tls_verified(nni_tls *);

// nni_tls_ciphersuite_name returns the name of the ciphersuite in use.
extern const char *nni_tls_ciphersuite_name(nni_tls *);

// TBD: getting additional peer certificate information...

#endif // NNG_SUPPLEMENTAL_TLS_TLS_API_H
