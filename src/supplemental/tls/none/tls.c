//
// Copyright 2019 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
// Copyright 2018 Devolutions <info@devolutions.net>
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

// This file is only used when TLS support is not build into the library.
// We provide stub functions only to satisfy linkage.

#include "core/nng_impl.h"
#include "supplemental/tls/tls_api.h"

void
nni_tls_config_fini(nng_tls_config *cfg)
{
	NNI_ARG_UNUSED(cfg);
}

int
nni_tls_config_init(nng_tls_config **cpp, enum nng_tls_mode mode)
{
	NNI_ARG_UNUSED(cpp);
	NNI_ARG_UNUSED(mode);
	return (NNG_ENOTSUP);
}

void
nni_tls_config_hold(nng_tls_config *cfg)
{
	NNI_ARG_UNUSED(cfg);
}

int
nng_tls_config_server_name(nng_tls_config *cfg, const char *name)
{
	NNI_ARG_UNUSED(cfg);
	NNI_ARG_UNUSED(name);
	return (NNG_ENOTSUP);
}

int
nng_tls_config_auth_mode(nng_tls_config *cfg, nng_tls_auth_mode mode)
{
	NNI_ARG_UNUSED(cfg);
	NNI_ARG_UNUSED(mode);
	return (NNG_ENOTSUP);
}

int
nng_tls_config_ca_chain(
    nng_tls_config *cfg, const char *certs, const char *crl)
{
	NNI_ARG_UNUSED(cfg);
	NNI_ARG_UNUSED(certs);
	NNI_ARG_UNUSED(crl);
	return (NNG_ENOTSUP);
}

int
nng_tls_config_own_cert(
    nng_tls_config *cfg, const char *cert, const char *key, const char *pass)
{
	NNI_ARG_UNUSED(cfg);
	NNI_ARG_UNUSED(cert);
	NNI_ARG_UNUSED(key);
	NNI_ARG_UNUSED(pass);
	return (NNG_ENOTSUP);
}

int
nng_tls_config_ca_file(nng_tls_config *cfg, const char *path)
{
	NNI_ARG_UNUSED(cfg);
	NNI_ARG_UNUSED(path);
	return (NNG_ENOTSUP);
}

int
nng_tls_config_cert_key_file(
    nng_tls_config *cfg, const char *path, const char *pass)
{
	NNI_ARG_UNUSED(cfg);
	NNI_ARG_UNUSED(path);
	NNI_ARG_UNUSED(pass);
	return (NNG_ENOTSUP);
}

int
nng_tls_config_key(nng_tls_config *cfg, const uint8_t *key, size_t size)
{
	NNI_ARG_UNUSED(cfg);
	NNI_ARG_UNUSED(key);
	NNI_ARG_UNUSED(size);
	return (NNG_ENOTSUP);
}

int
nng_tls_config_pass(nng_tls_config *cfg, const char *pass)
{
	NNI_ARG_UNUSED(cfg);
	NNI_ARG_UNUSED(pass);
	return (NNG_ENOTSUP);
}

int
nng_tls_config_alloc(nng_tls_config **cfgp, nng_tls_mode mode)
{

	NNI_ARG_UNUSED(cfgp);
	NNI_ARG_UNUSED(mode);
	return (NNG_ENOTSUP);
}

void
nng_tls_config_free(nng_tls_config *cfg)
{
	NNI_ARG_UNUSED(cfg);
}

int
nni_tls_dialer_alloc(nng_stream_dialer **dp, const nng_url *url)
{
	NNI_ARG_UNUSED(dp);
	NNI_ARG_UNUSED(url);
	return (NNG_ENOTSUP);
}

int
nni_tls_listener_alloc(nng_stream_listener **lp, const nng_url *url)
{
	NNI_ARG_UNUSED(lp);
	NNI_ARG_UNUSED(url);
	return (NNG_ENOTSUP);
}

int
nni_tls_checkopt(const char *nm, const void *buf, size_t sz, nni_type t)
{
	NNI_ARG_UNUSED(nm);
	NNI_ARG_UNUSED(buf);
	NNI_ARG_UNUSED(sz);
	NNI_ARG_UNUSED(t);
	return (NNG_ENOTSUP);
}