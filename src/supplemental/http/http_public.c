//
// Copyright 2025 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "core/nng_impl.h"
#include "http_api.h"
#include "nng/http.h"

// Symbols in this file are "public" versions of the HTTP API.
// These are suitable for exposure to applications.

void
nng_http_close(nng_http *conn)
{
	// API version of this closes *and* frees the structure.
	nni_http_conn_fini(conn);
}

void
nng_http_read(nng_http *conn, nng_aio *aio)
{
	nni_http_read(conn, aio);
}

void
nng_http_read_all(nng_http *conn, nng_aio *aio)
{
	nni_http_read_full(conn, aio);
}

void
nng_http_write(nng_http *conn, nng_aio *aio)
{
	nni_http_write(conn, aio);
}

void
nng_http_write_all(nng_http *conn, nng_aio *aio)
{
	nni_http_write_full(conn, aio);
}

void
nng_http_write_request(nng_http *conn, nng_aio *aio)
{
	nni_http_write_req(conn, aio);
}

void
nng_http_write_response(nng_http *conn, nng_aio *aio)
{
	nni_http_write_res(conn, aio);
}

void
nng_http_read_response(nng_http *conn, nng_aio *aio)
{
	nni_http_read_res(conn, aio);
}

nng_err
nng_http_server_hold(nng_http_server **srvp, const nng_url *url)
{
	return (nni_http_server_init(srvp, url));
}

void
nng_http_server_release(nng_http_server *srv)
{
	nni_http_server_fini(srv);
}

nng_err
nng_http_server_start(nng_http_server *srv)
{
	return (nni_http_server_start(srv));
}

void
nng_http_server_stop(nng_http_server *srv)
{
	nni_http_server_stop(srv);
}

nng_err
nng_http_server_add_handler(nng_http_server *srv, nng_http_handler *h)
{
	return (nni_http_server_add_handler(srv, h));
}

nng_err
nng_http_server_del_handler(nng_http_server *srv, nng_http_handler *h)
{
	return (nni_http_server_del_handler(srv, h));
}

nng_err
nng_http_server_set_error_page(
    nng_http_server *srv, nng_http_status code, const char *body)
{
	return (nni_http_server_set_error_page(srv, code, body));
}

nng_err
nng_http_server_set_tls(nng_http_server *srv, nng_tls_config *cfg)
{
	return (nni_http_server_set_tls(srv, cfg));
}

nng_err
nng_http_server_get_tls(nng_http_server *srv, nng_tls_config **cfg)
{
	return (nni_http_server_get_tls(srv, cfg));
}

nng_err
nng_http_server_get_addr(nng_http_server *srv, nng_sockaddr *addr)
{
	size_t size = sizeof(nng_sockaddr);
	if (srv == NULL || addr == NULL)
		return NNG_EINVAL;
	return (nni_http_server_get(
	    srv, NNG_OPT_LOCADDR, addr, &size, NNI_TYPE_SOCKADDR));
}

nng_err
nng_http_server_error(nng_http_server *srv, nng_http *conn)
{
	return (nni_http_server_error(srv, conn));
}

void
nng_http_reset(nng_http *conn)
{
	nni_http_conn_reset(conn);
}
