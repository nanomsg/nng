//
// Copyright 2025 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "core/defs.h"
#include "nng/http.h"

// Stubs for common API functions.
//
const char *
nng_http_get_header(nng_http *conn, const char *key)
{
	NNI_ARG_UNUSED(conn);
	NNI_ARG_UNUSED(key);
	return (NULL);
}

nng_err
nng_http_set_header(nng_http *conn, const char *key, const char *val)
{
	NNI_ARG_UNUSED(conn);
	NNI_ARG_UNUSED(key);
	NNI_ARG_UNUSED(val);
	return (NNG_ENOTSUP);
}

nng_err
nng_http_add_header(nng_http *conn, const char *key, const char *val)
{
	NNI_ARG_UNUSED(conn);
	NNI_ARG_UNUSED(key);
	NNI_ARG_UNUSED(val);
	return (NNG_ENOTSUP);
}

void
nng_http_del_header(nng_http *conn, const char *key)
{
	NNI_ARG_UNUSED(conn);
	NNI_ARG_UNUSED(key);
}

void
nng_http_set_body(nng_http *conn, void *data, size_t sz)
{
	NNI_ARG_UNUSED(conn);
	NNI_ARG_UNUSED(data);
	NNI_ARG_UNUSED(sz);
}

nng_err
nng_http_copy_body(nng_http *conn, const void *data, size_t len)
{
	NNI_ARG_UNUSED(conn);
	NNI_ARG_UNUSED(data);
	NNI_ARG_UNUSED(len);
	return (NNG_ENOTSUP);
}

void
nng_http_get_body(nng_http *conn, void **datap, size_t *lenp)
{
	NNI_ARG_UNUSED(conn);
	NNI_ARG_UNUSED(datap);
	NNI_ARG_UNUSED(lenp);
}

const char *
nng_http_get_uri(nng_http *conn)
{
	NNI_ARG_UNUSED(conn);
	return (NULL);
}

nng_err
nng_http_set_uri(nng_http *conn, const char *uri, const char *query)
{
	NNI_ARG_UNUSED(conn);
	NNI_ARG_UNUSED(uri);
	NNI_ARG_UNUSED(query);
	return (NNG_ENOTSUP);
}

const char *
nng_http_get_version(nng_http *conn)
{
	NNI_ARG_UNUSED(conn);
	return (NULL);
}

void
nng_http_set_status(nng_http *conn, nng_http_status status, const char *reason)
{
	NNI_ARG_UNUSED(conn);
	NNI_ARG_UNUSED(status);
	NNI_ARG_UNUSED(reason);
}

nng_http_status
nng_http_get_status(nng_http *conn)
{
	NNI_ARG_UNUSED(conn);
	return (0);
}

const char *
nng_http_get_reason(nng_http *conn)
{
	NNI_ARG_UNUSED(conn);
	return (NULL);
}

nng_err
nng_http_set_version(nng_http *conn, const char *version)
{
	NNI_ARG_UNUSED(conn);
	NNI_ARG_UNUSED(version);
	return (NNG_ENOTSUP);
}

void
nng_http_set_method(nng_http *conn, const char *method)
{
	NNI_ARG_UNUSED(conn);
	NNI_ARG_UNUSED(method);
}

const char *
nng_http_get_method(nng_http *conn)
{
	NNI_ARG_UNUSED(conn);
	return (NULL);
}

void
nng_http_close(nng_http *conn)
{
	NNI_ARG_UNUSED(conn);
}

void
nng_http_read(nng_http *conn, nng_aio *aio)
{
	NNI_ARG_UNUSED(conn);
	nng_aio_finish(aio, NNG_ENOTSUP);
}

void
nng_http_read_all(nng_http *conn, nng_aio *aio)
{
	NNI_ARG_UNUSED(conn);
	nng_aio_finish(aio, NNG_ENOTSUP);
}

void
nng_http_write(nng_http *conn, nng_aio *aio)
{
	NNI_ARG_UNUSED(conn);
	nng_aio_finish(aio, NNG_ENOTSUP);
}

void
nng_http_write_all(nng_http *conn, nng_aio *aio)
{
	NNI_ARG_UNUSED(conn);
	nng_aio_finish(aio, NNG_ENOTSUP);
}

void
nng_http_write_request(nng_http *conn, nng_aio *aio)
{
	NNI_ARG_UNUSED(conn);
	nng_aio_finish(aio, NNG_ENOTSUP);
}

void
nng_http_write_response(nng_http *conn, nng_aio *aio)
{
	NNI_ARG_UNUSED(conn);
	nng_aio_finish(aio, NNG_ENOTSUP);
}

void
nng_http_read_response(nng_http *conn, nng_aio *aio)
{
	NNI_ARG_UNUSED(conn);
	nng_aio_finish(aio, NNG_ENOTSUP);
}

nng_err
nng_http_handler_alloc(
    nng_http_handler **hp, const char *uri, nng_http_handler_func cb)
{
	NNI_ARG_UNUSED(hp);
	NNI_ARG_UNUSED(uri);
	NNI_ARG_UNUSED(cb);
	return (NNG_ENOTSUP);
}

void
nng_http_handler_free(nng_http_handler *h)
{
	NNI_ARG_UNUSED(h);
}

nng_err
nng_http_handler_file(nng_http_handler **hp, const char *uri, const char *path,
    const char *ctype)
{
	NNI_ARG_UNUSED(hp);
	NNI_ARG_UNUSED(uri);
	NNI_ARG_UNUSED(path);
	NNI_ARG_UNUSED(ctype);
	return (NNG_ENOTSUP);
}

nng_err
nng_http_handler_directory(
    nng_http_handler **hp, const char *uri, const char *path)
{
	NNI_ARG_UNUSED(hp);
	NNI_ARG_UNUSED(uri);
	NNI_ARG_UNUSED(path);
	return (NNG_ENOTSUP);
}

nng_err
nng_http_handler_redirect(nng_http_handler **hp, const char *uri,
    nng_http_status status, const char *where)
{
	NNI_ARG_UNUSED(hp);
	NNI_ARG_UNUSED(uri);
	NNI_ARG_UNUSED(status);
	NNI_ARG_UNUSED(where);
	return (NNG_ENOTSUP);
}

nng_err
nng_http_handler_static(nng_http_handler **hp, const char *uri,
    const void *data, size_t size, const char *ctype)
{
	NNI_ARG_UNUSED(hp);
	NNI_ARG_UNUSED(uri);
	NNI_ARG_UNUSED(data);
	NNI_ARG_UNUSED(size);
	NNI_ARG_UNUSED(ctype);
	return (NNG_ENOTSUP);
}

void
nng_http_handler_set_method(nng_http_handler *h, const char *meth)
{
	NNI_ARG_UNUSED(h);
	NNI_ARG_UNUSED(meth);
}

void
nng_http_handler_collect_body(nng_http_handler *h, bool want, size_t len)
{
	NNI_ARG_UNUSED(h);
	NNI_ARG_UNUSED(want);
	NNI_ARG_UNUSED(len);
}

void
nng_http_handler_set_host(nng_http_handler *h, const char *host)
{
	NNI_ARG_UNUSED(h);
	NNI_ARG_UNUSED(host);
}

void
nng_http_handler_set_tree(nng_http_handler *h)
{
	NNI_ARG_UNUSED(h);
}

void
nng_http_handler_set_data(nng_http_handler *h, void *dat, void (*dtor)(void *))
{
	NNI_ARG_UNUSED(h);
	NNI_ARG_UNUSED(dat);
	NNI_ARG_UNUSED(dtor);
}

nng_err
nng_http_server_hold(nng_http_server **srvp, const nng_url *url)
{
	NNI_ARG_UNUSED(srvp);
	NNI_ARG_UNUSED(url);
	return (NNG_ENOTSUP);
}

void
nng_http_server_release(nng_http_server *srv)
{
	NNI_ARG_UNUSED(srv);
}

nng_err
nng_http_server_start(nng_http_server *srv)
{
	NNI_ARG_UNUSED(srv);
	return (NNG_ENOTSUP);
}

void
nng_http_server_stop(nng_http_server *srv)
{
	NNI_ARG_UNUSED(srv);
}

nng_err
nng_http_server_add_handler(nng_http_server *srv, nng_http_handler *h)
{
	NNI_ARG_UNUSED(srv);
	NNI_ARG_UNUSED(h);
	return (NNG_ENOTSUP);
}

nng_err
nng_http_server_del_handler(nng_http_server *srv, nng_http_handler *h)
{
	NNI_ARG_UNUSED(srv);
	NNI_ARG_UNUSED(h);
	return (NNG_ENOTSUP);
}

nng_err
nng_http_server_set_error_page(
    nng_http_server *srv, nng_http_status code, const char *body)
{
	NNI_ARG_UNUSED(srv);
	NNI_ARG_UNUSED(code);
	NNI_ARG_UNUSED(body);
	return (NNG_ENOTSUP);
}

nng_err
nng_http_server_set_tls(nng_http_server *srv, nng_tls_config *cfg)
{
	NNI_ARG_UNUSED(srv);
	NNI_ARG_UNUSED(cfg);
}

nng_err
nng_http_server_get_tls(nng_http_server *srv, nng_tls_config **cfg)
{
	NNI_ARG_UNUSED(srv);
	NNI_ARG_UNUSED(cfg);
	return (NNG_ENOTSUP);
}

nng_err
nng_http_server_get_addr(nng_http_server *srv, nng_sockaddr *addr)
{
	NNI_ARG_UNUSED(srv);
	NNI_ARG_UNUSED(addr);
	return (NNG_ENOTSUP);
}

nng_err
nng_http_server_error(nng_http_server *srv, nng_http *conn)
{
	NNI_ARG_UNUSED(srv);
	NNI_ARG_UNUSED(conn);
	return (NNG_ENOTSUP);
}

nng_err
nng_http_hijack(nng_http *conn)
{
	NNI_ARG_UNUSED(conn);
	return (NNG_ENOTSUP);
}

nng_err
nng_http_client_alloc(nng_http_client **clip, const nng_url *url)
{
	NNI_ARG_UNUSED(clip);
	NNI_ARG_UNUSED(url);
	return (NNG_ENOTSUP);
}

void
nng_http_client_free(nng_http_client *cli)
{
	NNI_ARG_UNUSED(cli);
}

nng_err
nng_http_client_set_tls(nng_http_client *cli, nng_tls_config *cfg)
{
	NNI_ARG_UNUSED(cli);
	NNI_ARG_UNUSED(cfg);
	return (NNG_ENOTSUP);
}

nng_err
nng_http_client_get_tls(nng_http_client *cli, nng_tls_config **cfgp)
{
	NNI_ARG_UNUSED(cli);
	NNI_ARG_UNUSED(cfgp);
	return (NNG_ENOTSUP);
}

void
nng_http_client_connect(nng_http_client *cli, nng_aio *aio)
{
	NNI_ARG_UNUSED(cli);
	nng_aio_finish(aio, NNG_ENOTSUP);
}

void
nng_http_transact(nng_http *conn, nng_aio *aio)
{
	NNI_ARG_UNUSED(conn);
	nng_aio_finish(aio, NNG_ENOTSUP);
}

void
nng_http_reset(nng_http *conn)
{
	NNI_ARG_UNUSED(conn);
}
