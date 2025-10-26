//
// Copyright 2025 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "../../core/nng_impl.h"
#include "http_api.h"
#include "nng/http.h"

// Symbols in this file are "public" versions of the HTTP API.
// These are suitable for exposure to applications.

const char *
nng_http_get_header(nng_http *conn, const char *key)
{
#ifdef NNG_SUPP_HTTP
	return (nni_http_get_header(conn, key));
#else
	NNI_ARG_UNUSED(conn);
	NNI_ARG_UNUSED(key);
	return (NULL);
#endif
}

bool
nng_http_next_header(
    nng_http *conn, const char **key, const char **val, void **ptr)
{
#ifdef NNG_SUPP_HTTP
	return (nni_http_next_header(conn, key, val, ptr));
#else
	NNI_ARG_UNUSED(conn);
	NNI_ARG_UNUSED(key);
	NNI_ARG_UNUSED(val);
	NNI_ARG_UNUSED(ptr);
	return (NNG_ENOTSUP);
#endif
}

nng_err
nng_http_set_header(nng_http *conn, const char *key, const char *val)
{
#ifdef NNG_SUPP_HTTP
	return (nni_http_set_header(conn, key, val));
#else
	NNI_ARG_UNUSED(conn);
	NNI_ARG_UNUSED(key);
	NNI_ARG_UNUSED(val);
	return (NNG_ENOTSUP);
#endif
}

nng_err
nng_http_add_header(nng_http *conn, const char *key, const char *val)
{
#ifdef NNG_SUPP_HTTP
	return (nni_http_add_header(conn, key, val));
#else
	NNI_ARG_UNUSED(conn);
	NNI_ARG_UNUSED(key);
	NNI_ARG_UNUSED(val);
	return (NNG_ENOTSUP);
#endif
}

void
nng_http_del_header(nng_http *conn, const char *key)
{
#ifdef NNG_SUPP_HTTP
	nni_http_del_header(conn, key);
#else
	NNI_ARG_UNUSED(conn);
	NNI_ARG_UNUSED(key);
#endif
}

void
nng_http_set_body(nng_http *conn, void *data, size_t sz)
{
#ifdef NNG_SUPP_HTTP
	nni_http_set_body(conn, data, sz);
#else
	NNI_ARG_UNUSED(conn);
	NNI_ARG_UNUSED(data);
	NNI_ARG_UNUSED(sz);
	return;
#endif
}

nng_err
nng_http_copy_body(nng_http *conn, const void *data, size_t len)
{
#ifdef NNG_SUPP_HTTP
	return (nni_http_copy_body(conn, data, len));
#else
	NNI_ARG_UNUSED(conn);
	NNI_ARG_UNUSED(data);
	NNI_ARG_UNUSED(len);
	return (NNG_ENOTSUP);
#endif
}

void
nng_http_get_body(nng_http *conn, void **datap, size_t *lenp)
{
#ifdef NNG_SUPP_HTTP
	nni_http_get_body(conn, datap, lenp);
#else
	NNI_ARG_UNUSED(conn);
	NNI_ARG_UNUSED(datap);
	NNI_ARG_UNUSED(lenp);
#endif
}

const char *
nng_http_get_uri(nng_http *conn)
{
#ifdef NNG_SUPP_HTTP
	return (nni_http_get_uri(conn));
#else
	NNI_ARG_UNUSED(conn);
	return (NULL);
#endif
}

nng_err
nng_http_set_uri(nng_http *conn, const char *uri, const char *query)
{
#ifdef NNG_SUPP_HTTP
	return (nni_http_set_uri(conn, uri, query));
#else
	NNI_ARG_UNUSED(conn);
	NNI_ARG_UNUSED(uri);
	NNI_ARG_UNUSED(query);
	return (NNG_ENOTSUP);
#endif
}

const char *
nng_http_get_version(nng_http *conn)
{
#ifdef NNG_SUPP_HTTP
	return (nni_http_get_version(conn));
#else
	NNI_ARG_UNUSED(conn);
	return (NULL);
#endif
}

void
nng_http_set_status(nng_http *conn, nng_http_status status, const char *reason)
{
#ifdef NNG_SUPP_HTTP
	nni_http_set_status(conn, status, reason);
#else
	NNI_ARG_UNUSED(conn);
	NNI_ARG_UNUSED(status);
	NNI_ARG_UNUSED(reason);
#endif
}

nng_http_status
nng_http_get_status(nng_http *conn)
{
#ifdef NNG_SUPP_HTTP
	return (nni_http_get_status(conn));
#else
	NNI_ARG_UNUSED(conn);
	return (0);
#endif
}

const char *
nng_http_get_reason(nng_http *conn)
{
#ifdef NNG_SUPP_HTTP
	return (nni_http_get_reason(conn));
#else
	NNI_ARG_UNUSED(conn);
	return (0);
#endif
}

nng_err
nng_http_set_version(nng_http *conn, const char *version)
{
#ifdef NNG_SUPP_HTTP
	return (nni_http_set_version(conn, version));
#else
	return (NNG_ENOTSUP);
#endif
}

void
nng_http_set_method(nng_http *conn, const char *method)
{
#ifdef NNG_SUPP_HTTP
	nni_http_set_method(conn, method);
#else
	NNI_ARG_UNUSED(conn);
	NNI_ARG_UNUSED(method);
#endif
}

const char *
nng_http_get_method(nng_http *conn)
{
#ifdef NNG_SUPP_HTTP
	return (nni_http_get_method(conn));
#else
	NNI_ARG_UNUSED(conn);
	return (NULL);
#endif
}

void
nng_http_close(nng_http *conn)
{
#ifdef NNG_SUPP_HTTP
	// API version of this closes *and* frees the structure.
	nni_http_conn_fini(conn);
#else
	NNI_ARG_UNUSED(conn);
#endif
}

void
nng_http_read(nng_http *conn, nng_aio *aio)
{
#ifdef NNG_SUPP_HTTP
	nni_http_read(conn, aio);
#else
	NNI_ARG_UNUSED(conn);
	nni_aio_finish_error(aio, NNG_ENOTSUP);
#endif
}

void
nng_http_read_all(nng_http *conn, nng_aio *aio)
{
#ifdef NNG_SUPP_HTTP
	nni_http_read_full(conn, aio);
#else
	NNI_ARG_UNUSED(conn);
	nni_aio_finish_error(aio, NNG_ENOTSUP);
#endif
}

void
nng_http_write(nng_http *conn, nng_aio *aio)
{
#ifdef NNG_SUPP_HTTP
	nni_http_write(conn, aio);
#else
	NNI_ARG_UNUSED(conn);
	nni_aio_finish_error(aio, NNG_ENOTSUP);
#endif
}

void
nng_http_write_all(nng_http *conn, nng_aio *aio)
{
#ifdef NNG_SUPP_HTTP
	nni_http_write_full(conn, aio);
#else
	NNI_ARG_UNUSED(conn);
	NNI_ARG_UNUSED(aio);
#endif
}

void
nng_http_write_request(nng_http *conn, nng_aio *aio)
{
#ifdef NNG_SUPP_HTTP
	nni_http_write_req(conn, aio);
#else
	NNI_ARG_UNUSED(conn);
	nni_aio_finish_error(aio, NNG_ENOTSUP);
#endif
}

void
nng_http_write_response(nng_http *conn, nng_aio *aio)
{
#ifdef NNG_SUPP_HTTP
	nni_http_write_res(conn, aio);
#else
	NNI_ARG_UNUSED(conn);
	nni_aio_finish_error(aio, NNG_ENOTSUP);
#endif
}

void
nng_http_read_response(nng_http *conn, nng_aio *aio)
{
#ifdef NNG_SUPP_HTTP
	nni_http_read_res(conn, aio);
#else
	NNI_ARG_UNUSED(conn);
	nni_aio_finish_error(aio, NNG_ENOTSUP);
#endif
}

nng_err
nng_http_remote_address(nng_http *conn, nng_sockaddr *addrp)
{
	*addrp = *(nni_http_peer_addr(conn));
	return (NNG_OK);
}

nng_err
nng_http_local_address(nng_http *conn, nng_sockaddr *addrp)
{
	*addrp = *(nni_http_self_addr(conn));
	return (NNG_OK);
}

nng_err
nng_http_handler_alloc(
    nng_http_handler **hp, const char *uri, nng_http_handler_func cb)
{
#ifdef NNG_SUPP_HTTP
	return (nni_http_handler_init(hp, uri, cb));
#else
	NNI_ARG_UNUSED(hp);
	NNI_ARG_UNUSED(uri);
	NNI_ARG_UNUSED(cb);
	return (NNG_ENOTSUP);
#endif
}

void
nng_http_handler_free(nng_http_handler *h)
{
#ifdef NNG_SUPP_HTTP
	nni_http_handler_fini(h);
#else
	NNI_ARG_UNUSED(h);
#endif
}

nng_err
nng_http_handler_alloc_file(
    nng_http_handler **hp, const char *uri, const char *path)
{
#ifdef NNG_SUPP_HTTP
	return (nni_http_handler_init_file(hp, uri, path));
#else
	NNI_ARG_UNUSED(hp);
	NNI_ARG_UNUSED(uri);
	NNI_ARG_UNUSED(path);
	return (NNG_ENOTSUP);
#endif
}

nng_err
nng_http_handler_alloc_directory(
    nng_http_handler **hp, const char *uri, const char *path)
{
#ifdef NNG_SUPP_HTTP
	return (nni_http_handler_init_directory(hp, uri, path));
#else
	NNI_ARG_UNUSED(hp);
	NNI_ARG_UNUSED(uri);
	NNI_ARG_UNUSED(path);
	return (NNG_ENOTSUP);
#endif
}

nng_err
nng_http_handler_alloc_redirect(nng_http_handler **hp, const char *uri,
    nng_http_status status, const char *where)
{
#ifdef NNG_SUPP_HTTP
	return (nni_http_handler_init_redirect(hp, uri, status, where));
#else
	NNI_ARG_UNUSED(hp);
	NNI_ARG_UNUSED(uri);
	NNI_ARG_UNUSED(status);
	NNI_ARG_UNUSED(where);
	return (NNG_ENOTSUP);
#endif
}

nng_err
nng_http_handler_alloc_static(nng_http_handler **hp, const char *uri,
    const void *data, size_t size, const char *ctype)
{
#ifdef NNG_SUPP_HTTP
	return (nni_http_handler_init_static(hp, uri, data, size, ctype));
#else
	NNI_ARG_UNUSED(hp);
	NNI_ARG_UNUSED(uri);
	NNI_ARG_UNUSED(data);
	NNI_ARG_UNUSED(size);
	NNI_ARG_UNUSED(ctype);
	return (NNG_ENOTSUP);
#endif
}

void
nng_http_handler_set_method(nng_http_handler *h, const char *meth)
{
#ifdef NNG_SUPP_HTTP
	nni_http_handler_set_method(h, meth);
#else
	NNI_ARG_UNUSED(h);
	NNI_ARG_UNUSED(meth);
#endif
}

void
nng_http_handler_collect_body(nng_http_handler *h, bool want, size_t len)
{
#ifdef NNG_SUPP_HTTP
	nni_http_handler_collect_body(h, want, len);
#else
	NNI_ARG_UNUSED(h);
	NNI_ARG_UNUSED(want);
	NNI_ARG_UNUSED(len);
#endif
}

void
nng_http_handler_set_host(nng_http_handler *h, const char *host)
{
#ifdef NNG_SUPP_HTTP
	nni_http_handler_set_host(h, host);
#else
	NNI_ARG_UNUSED(h);
	NNI_ARG_UNUSED(host);
#endif
}

void
nng_http_handler_set_tree(nng_http_handler *h)
{
#ifdef NNG_SUPP_HTTP
	nni_http_handler_set_tree(h);
#else
	NNI_ARG_UNUSED(h);
#endif
}

void
nng_http_handler_set_data(nng_http_handler *h, void *dat, void (*dtor)(void *))
{
#ifdef NNG_SUPP_HTTP
	nni_http_handler_set_data(h, dat, dtor);
#else
	NNI_ARG_UNUSED(h);
	NNI_ARG_UNUSED(dat);
	NNI_ARG_UNUSED(dtor);
#endif
}

nng_err
nng_http_server_hold(nng_http_server **srvp, const nng_url *url)
{
#ifdef NNG_SUPP_HTTP
	return (nni_http_server_init(srvp, url));
#else
	NNI_ARG_UNUSED(srvp);
	NNI_ARG_UNUSED(url);
	return (NNG_ENOTSUP);
#endif
}

void
nng_http_server_release(nng_http_server *srv)
{
#ifdef NNG_SUPP_HTTP
	nni_http_server_fini(srv);
#else
	NNI_ARG_UNUSED(srv);
#endif
}

nng_err
nng_http_server_start(nng_http_server *srv)
{
#ifdef NNG_SUPP_HTTP
	return (nni_http_server_start(srv));
#else
	NNI_ARG_UNUSED(srv);
	return (NNG_ENOTSUP);
#endif
}

void
nng_http_server_stop(nng_http_server *srv)
{
#ifdef NNG_SUPP_HTTP
	nni_http_server_stop(srv);
#else
	NNI_ARG_UNUSED(srv);
#endif
}

nng_err
nng_http_server_add_handler(nng_http_server *srv, nng_http_handler *h)
{
#ifdef NNG_SUPP_HTTP
	return (nni_http_server_add_handler(srv, h));
#else
	NNI_ARG_UNUSED(srv);
	NNI_ARG_UNUSED(h);
	return (NNG_ENOTSUP);
#endif
}

nng_err
nng_http_server_del_handler(nng_http_server *srv, nng_http_handler *h)
{
#ifdef NNG_SUPP_HTTP
	return (nni_http_server_del_handler(srv, h));
#else
	NNI_ARG_UNUSED(srv);
	NNI_ARG_UNUSED(h);
	return (NNG_ENOTSUP);
#endif
}

nng_err
nng_http_server_set_error_page(
    nng_http_server *srv, nng_http_status code, const char *body)
{
#ifdef NNG_SUPP_HTTP
	return (nni_http_server_set_error_page(srv, code, body));
#else
	NNI_ARG_UNUSED(srv);
	NNI_ARG_UNUSED(code);
	NNI_ARG_UNUSED(body);
	return (NNG_ENOTSUP);
#endif
}

nng_err
nng_http_server_set_tls(nng_http_server *srv, nng_tls_config *cfg)
{
#if defined(NNG_SUPP_HTTP) && defined(NNG_SUPP_TLS)
	return (nni_http_server_set_tls(srv, cfg));
#else
	NNI_ARG_UNUSED(srv);
	NNI_ARG_UNUSED(cfg);
	return (NNG_ENOTSUP);
#endif
}

nng_err
nng_http_server_get_tls(nng_http_server *srv, nng_tls_config **cfg)
{
#if defined(NNG_SUPP_HTTP) && defined(NNG_SUPP_TLS)
	return (nni_http_server_get_tls(srv, cfg));
#else
	NNI_ARG_UNUSED(srv);
	NNI_ARG_UNUSED(cfg);
	return (NNG_ENOTSUP);
#endif
}

nng_err
nng_http_server_get_port(nng_http_server *srv, int *port)
{
#ifdef NNG_SUPP_HTTP
	size_t size = sizeof(*port);
	return (nni_http_server_get(
	    srv, NNG_OPT_BOUND_PORT, port, &size, NNI_TYPE_INT32));
#else
	NNI_ARG_UNUSED(srv);
	NNI_ARG_UNUSED(addr);
	return (NNG_ENOTSUP);
#endif
}

nng_err
nng_http_server_error(nng_http_server *srv, nng_http *conn)
{
#ifdef NNG_SUPP_HTTP
	return (nni_http_server_error(srv, conn));
#else
	NNI_ARG_UNUSED(srv);
	NNI_ARG_UNUSED(conn);
	return (NNG_ENOTSUP);
#endif
}

nng_err
nng_http_hijack(nng_http *conn)
{
#ifdef NNG_SUPP_HTTP
	return (nni_http_hijack(conn));
#else
	NNI_ARG_UNUSED(conn);
	return (NNG_ENOTSUP);
#endif
}

nng_err
nng_http_client_alloc(nng_http_client **clip, const nng_url *url)
{
#ifdef NNG_SUPP_HTTP
	return (nni_http_client_init(clip, url));
#else
	NNI_ARG_UNUSED(clip);
	NNI_ARG_UNUSED(url);
	return (NNG_ENOTSUP);
#endif
}

void
nng_http_client_free(nng_http_client *cli)
{
#ifdef NNG_SUPP_HTTP
	nni_http_client_fini(cli);
#else
	NNI_ARG_UNUSED(cli);
#endif
}

nng_err
nng_http_client_set_tls(nng_http_client *cli, nng_tls_config *cfg)
{
#if defined(NNG_SUPP_HTTP) && defined(NNG_SUPP_TLS)
	return (nni_http_client_set_tls(cli, cfg));
#else
	NNI_ARG_UNUSED(cli);
	NNI_ARG_UNUSED(cfg);
	return (NNG_ENOTSUP);
#endif
}

nng_err
nng_http_client_get_tls(nng_http_client *cli, nng_tls_config **cfgp)
{
#if defined(NNG_SUPP_HTTP) && defined(NNG_SUPP_TLS)
	return (nni_http_client_get_tls(cli, cfgp));
#else
	NNI_ARG_UNUSED(cli);
	NNI_ARG_UNUSED(cfgp);
	return (NNG_ENOTSUP);
#endif
}

void
nng_http_client_connect(nng_http_client *cli, nng_aio *aio)
{
#ifdef NNG_SUPP_HTTP
	nni_http_client_connect(cli, aio);
#else
	NNI_ARG_UNUSED(cli);
	nni_aio_finish_error(aio, NNG_ENOTSUP);
#endif
}

void
nng_http_transact(nng_http *conn, nng_aio *aio)
{
#ifdef NNG_SUPP_HTTP
	nni_http_transact_conn(conn, aio);
#else
	NNI_ARG_UNUSED(conn);
	nni_aio_finish_error(aio, NNG_ENOTSUP);
#endif
}

void
nng_http_reset(nng_http *conn)
{
#ifdef NNG_SUPP_HTTP
	nni_http_conn_reset(conn);
#else
	NNI_ARG_UNUSED(conn);
#endif
}

nng_err
nng_http_peer_cert(nng_http *conn, nng_tls_cert **certp)
{
#ifdef NNG_SUPP_HTTP
	return (nni_http_conn_peer_cert(conn, certp));
#else
	NNI_ARG_UNUSED(conn);
	NNI_ARG_UNUSED(certp);
	return (NNG_ENOTSUP);
#endif
}
