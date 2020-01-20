//
// Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "core/nng_impl.h"
#include "http_api.h"
#include "nng/supplemental/http/http.h"
#include "nng/supplemental/tls/tls.h"

// Symbols in this file are "public" versions of the HTTP API.
// These are suitable for exposure to applications.

int
nng_http_req_alloc(nng_http_req **reqp, const nng_url *url)
{
#ifdef NNG_SUPP_HTTP
	nni_init();
	return (nni_http_req_alloc(reqp, url));
#else
	NNI_ARG_UNUSED(reqp);
	NNI_ARG_UNUSED(url);
	return (NNG_ENOTSUP);
#endif
}

void
nng_http_req_free(nng_http_req *req)
{
#ifdef NNG_SUPP_HTTP
	nni_http_req_free(req);
#else
	NNI_ARG_UNUSED(req);
#endif
}

void
nng_http_res_free(nng_http_res *res)
{
#ifdef NNG_SUPP_HTTP
	nni_http_res_free(res);
#else
	NNI_ARG_UNUSED(res);
#endif
}

int
nng_http_res_alloc(nng_http_res **resp)
{
#ifdef NNG_SUPP_HTTP
	nni_init();
	return (nni_http_res_alloc(resp));
#else
	NNI_ARG_UNUSED(resp);
	return (NNG_ENOTSUP);
#endif
}

int
nng_http_res_alloc_error(nng_http_res **resp, uint16_t code)
{
	nni_init();
#ifdef NNG_SUPP_HTTP
	return (nni_http_res_alloc_error(resp, code));
#else
	NNI_ARG_UNUSED(resp);
	NNI_ARG_UNUSED(code);
	return (NNG_ENOTSUP);
#endif
}

const char *
nng_http_req_get_header(nng_http_req *req, const char *key)
{
#ifdef NNG_SUPP_HTTP
	return (nni_http_req_get_header(req, key));
#else
	NNI_ARG_UNUSED(req);
	NNI_ARG_UNUSED(key);
	return (NULL);
#endif
}

const char *
nng_http_res_get_header(nng_http_res *res, const char *key)
{
#ifdef NNG_SUPP_HTTP
	return (nni_http_res_get_header(res, key));
#else
	NNI_ARG_UNUSED(res);
	NNI_ARG_UNUSED(key);
	return (NULL);
#endif
}

int
nng_http_req_add_header(nng_http_req *req, const char *key, const char *val)
{
#ifdef NNG_SUPP_HTTP
	return (nni_http_req_add_header(req, key, val));
#else
	NNI_ARG_UNUSED(req);
	NNI_ARG_UNUSED(key);
	NNI_ARG_UNUSED(val);
	return (NNG_ENOTSUP);
#endif
}

int
nng_http_res_add_header(nng_http_res *res, const char *key, const char *val)
{
#ifdef NNG_SUPP_HTTP
	return (nni_http_res_add_header(res, key, val));
#else
	NNI_ARG_UNUSED(res);
	NNI_ARG_UNUSED(key);
	NNI_ARG_UNUSED(val);
	return (NNG_ENOTSUP);
#endif
}

int
nng_http_req_set_header(nng_http_req *req, const char *key, const char *val)
{
#ifdef NNG_SUPP_HTTP
	return (nni_http_req_set_header(req, key, val));
#else
	NNI_ARG_UNUSED(req);
	NNI_ARG_UNUSED(key);
	NNI_ARG_UNUSED(val);
	return (NNG_ENOTSUP);
#endif
}

int
nng_http_res_set_header(nng_http_res *res, const char *key, const char *val)
{
#ifdef NNG_SUPP_HTTP
	return (nni_http_res_set_header(res, key, val));
#else
	NNI_ARG_UNUSED(res);
	NNI_ARG_UNUSED(key);
	NNI_ARG_UNUSED(val);
	return (NNG_ENOTSUP);
#endif
}

int
nng_http_req_del_header(nng_http_req *req, const char *key)
{
#ifdef NNG_SUPP_HTTP
	return (nni_http_req_del_header(req, key));
#else
	NNI_ARG_UNUSED(req);
	NNI_ARG_UNUSED(key);
	return (NNG_ENOTSUP);
#endif
}

int
nng_http_res_del_header(nng_http_res *res, const char *key)
{
#ifdef NNG_SUPP_HTTP
	return (nni_http_res_del_header(res, key));
#else
	NNI_ARG_UNUSED(res);
	NNI_ARG_UNUSED(key);
	return (NNG_ENOTSUP);
#endif
}

int
nng_http_req_copy_data(nng_http_req *req, const void *data, size_t sz)
{
#ifdef NNG_SUPP_HTTP
	return (nni_http_req_copy_data(req, data, sz));
#else
	NNI_ARG_UNUSED(req);
	NNI_ARG_UNUSED(data);
	NNI_ARG_UNUSED(sz);
	return (NNG_ENOTSUP);
#endif
}

int
nng_http_res_copy_data(nng_http_res *res, const void *data, size_t sz)
{
#ifdef NNG_SUPP_HTTP
	return (nni_http_res_copy_data(res, data, sz));
#else
	NNI_ARG_UNUSED(res);
	NNI_ARG_UNUSED(data);
	NNI_ARG_UNUSED(sz);
	return (NNG_ENOTSUP);
#endif
}

int
nng_http_req_set_data(nng_http_req *req, const void *data, size_t sz)
{
#ifdef NNG_SUPP_HTTP
	return (nni_http_req_set_data(req, data, sz));
#else
	NNI_ARG_UNUSED(req);
	NNI_ARG_UNUSED(data);
	NNI_ARG_UNUSED(sz);
	return (NNG_ENOTSUP);
#endif
}

int
nng_http_res_set_data(nng_http_res *res, const void *data, size_t sz)
{
#ifdef NNG_SUPP_HTTP
	return (nni_http_res_set_data(res, data, sz));
#else
	NNI_ARG_UNUSED(res);
	NNI_ARG_UNUSED(data);
	NNI_ARG_UNUSED(sz);
	return (NNG_ENOTSUP);
#endif
}

void
nng_http_req_get_data(nng_http_req *req, void **datap, size_t *lenp)
{
#ifdef NNG_SUPP_HTTP
	nni_http_req_get_data(req, datap, lenp);
#else
	NNI_ARG_UNUSED(req);
	*datap = NULL;
	*lenp  = 0;
#endif
}

void
nng_http_res_get_data(nng_http_res *res, void **datap, size_t *lenp)
{
#ifdef NNG_SUPP_HTTP
	nni_http_res_get_data(res, datap, lenp);
#else
	NNI_ARG_UNUSED(res);
	*datap = NULL;
	*lenp  = 0;
#endif
}

const char *
nng_http_req_get_method(nng_http_req *req)
{
#ifdef NNG_SUPP_HTTP
	return (nni_http_req_get_method(req));
#else
	NNI_ARG_UNUSED(req);
	return (NULL);
#endif
}

const char *
nng_http_req_get_version(nng_http_req *req)
{
#ifdef NNG_SUPP_HTTP
	return (nni_http_req_get_version(req));
#else
	NNI_ARG_UNUSED(req);
	return (NULL);
#endif
}

const char *
nng_http_req_get_uri(nng_http_req *req)
{
#ifdef NNG_SUPP_HTTP
	return (nni_http_req_get_uri(req));
#else
	NNI_ARG_UNUSED(req);
	return (NULL);
#endif
}

int
nng_http_req_set_method(nng_http_req *req, const char *meth)
{
#ifdef NNG_SUPP_HTTP
	return (nni_http_req_set_method(req, meth));
#else
	NNI_ARG_UNUSED(req);
	NNI_ARG_UNUSED(meth);
	return (NNG_ENOTSUP);
#endif
}

int
nng_http_req_set_version(nng_http_req *req, const char *vers)
{
#ifdef NNG_SUPP_HTTP
	return (nni_http_req_set_version(req, vers));
#else
	NNI_ARG_UNUSED(req);
	NNI_ARG_UNUSED(vers);
	return (NNG_ENOTSUP);
#endif
}

int
nng_http_req_set_uri(nng_http_req *req, const char *uri)
{
#ifdef NNG_SUPP_HTTP
	return (nni_http_req_set_uri(req, uri));
#else
	NNI_ARG_UNUSED(req);
	NNI_ARG_UNUSED(uri);
	return (NNG_ENOTSUP);
#endif
}

uint16_t
nng_http_res_get_status(nng_http_res *res)
{
#ifdef NNG_SUPP_HTTP
	return (nni_http_res_get_status(res));
#else
	NNI_ARG_UNUSED(res);
	return (0);
#endif
}

const char *
nng_http_res_get_version(nng_http_res *res)
{
#ifdef NNG_SUPP_HTTP
	return (nni_http_res_get_version(res));
#else
	NNI_ARG_UNUSED(res);
	return (NULL);
#endif
}

const char *
nng_http_res_get_reason(nng_http_res *res)
{
#ifdef NNG_SUPP_HTTP
	return (nni_http_res_get_reason(res));
#else
	NNI_ARG_UNUSED(res);
	return (NULL);
#endif
}

int
nng_http_res_set_status(nng_http_res *res, uint16_t status)
{
#ifdef NNG_SUPP_HTTP
	return (nni_http_res_set_status(res, status));
#else
	NNI_ARG_UNUSED(res);
	NNI_ARG_UNUSED(status);
	return (NNG_ENOTSUP);
#endif
}

int
nng_http_res_set_version(nng_http_res *res, const char *vers)
{
#ifdef NNG_SUPP_HTTP
	return (nni_http_res_set_version(res, vers));
#else
	NNI_ARG_UNUSED(res);
	NNI_ARG_UNUSED(vers);
	return (NNG_ENOTSUP);
#endif
}

int
nng_http_res_set_reason(nng_http_res *res, const char *rsn)
{
#ifdef NNG_SUPP_HTTP
	return (nni_http_res_set_reason(res, rsn));
#else
	NNI_ARG_UNUSED(res);
	NNI_ARG_UNUSED(rsn);
	return (NNG_ENOTSUP);
#endif
}

void
nng_http_conn_close(nng_http_conn *conn)
{
#ifdef NNG_SUPP_HTTP
	// API version of this closes *and* frees the structure.
	nni_http_conn_fini(conn);
#else
	NNI_ARG_UNUSED(conn);
#endif
}

void
nng_http_conn_read(nng_http_conn *conn, nng_aio *aio)
{
#ifdef NNG_SUPP_HTTP
	nni_http_read(conn, aio);
#else
	NNI_ARG_UNUSED(conn);
	if (nni_aio_begin(aio) == 0) {
		nni_aio_finish_error(aio, NNG_ENOTSUP);
	}
#endif
}

void
nng_http_conn_read_all(nng_http_conn *conn, nng_aio *aio)
{
#ifdef NNG_SUPP_HTTP
	nni_http_read_full(conn, aio);
#else
	NNI_ARG_UNUSED(conn);
	if (nni_aio_begin(aio) == 0) {
		nni_aio_finish_error(aio, NNG_ENOTSUP);
	}
#endif
}

void
nng_http_conn_write(nng_http_conn *conn, nng_aio *aio)
{
#ifdef NNG_SUPP_HTTP
	nni_http_write(conn, aio);
#else
	NNI_ARG_UNUSED(conn);
	if (nni_aio_begin(aio) == 0) {
		nni_aio_finish_error(aio, NNG_ENOTSUP);
	}
#endif
}

void
nng_http_conn_write_all(nng_http_conn *conn, nng_aio *aio)
{
#ifdef NNG_SUPP_HTTP
	nni_http_write_full(conn, aio);
#else
	NNI_ARG_UNUSED(conn);
	NNI_ARG_UNUSED(aio);
#endif
}

void
nng_http_conn_write_req(nng_http_conn *conn, nng_http_req *req, nng_aio *aio)
{
#ifdef NNG_SUPP_HTTP
	nni_http_write_req(conn, req, aio);
#else
	NNI_ARG_UNUSED(conn);
	NNI_ARG_UNUSED(req);
	if (nni_aio_begin(aio) == 0) {
		nni_aio_finish_error(aio, NNG_ENOTSUP);
	}
#endif
}

void
nng_http_conn_write_res(nng_http_conn *conn, nng_http_res *res, nng_aio *aio)
{
#ifdef NNG_SUPP_HTTP
	nni_http_write_res(conn, res, aio);
#else
	NNI_ARG_UNUSED(conn);
	NNI_ARG_UNUSED(res);
	if (nni_aio_begin(aio) == 0) {
		nni_aio_finish_error(aio, NNG_ENOTSUP);
	}
#endif
}

void
nng_http_conn_read_req(nng_http_conn *conn, nng_http_req *req, nng_aio *aio)
{
#ifdef NNG_SUPP_HTTP
	nni_http_read_req(conn, req, aio);
#else
	NNI_ARG_UNUSED(conn);
	NNI_ARG_UNUSED(req);
	if (nni_aio_begin(aio) == 0) {
		nni_aio_finish_error(aio, NNG_ENOTSUP);
	}
#endif
}

void
nng_http_conn_read_res(nng_http_conn *conn, nng_http_res *res, nng_aio *aio)
{
#ifdef NNG_SUPP_HTTP
	nni_http_read_res(conn, res, aio);
#else
	NNI_ARG_UNUSED(conn);
	NNI_ARG_UNUSED(res);
	if (nni_aio_begin(aio) == 0) {
		nni_aio_finish_error(aio, NNG_ENOTSUP);
	}
#endif
}

int
nng_http_handler_alloc(
    nng_http_handler **hp, const char *uri, void (*cb)(nng_aio *))
{
#ifdef NNG_SUPP_HTTP
	nni_init();
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

int
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

int
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

int
nng_http_handler_alloc_redirect(
    nng_http_handler **hp, const char *uri, uint16_t status, const char *where)
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

int
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

int
nng_http_handler_set_method(nng_http_handler *h, const char *meth)
{
#ifdef NNG_SUPP_HTTP
	return (nni_http_handler_set_method(h, meth));
#else
	NNI_ARG_UNUSED(h);
	NNI_ARG_UNUSED(meth);
	return (NNG_ENOTSUP);
#endif
}

int
nng_http_handler_collect_body(nng_http_handler *h, bool want, size_t len)
{
#ifdef NNG_SUPP_HTTP
	nni_http_handler_collect_body(h, want, len);
	return (0);
#else
	return (NNG_ENOTSUP);
#endif
}

int
nng_http_handler_set_host(nng_http_handler *h, const char *host)
{
#ifdef NNG_SUPP_HTTP
	return (nni_http_handler_set_host(h, host));
#else
	NNI_ARG_UNUSED(h);
	NNI_ARG_UNUSED(host);
	return (NNG_ENOTSUP);
#endif
}

int
nng_http_handler_set_tree(nng_http_handler *h)
{
#ifdef NNG_SUPP_HTTP
	return (nni_http_handler_set_tree(h));
#else
	NNI_ARG_UNUSED(h);
	return (NNG_ENOTSUP);
#endif
}

int
nng_http_handler_set_tree_exclusive(nng_http_handler *h)
{
#ifdef NNG_SUPP_HTTP
	return (nni_http_handler_set_tree_exclusive(h));
#else
	NNI_ARG_UNUSED(h);
	return (NNG_ENOTSUP);
#endif
}

int
nng_http_handler_set_data(nng_http_handler *h, void *dat, void (*dtor)(void *))
{
#ifdef NNG_SUPP_HTTP
	return (nni_http_handler_set_data(h, dat, dtor));
#else
	NNI_ARG_UNUSED(h);
	NNI_ARG_UNUSED(dat);
	NNI_ARG_UNUSED(dtor);
	return (NNG_ENOTSUP);
#endif
}

void *
nng_http_handler_get_data(nng_http_handler *h)
{
#ifdef NNG_SUPP_HTTP
	return (nni_http_handler_get_data(h));
#else
	NNI_ARG_UNUSED(h);
	return (NULL);
#endif
}

int
nng_http_server_hold(nng_http_server **srvp, const nng_url *url)
{
#ifdef NNG_SUPP_HTTP
	nni_init();
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

int
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

int
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

int
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

int
nng_http_server_set_error_page(
    nng_http_server *srv, uint16_t code, const char *body)
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

int
nng_http_server_set_error_file(
    nng_http_server *srv, uint16_t code, const char *path)
{
#ifdef NNG_SUPP_HTTP
	return (nni_http_server_set_error_file(srv, code, path));
#else
	NNI_ARG_UNUSED(srv);
	NNI_ARG_UNUSED(code);
	NNI_ARG_UNUSED(path);
	return (NNG_ENOTSUP);
#endif
}

int
nng_http_server_set_tls(nng_http_server *srv, struct nng_tls_config *cfg)
{
#if defined(NNG_SUPP_HTTP) && defined(NNG_SUPP_TLS)
	return (nni_http_server_set_tls(srv, cfg));
#else
	NNI_ARG_UNUSED(srv);
	NNI_ARG_UNUSED(cfg);
	return (NNG_ENOTSUP);
#endif
}

int
nng_http_server_get_tls(nng_http_server *srv, struct nng_tls_config **cfgp)
{
#if defined(NNG_SUPP_HTTP) && defined(NNG_SUPP_TLS)
	return (nni_http_server_get_tls(srv, cfgp));
#else
	NNI_ARG_UNUSED(srv);
	NNI_ARG_UNUSED(cfgp);
	return (NNG_ENOTSUP);
#endif
}

int
nng_http_server_get_addr(nng_http_server *srv, nng_sockaddr *addrp)
{
#ifdef NNG_SUPP_HTTP
	size_t size = sizeof(nng_sockaddr);
	if (srv == NULL || addrp == NULL)
		return NNG_EINVAL;
	return (nni_http_server_getx(
	    srv, NNG_OPT_LOCADDR, addrp, &size, NNI_TYPE_SOCKADDR));
#else
	NNI_ARG_UNUSED(srv);
	NNI_ARG_UNUSED(addrp);
	return (NNG_ENOTSUP);
#endif
}

int
nng_http_server_res_error(nng_http_server *srv, nng_http_res *res)
{
#ifdef NNG_SUPP_HTTP
	return (nni_http_server_res_error(srv, res));
#else
	NNI_ARG_UNUSED(srv);
	NNI_ARG_UNUSED(res);
	return (NNG_ENOTSUP);
#endif
}

int
nng_http_hijack(nng_http_conn *conn)
{
#ifdef NNG_SUPP_HTTP
	return (nni_http_hijack(conn));
#else
	NNI_ARG_UNUSED(conn);
	return (NNG_ENOTSUP);
#endif
}

int
nng_http_client_alloc(nng_http_client **clip, const nng_url *url)
{
#ifdef NNG_SUPP_HTTP
	nni_init();
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

int
nng_http_client_set_tls(nng_http_client *cli, struct nng_tls_config *cfg)
{
#if defined(NNG_SUPP_HTTP) && defined(NNG_SUPP_TLS)
	return (nni_http_client_set_tls(cli, cfg));
#else
	NNI_ARG_UNUSED(cli);
	NNI_ARG_UNUSED(cfg);
	return (NNG_ENOTSUP);
#endif
}

int
nng_http_client_get_tls(nng_http_client *cli, struct nng_tls_config **cfgp)
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
	if (nni_aio_begin(aio) == 0) {
		nni_aio_finish_error(aio, NNG_ENOTSUP);
	}
#endif
}

void
nng_http_client_transact(
    nng_http_client *cli, nng_http_req *req, nng_http_res *res, nng_aio *aio)
{
#ifdef NNG_SUPP_HTTP
	nni_http_transact(cli, req, res, aio);
#else
	NNI_ARG_UNUSED(cli);
	NNI_ARG_UNUSED(req);
	NNI_ARG_UNUSED(res);
	if (nni_aio_begin(aio) == 0) {
		nni_aio_finish_error(aio, NNG_ENOTSUP);
	}
#endif
}

void
nng_http_conn_transact(
    nng_http_conn *conn, nng_http_req *req, nng_http_res *res, nng_aio *aio)
{
#ifdef NNG_SUPP_HTTP
	nni_http_transact_conn(conn, req, res, aio);
#else
	NNI_ARG_UNUSED(conn);
	NNI_ARG_UNUSED(req);
	NNI_ARG_UNUSED(res);
	if (nni_aio_begin(aio) == 0) {
		nni_aio_finish_error(aio, NNG_ENOTSUP);
	}
#endif
}

void
nng_http_req_reset(nng_http_req *req)
{
#ifdef NNG_SUPP_HTTP
	nni_http_req_reset(req);
#endif
}

void
nng_http_res_reset(nng_http_res *res)
{
#ifdef NNG_SUPP_HTTP
	nni_http_res_reset(res);
#endif
}
