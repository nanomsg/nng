//
// Copyright 2020 Staysail Systems, Inc. <info@staysail.tech>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#ifndef NNG_ELIDE_DEPRECATED
#include "core/nng_impl.h"

// These are legacy APIs that we would prefer nobody used.
// Eventually they will likely be removed.  For now we have
// to continue to provide them for compatibility.

// This function is not supported, but we keep it around to
// satisfy link dependencies in old programs.  It has never done
// anything useful.
int
nng_msg_getopt(nng_msg *msg, int opt, void *ptr, size_t *szp)
{
	NNI_ARG_UNUSED(msg);
	NNI_ARG_UNUSED(opt);
	NNI_ARG_UNUSED(ptr);
	NNI_ARG_UNUSED(szp);
	return (NNG_ENOTSUP);
}

int
nng_getopt(nng_socket id, const char *n, void *v, size_t *sz)
{
	return (nng_socket_get(id, n, v, sz));
}

int
nng_getopt_int(nng_socket id, const char *n, int *v)
{
	return (nng_socket_get_int(id, n, v));
}

int
nng_getopt_uint64(nng_socket id, const char *n, uint64_t *v)
{
	return (nng_socket_get_uint64(id, n, v));
}

int
nng_getopt_bool(nng_socket id, const char *n, bool *v)
{
	return (nng_socket_get_bool(id, n, v));
}

int
nng_getopt_size(nng_socket id, const char *n, size_t *v)
{
	return (nng_socket_get_size(id, n, v));
}

int
nng_getopt_ms(nng_socket id, const char *n, nng_duration *v)
{
	return (nng_socket_get_ms(id, n, v));
}

int nng_getopt_ptr(nng_socket id, const char *n, void **v)
{
	return (nng_socket_get_ptr(id, n, v));
}

int
nng_getopt_string(nng_socket id, const char *n, char **v)
{
	return (nng_socket_get_string(id, n, v));
}

int
nng_setopt(nng_socket id, const char *name, const void *v, size_t sz)
{
	return (nng_socket_set(id, name, v, sz));
}

int
nng_setopt_bool(nng_socket id, const char *n, bool v)
{
	return (nng_socket_set_bool(id, n, v));
}

int
nng_setopt_int(nng_socket id, const char *n, int v)
{
	return (nng_socket_set_int(id, n, v));
}

int
nng_setopt_ms(nng_socket id, const char *n, nng_duration v)
{
	return (nng_socket_set_ms(id, n, v));
}

int
nng_setopt_size(nng_socket id, const char *n, size_t v)
{
	return (nng_socket_set_size(id, n, v));
}

int
nng_setopt_uint64(nng_socket id, const char *n, uint64_t v)
{
	return (nng_socket_set_uint64(id, n, v));
}

int
nng_setopt_string(nng_socket id, const char *n, const char *v)
{
	return (nng_socket_set_string(id, n, v));
}

int
nng_setopt_ptr(nng_socket id, const char *n, void *v)
{
	return (nng_socket_set_ptr(id, n, v));
}

// Contexts.

int
nng_ctx_getopt(nng_ctx id, const char *n, void *v, size_t *sz)
{
	return (nng_ctx_get(id, n, v, sz));
}

int
nng_ctx_getopt_int(nng_ctx id, const char *n, int *v)
{
	return (nng_ctx_get_int(id, n, v));
}

int
nng_ctx_getopt_bool(nng_ctx id, const char *n, bool *v)
{
	return (nng_ctx_get_bool(id, n, v));
}

int
nng_ctx_getopt_size(nng_ctx id, const char *n, size_t *v)
{
	return (nng_ctx_get_size(id, n, v));
}

int
nng_ctx_getopt_ms(nng_ctx id, const char *n, nng_duration *v)
{
	return (nng_ctx_get_ms(id, n, v));
}

int
nng_ctx_setopt(nng_ctx id, const char *name, const void *v, size_t sz)
{
	return (nng_ctx_set(id, name, v, sz));
}

int
nng_ctx_setopt_bool(nng_ctx id, const char *n, bool v)
{
	return (nng_ctx_set_bool(id, n, v));
}

int
nng_ctx_setopt_int(nng_ctx id, const char *n, int v)
{
	return (nng_ctx_set_int(id, n, v));
}

int
nng_ctx_setopt_ms(nng_ctx id, const char *n, nng_duration v)
{
	return (nng_ctx_set_ms(id, n, v));
}

int
nng_ctx_setopt_size(nng_ctx id, const char *n, size_t v)
{
	return (nng_ctx_set_size(id, n, v));
}

// Dialers.

int
nng_dialer_getopt(nng_dialer id, const char *n, void *v, size_t *sz)
{
	return (nng_dialer_get(id, n, v, sz));
}

int
nng_dialer_getopt_int(nng_dialer id, const char *n, int *v)
{
	return (nng_dialer_get_int(id, n, v));
}

int
nng_dialer_getopt_bool(nng_dialer id, const char *n, bool *v)
{
	return (nng_dialer_get_bool(id, n, v));
}

int
nng_dialer_getopt_size(nng_dialer id, const char *n, size_t *v)
{
	return (nng_dialer_get_size(id, n, v));
}

int
nng_dialer_getopt_uint64(nng_dialer id, const char *n, uint64_t *v)
{
	return (nng_dialer_get_uint64(id, n, v));
}

int
nng_dialer_getopt_string(nng_dialer id, const char *n, char **v)
{
	return (nng_dialer_get_string(id, n, v));
}

int
nng_dialer_getopt_ptr(nng_dialer id, const char *n, void **v)
{
	return (nng_dialer_get_ptr(id, n, v));
}

int
nng_dialer_getopt_ms(nng_dialer id, const char *n, nng_duration *v)
{
	return (nng_dialer_get_ms(id, n, v));
}

int
nng_dialer_getopt_sockaddr(nng_dialer id, const char *n, nng_sockaddr *v)
{
	return (nng_dialer_get_addr(id, n, v));
}

int
nng_dialer_setopt(
    nng_dialer id, const char *name, const void *v, size_t sz)
{
	return (nng_dialer_set(id, name, v, sz));
}

int
nng_dialer_setopt_bool(nng_dialer id, const char *n, bool v)
{
	return (nng_dialer_set_bool(id, n, v));
}

int
nng_dialer_setopt_int(nng_dialer id, const char *n, int v)
{
	return (nng_dialer_set_int(id, n, v));
}

int
nng_dialer_setopt_ms(nng_dialer id, const char *n, nng_duration v)
{
	return (nng_dialer_set_ms(id, n, v));
}

int
nng_dialer_setopt_size(nng_dialer id, const char *n, size_t v)
{
	return (nng_dialer_set_size(id, n, v));
}

int
nng_dialer_setopt_uint64(nng_dialer id, const char *n, uint64_t v)
{
	return (nng_dialer_set_uint64(id, n, v));
}

int
nng_dialer_setopt_ptr(nng_dialer id, const char *n, void *v)
{
	return (nng_dialer_set_ptr(id, n, v));
}

int
nng_dialer_setopt_string(nng_dialer id, const char *n, const char *v)
{
	return (nng_dialer_set_string(id, n, v));
}

// Listeners.

int
nng_listener_getopt(nng_listener id, const char *n, void *v, size_t *sz)
{
	return (nng_listener_get(id, n, v, sz));
}

int
nng_listener_getopt_int(nng_listener id, const char *n, int *v)
{
	return (nng_listener_get_int(id, n, v));
}

int
nng_listener_getopt_bool(nng_listener id, const char *n, bool *v)
{
	return (nng_listener_get_bool(id, n, v));
}

int
nng_listener_getopt_size(nng_listener id, const char *n, size_t *v)
{
	return (nng_listener_get_size(id, n, v));
}

int
nng_listener_getopt_uint64(nng_listener id, const char *n, uint64_t *v)
{
	return (nng_listener_get_uint64(id, n, v));
}

int
nng_listener_getopt_string(nng_listener id, const char *n, char **v)
{
	return (nng_listener_get_string(id, n, v));
}

int
nng_listener_getopt_ptr(nng_listener id, const char *n, void **v)
{
	return (nng_listener_get_ptr(id, n, v));
}

int
nng_listener_getopt_ms(nng_listener id, const char *n, nng_duration *v)
{
	return (nng_listener_get_ms(id, n, v));
}

int
nng_listener_getopt_sockaddr(nng_listener id, const char *n, nng_sockaddr *v)
{
	return (nng_listener_get_addr(id, n, v));
}

int
nng_listener_setopt(
    nng_listener id, const char *name, const void *v, size_t sz)
{
	return (nng_listener_set(id, name, v, sz));
}

int
nng_listener_setopt_bool(nng_listener id, const char *n, bool v)
{
	return (nng_listener_set_bool(id, n, v));
}

int
nng_listener_setopt_int(nng_listener id, const char *n, int v)
{
	return (nng_listener_set_int(id, n, v));
}

int
nng_listener_setopt_ms(nng_listener id, const char *n, nng_duration v)
{
	return (nng_listener_set_ms(id, n, v));
}

int
nng_listener_setopt_size(nng_listener id, const char *n, size_t v)
{
	return (nng_listener_set_size(id, n, v));
}

int
nng_listener_setopt_uint64(nng_listener id, const char *n, uint64_t v)
{
	return (nng_listener_set_uint64(id, n, v));
}

int
nng_listener_setopt_ptr(nng_listener id, const char *n, void *v)
{
	return (nng_listener_set_ptr(id, n, v));
}

int
nng_listener_setopt_string(nng_listener id, const char *n, const char *v)
{
	return (nng_listener_set_string(id, n, v));
}

// Pipes

int
nng_pipe_getopt(nng_pipe id, const char *n, void *v, size_t *sz)
{
	return (nng_pipe_get(id, n, v, sz));
}

int
nng_pipe_getopt_int(nng_pipe id, const char *n, int *v)
{
	return (nng_pipe_get_int(id, n, v));
}

int
nng_pipe_getopt_bool(nng_pipe id, const char *n, bool *v)
{
	return (nng_pipe_get_bool(id, n, v));
}

int
nng_pipe_getopt_size(nng_pipe id, const char *n, size_t *v)
{
	return (nng_pipe_get_size(id, n, v));
}

int
nng_pipe_getopt_uint64(nng_pipe id, const char *n, uint64_t *v)
{
	return (nng_pipe_get_uint64(id, n, v));
}

int
nng_pipe_getopt_string(nng_pipe id, const char *n, char **v)
{
	return (nng_pipe_get_string(id, n, v));
}

int
nng_pipe_getopt_ptr(nng_pipe id, const char *n, void **v)
{
	return (nng_pipe_get_ptr(id, n, v));
}

int
nng_pipe_getopt_ms(nng_pipe id, const char *n, nng_duration *v)
{
	return (nng_pipe_get_ms(id, n, v));
}

int
nng_pipe_getopt_sockaddr(nng_pipe id, const char *n, nng_sockaddr *v)
{
	return (nng_pipe_get_addr(id, n, v));
}

void
nng_closeall(void)
{
	nni_sock_closeall();
}

#endif // NNG_ELIDE_DEPRECATED