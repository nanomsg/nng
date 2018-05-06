//
// Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <string.h>

#include "core/nng_impl.h"

// Protocol related stuff - generically.
typedef struct nni_protocol nni_protocol;
struct nni_protocol {
	const nni_proto *p_proto;
	nni_list_node    p_link;
};

static nni_mtx  nni_proto_lk;
static nni_list nni_proto_list;
static int      nni_proto_inited = 0;

static int
nni_proto_init(const nni_proto *proto)
{
	nni_protocol *p;
	int           rv;

	nni_mtx_lock(&nni_proto_lk);
	NNI_LIST_FOREACH (&nni_proto_list, p) {
		if (p->p_proto == proto) {
			nni_mtx_unlock(&nni_proto_lk);
			return (0);
		}
	}
	if ((p = NNI_ALLOC_STRUCT(p)) == NULL) {
		nni_mtx_unlock(&nni_proto_lk);
		return (NNG_ENOMEM);
	}
	NNI_LIST_NODE_INIT(&p->p_link);
	p->p_proto = proto;
	if ((proto->proto_init != NULL) && ((rv = proto->proto_init()) != 0)) {
		NNI_FREE_STRUCT(p);
		nni_mtx_unlock(&nni_proto_lk);
		return (rv);
	}
	nni_list_append(&nni_proto_list, p);
	nni_mtx_unlock(&nni_proto_lk);
	return (0);
}

int
nni_proto_open(nng_socket *sockidp, const nni_proto *proto)
{
	int       rv;
	nni_sock *sock;

	if (((rv = nni_init()) != 0) || ((rv = nni_proto_init(proto)) != 0)) {
		return (rv);
	}
	if ((rv = nni_sock_open(&sock, proto)) == 0) {
		nng_socket s;
		s.id     = nni_sock_id(sock); // Keep socket held open.
		*sockidp = s;
	}
	return (rv);
}

int
nni_proto_sys_init(void)
{
	NNI_LIST_INIT(&nni_proto_list, nni_protocol, p_link);
	nni_mtx_init(&nni_proto_lk);
	nni_proto_inited = 1;
	return (0);
}

void
nni_proto_sys_fini(void)
{
	if (nni_proto_inited) {
		nni_protocol *p;
		nni_mtx_lock(&nni_proto_lk);
		while ((p = nni_list_first(&nni_proto_list)) != NULL) {
			nni_list_remove(&nni_proto_list, p);
			if (p->p_proto->proto_fini != NULL) {
				p->p_proto->proto_fini();
			}
			NNI_FREE_STRUCT(p);
		}
		nni_mtx_unlock(&nni_proto_lk);
	}
	nni_proto_inited = 0;
	nni_mtx_fini(&nni_proto_lk);
}
