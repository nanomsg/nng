//
// Copyright 2017 Garrett D'Amore <garrett@damore.org>
// Copyright 2017 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <string.h>

#include "core/nng_impl.h"

// Protocol related stuff - generically.

int
nni_proto_open(nng_socket *sockidp, const nni_proto *proto)
{
	int       rv;
	nni_sock *sock;

	if ((rv = nni_sock_open(&sock, proto)) == 0) {
		*sockidp = nni_sock_id(sock); // Keep socket held open.
	}
	return (rv);
}
