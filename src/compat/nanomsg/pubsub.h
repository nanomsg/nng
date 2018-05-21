//
// Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#ifndef NNG_COMPAT_PUBSUB_H
#define NNG_COMPAT_PUBSUB_H

// This header contains interfaces that are intended to offer compatibility
// with nanomsg v1.0.  These are not the "preferred" interfaces for nng,
// and consumers should only use these if they are porting software that
// previously used nanomsg.  New programs should use the nng native APIs.

#ifdef __cplusplus
extern "C" {
#endif

// PUB and SUB sockopt level.
#define NN_PROTO_PUBSUB 2
#define NN_PUB (NN_PROTO_PUBSUB * 16 + 0)
#define NN_SUB (NN_PROTO_PUBSUB * 16 + 1)

// SUB options.  (PUB has none.)
#define NN_SUB_SUBSCRIBE (NN_SUB * 16 + 1)
#define NN_SUB_UNSUBSCRIBE (NN_SUB * 16 + 2)

#ifdef __cplusplus
}
#endif

#endif // NNG_COMPAT_PUBSUB_H
