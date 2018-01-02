//
// Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#ifndef NNG_SUPPLEMENTAL_SHA1_SHA1_H
#define NNG_SUPPLEMENTAL_SHA1_SHA1_H

typedef struct {
	uint32_t digest[5]; // resulting digest
	uint64_t len;       // length in bits
	uint8_t  blk[64];   // message block
	int      idx;       // index of next byte in block
} nni_sha1_ctx;

extern void nni_sha1_init(nni_sha1_ctx *);
extern void nni_sha1_update(nni_sha1_ctx *, const void *, size_t);
extern void nni_sha1_final(nni_sha1_ctx *, uint8_t[20]);
extern void nni_sha1(const void *, size_t, uint8_t[20]);

#endif // NNG_SUPPLEMENTAL_SHA1_SHA1_H
