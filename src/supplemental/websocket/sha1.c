//
// Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

// This file represents a modification of Paul E. Jones' implementation.
// We have adapted this code for C99, removed the error checks on input size,
// and adjusted names to fit within NNG.  We also updated the code to emit
// the digest as a byte array, following convention. The original code was
// distributed with the following notice:

// Copyright (C) 1998, 2009
// Paul E. Jones <paulej@packetizer.com>
//
// Freeware Public License (FPL)
//
// This software is licensed as "freeware."  Permission to distribute
// this software in source and binary forms, including incorporation
// into other products, is hereby granted without a fee.  THIS SOFTWARE
// IS PROVIDED 'AS IS' AND WITHOUT ANY EXPRESSED OR IMPLIED WARRANTIES,
// INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
// AND FITNESS FOR A PARTICULAR PURPOSE.  THE AUTHOR SHALL NOT BE HELD
// LIABLE FOR ANY DAMAGES RESULTING FROM THE USE OF THIS SOFTWARE, EITHER
// DIRECTLY OR INDIRECTLY, INCLUDING, BUT NOT LIMITED TO, LOSS OF DATA
// OR DATA BEING RENDERED INACCURATE.

// This file implements the Secure Hashing Standard, defined in FIPS PUB 180-1
// and RFC 3174. This particular implementation has not undergone any NIST
// validation.  Furthermore, SHA-1 has been found to be insufficiently strong
// against cryptanalysis, and it's use is specifically discouraged in new
// security-sensitive applications.  Nonetheless, it is useful for non-secure
// applications such as basic message validation.  In the websocket protocol
// (RFC 6455), SHA-1's use is limited to a non-security sensitive context.

// This implementation assumes an 8-bit byte, and a C99 compilation
// environment including support for 64-bit integers.  It does not
// detect overflows caused by issuing too large messages (2^56 bytes is the
// maximum message size) or caused by incorrect usage.  The results in either
// of those circumstances are undefined.

#include <stdint.h>
#include <string.h>

#include "sha1.h"

// Define the circular shift macro
#define nni_sha1_circular_shift(bits, word) \
	((((word) << (bits)) & 0xFFFFFFFF) | ((word) >> (32 - (bits))))

static void nni_sha1_process(nni_sha1_ctx *);
static void nni_sha1_pad(nni_sha1_ctx *);

// nni_sha1_init initializes the context to an initial value.
void
nni_sha1_init(nni_sha1_ctx *ctx)
{
	ctx->len = 0;
	ctx->idx = 0;

	ctx->digest[0] = 0x67452301;
	ctx->digest[1] = 0xEFCDAB89;
	ctx->digest[2] = 0x98BADCFE;
	ctx->digest[3] = 0x10325476;
	ctx->digest[4] = 0xC3D2E1F0;
}

// nni_sha1_final runs the final padding for the digest, and stores
// the resulting digest in the supplied output buffer.
void
nni_sha1_final(nni_sha1_ctx *ctx, uint8_t digest[20])
{
	nni_sha1_pad(ctx);
	for (int i = 0; i < 5; i++) {
		digest[i * 4]     = (ctx->digest[i] >> 24) & 0xff;
		digest[i * 4 + 1] = (ctx->digest[i] >> 16) & 0xff;
		digest[i * 4 + 2] = (ctx->digest[i] >> 8) & 0xff;
		digest[i * 4 + 3] = (ctx->digest[i] >> 0) & 0xff;
	}
}

// nni_sha1 is a convenience that does the entire init, update, and final
// sequence in a single operation.
void
nni_sha1(const void *msg, size_t length, uint8_t digest[20])
{
	nni_sha1_ctx ctx;

	nni_sha1_init(&ctx);
	nni_sha1_update(&ctx, msg, length);
	nni_sha1_final(&ctx, digest);
}

// nni_sha1_update updates the SHA1 context, reading from the message supplied.
void
nni_sha1_update(nni_sha1_ctx *ctx, const void *data, size_t length)
{
	const uint8_t *msg = data;

	if (!length) {
		return;
	}

	while (length--) {
		// memcpy might be faster...
		ctx->blk[ctx->idx++] = (*msg & 0xFF);
		ctx->len += 8;

		if (ctx->idx == 64) {
			// This will reset the index back to zero.
			nni_sha1_process(ctx);
		}

		msg++;
	}
}

// nni_sha1_process processes the next 512 bites of the message stored
// in the blk array.
void
nni_sha1_process(nni_sha1_ctx *ctx)
{
	const unsigned K[] = // Constants defined in SHA-1
	    { 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6 };
	unsigned temp;          // Temporary word value
	unsigned W[80];         // Word sequence
	unsigned A, B, C, D, E; // Word buffers

	// Initialize the first 16 words in the array W
	for (int t = 0; t < 16; t++) {
		W[t] = ((unsigned) ctx->blk[t * 4]) << 24;
		W[t] |= ((unsigned) ctx->blk[t * 4 + 1]) << 16;
		W[t] |= ((unsigned) ctx->blk[t * 4 + 2]) << 8;
		W[t] |= ((unsigned) ctx->blk[t * 4 + 3]);
	}

	for (int t = 16; t < 80; t++) {
		W[t] = nni_sha1_circular_shift(
		    1, W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16]);
	}

	A = ctx->digest[0];
	B = ctx->digest[1];
	C = ctx->digest[2];
	D = ctx->digest[3];
	E = ctx->digest[4];

	for (int t = 0; t < 20; t++) {
		temp = nni_sha1_circular_shift(5, A) + ((B & C) | ((~B) & D)) +
		    E + W[t] + K[0];
		temp &= 0xFFFFFFFF;
		E = D;
		D = C;
		C = nni_sha1_circular_shift(30, B);
		B = A;
		A = temp;
	}

	for (int t = 20; t < 40; t++) {
		temp = nni_sha1_circular_shift(5, A) + (B ^ C ^ D) + E + W[t] +
		    K[1];
		temp &= 0xFFFFFFFF;
		E = D;
		D = C;
		C = nni_sha1_circular_shift(30, B);
		B = A;
		A = temp;
	}

	for (int t = 40; t < 60; t++) {
		temp = nni_sha1_circular_shift(5, A) +
		    ((B & C) | (B & D) | (C & D)) + E + W[t] + K[2];
		temp &= 0xFFFFFFFF;
		E = D;
		D = C;
		C = nni_sha1_circular_shift(30, B);
		B = A;
		A = temp;
	}

	for (int t = 60; t < 80; t++) {
		temp = nni_sha1_circular_shift(5, A) + (B ^ C ^ D) + E + W[t] +
		    K[3];
		temp &= 0xFFFFFFFF;
		E = D;
		D = C;
		C = nni_sha1_circular_shift(30, B);
		B = A;
		A = temp;
	}

	ctx->digest[0] = (ctx->digest[0] + A) & 0xFFFFFFFF;
	ctx->digest[1] = (ctx->digest[1] + B) & 0xFFFFFFFF;
	ctx->digest[2] = (ctx->digest[2] + C) & 0xFFFFFFFF;
	ctx->digest[3] = (ctx->digest[3] + D) & 0xFFFFFFFF;
	ctx->digest[4] = (ctx->digest[4] + E) & 0xFFFFFFFF;

	ctx->idx = 0;
}

// nni_sha1_pad pads the message, adding the length.  This is done
// when finishing the message.
//
// According to the standard, the message must be padded to an even 512 bits.
// The first padding bit must be a '1'.  The last 64 bits represent the length
// of the original message.  All bits in between should be 0.  This function
// will pad the message according to those rules by filling the blk array
// accordingly. It will also call nni_sha1_process() appropriately.  When it
// returns, it can be assumed that the message digest has been computed.
void
nni_sha1_pad(nni_sha1_ctx *ctx)
{
	// Check to see if the current message block is too small to hold
	// the initial padding bits and length.  If so, we will pad the
	// block, process it, and then continue padding into a second block.
	if (ctx->idx > 55) {
		ctx->blk[ctx->idx++] = 0x80;
		while (ctx->idx < 64) {
			ctx->blk[ctx->idx++] = 0;
		}

		nni_sha1_process(ctx);

		while (ctx->idx < 56) {
			ctx->blk[ctx->idx++] = 0;
		}
	} else {
		ctx->blk[ctx->idx++] = 0x80;
		while (ctx->idx < 56) {
			ctx->blk[ctx->idx++] = 0;
		}
	}

	// Store the message length as the last 8 octets (big endian)
	ctx->blk[56] = (ctx->len >> 56) & 0xff;
	ctx->blk[57] = (ctx->len >> 48) & 0xff;
	ctx->blk[58] = (ctx->len >> 40) & 0xff;
	ctx->blk[59] = (ctx->len >> 32) & 0xff;
	ctx->blk[60] = (ctx->len >> 24) & 0xff;
	ctx->blk[61] = (ctx->len >> 16) & 0xff;
	ctx->blk[62] = (ctx->len >> 8) & 0xff;
	ctx->blk[63] = (ctx->len) & 0xff;

	nni_sha1_process(ctx);
}
