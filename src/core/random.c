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

// This is ISAAC, a (reputedly) cryptographically secure PRNG that is also
// quite efficient.  While the particular adjustments to fit in our code
// base are under our copyright, the actual algorithm itself, as well as
// sample implementations, are part of the public domain.  See this:
// http://www.burtleburtle.net/bob/c/readable.c
//
// Our changes include making this code thread safe/reentrant, and naming
// and style changes, to fit C99.

typedef struct {
	// the rsl is the actual results, and the randcnt is the length
	// of the results.
	uint32_t randrsl[256];
	uint32_t randcnt;

	// lock to protect concurrent access
	nni_mtx mx;

	// more or less internal state
	uint32_t mm[256];
	uint32_t aa;
	uint32_t bb;
	uint32_t cc;
} nni_isaac_ctx;

static void
nni_isaac(nni_isaac_ctx *ctx)
{
	ctx->cc++;          // cc incremented once per 256 results
	ctx->bb += ctx->cc; // then combined with bb

	for (uint32_t i = 0; i < 256; ++i) {
		uint32_t x = ctx->mm[i];
		uint32_t y;
		switch (i % 4) {
		case 0:
			ctx->aa ^= (ctx->aa << 13);
			break;
		case 1:
			ctx->aa ^= (ctx->aa >> 6);
			break;
		case 2:
			ctx->aa ^= (ctx->aa << 2);
			break;
		case 3:
			ctx->aa ^= (ctx->aa >> 16);
			break;
		}
		ctx->aa += ctx->mm[(i + 128) % 256];
		ctx->mm[i] = y  = ctx->mm[(x >> 2) % 256] + ctx->aa + ctx->bb;
		ctx->randrsl[i] = ctx->bb = ctx->mm[(y >> 10) % 256] + x;

		// Note that bits 2..9 are chosen from x but 10..17 are chosen
		// from y.  The only important thing here is that 2..9 and
		// 10..17 don't overlap.  2..9 and 10..17 were then chosen
		// for speed in the optimized version (rand.c)

		// See http://burtleburtle.net/bob/rand/isaac.html
		// for further explanations and analysis.
	}
}

// if (flag!=0), then use the contents of randrsl[] to initialize mm[].
#define nni_isaac_mix(a, b, c, d, e, f, g, h) \
	{                                     \
		a ^= b << 11;                 \
		d += a;                       \
		b += c;                       \
		b ^= c >> 2;                  \
		e += b;                       \
		c += d;                       \
		c ^= d << 8;                  \
		f += c;                       \
		d += e;                       \
		d ^= e >> 16;                 \
		g += d;                       \
		e += f;                       \
		e ^= f << 10;                 \
		h += e;                       \
		f += g;                       \
		f ^= g >> 4;                  \
		a += f;                       \
		g += h;                       \
		g ^= h << 8;                  \
		b += g;                       \
		h += a;                       \
		h ^= a >> 9;                  \
		c += h;                       \
		a += b;                       \
	}

static void
nni_isaac_randinit(nni_isaac_ctx *ctx, int flag)
{
	int      i;
	uint32_t a, b, c, d, e, f, g, h;

	ctx->aa = ctx->bb = ctx->cc = 0;
	a = b = c = d = e = f = g = h = 0x9e3779b9; // the golden ratio

	for (i = 0; i < 4; ++i) { // scramble it
		nni_isaac_mix(a, b, c, d, e, f, g, h);
	}

	for (i = 0; i < 256; i += 8) { // fill in mm[] with messy stuff
		if (flag) {            // use all the information in the seed
			a += ctx->randrsl[i];
			b += ctx->randrsl[i + 1];
			c += ctx->randrsl[i + 2];
			d += ctx->randrsl[i + 3];
			e += ctx->randrsl[i + 4];
			f += ctx->randrsl[i + 5];
			g += ctx->randrsl[i + 6];
			h += ctx->randrsl[i + 7];
		}
		nni_isaac_mix(a, b, c, d, e, f, g, h);
		ctx->mm[i]     = a;
		ctx->mm[i + 1] = b;
		ctx->mm[i + 2] = c;
		ctx->mm[i + 3] = d;
		ctx->mm[i + 4] = e;
		ctx->mm[i + 5] = f;
		ctx->mm[i + 6] = g;
		ctx->mm[i + 7] = h;
	}

	if (flag) {
		// do a second pass to make all of the seed affect all of mm
		for (i = 0; i < 256; i += 8) {
			a += ctx->mm[i];
			b += ctx->mm[i + 1];
			c += ctx->mm[i + 2];
			d += ctx->mm[i + 3];
			e += ctx->mm[i + 4];
			f += ctx->mm[i + 5];
			g += ctx->mm[i + 6];
			h += ctx->mm[i + 7];
			nni_isaac_mix(a, b, c, d, e, f, g, h);
			ctx->mm[i]     = a;
			ctx->mm[i + 1] = b;
			ctx->mm[i + 2] = c;
			ctx->mm[i + 3] = d;
			ctx->mm[i + 4] = e;
			ctx->mm[i + 5] = f;
			ctx->mm[i + 6] = g;
			ctx->mm[i + 7] = h;
		}
	}

	nni_isaac(ctx);     // fill in the first set of results
	ctx->randcnt = 256; // prepare to use the first set of results
}

static nni_isaac_ctx nni_random_ctx;

int
nni_random_sys_init(void)
{
	// minimally, grab the system clock
	nni_isaac_ctx *ctx = &nni_random_ctx;

	nni_mtx_init(&ctx->mx);
	nni_plat_seed_prng(ctx->randrsl, sizeof(ctx->randrsl));
	nni_isaac_randinit(ctx, 1);
	return (0);
}

uint32_t
nni_random(void)
{
	uint32_t       rv;
	nni_isaac_ctx *ctx = &nni_random_ctx;

	nni_mtx_lock(&ctx->mx);
	if (ctx->randcnt < 1) {
		nni_isaac(ctx);
		ctx->randcnt = 256;
	}
	ctx->randcnt--;
	rv = ctx->randrsl[ctx->randcnt];
	nni_mtx_unlock(&ctx->mx);

	return (rv);
}

void
nni_random_sys_fini(void)
{
	nni_mtx_fini(&nni_random_ctx.mx);
}
