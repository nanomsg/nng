/*
 * Copyright 2016 Garrett D'Amore <garrett@damore.org>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom
 * the Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <setjmp.h>
#include <stdarg.h>

#include "test.h"

test_ctx_t *T_C = NULL;

void
test_ctx_print_start(test_ctx_t *ctx)
{
	int i;
	if (ctx->T_printed) {
		return;
	}
	ctx->T_printed = 1;
	if (ctx->T_root) {
		printf("\n=== RUN: %s\n", ctx->T_name);
	} else {
		printf("\n");
		for (i = 0; i < ctx->T_level; i++) {
			printf("  ");
		}
		printf("%s ", ctx->T_name);
		fflush(stdout);
	}
}

void
test_ctx_print_result(test_ctx_t *ctx)
{
	if (ctx->T_root) {
		printf("\n\n--- %s: %s\n",
			ctx->T_fatal ? "FATAL" :
			ctx->T_fail ? "FAIL" :
			ctx->T_skip ? "SKIP" :
			"PASS", ctx->T_name);
	}
}

void
test_ctx_log(test_ctx_t ctx, const char *fmt, ...)
{
}

void
test_ctx_fatal(test_ctx_t *ctx, const char *fmt, ...)
{
	va_list va;
	va_start(va, fmt);
	printf("FATALITY: ");
	vprintf(fmt, va);
	printf("\n");
}

extern int test_main_impl(void);

int
main(int argc, char **argv)
{
	test_main_impl();
}