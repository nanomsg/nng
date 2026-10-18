//
// Copyright 2026 Staysail Systems, Inc. <info@staysail.tech>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "../core/nng_impl.h"

#include "../testing/nuts.h"

static void
test_known_errors(void)
{
	NUTS_MATCH(nng_strerror(0), "Hunky dory");
	NUTS_MATCH(nng_strerror(NNG_ECLOSED), "Object closed");
	NUTS_MATCH(nng_strerror(NNG_ETIMEDOUT), "Timed out");
	NUTS_MATCH(nng_strerror(NNG_ESTOPPED), "Operation stopped");
}

static void
test_unknown_errors(void)
{
	for (unsigned i = 1; i < 0x1000000; i = i * 2 + 100) {
		NUTS_TRUE(nng_strerror(i) != NULL);
	}
}

static void
test_system_errors(void)
{
#ifdef NNG_PLATFORM_POSIX
	int  errors[] = { 0, ENOENT, EINVAL, EIO, EFAULT };
	char expected[1024];

	for (unsigned i = 0; i < NNI_NUM_ELEMENTS(errors); i++) {
		snprintf(expected, sizeof(expected), "%s (%d)",
		    strerror(errors[i]), errors[i]);
		NUTS_MATCH(nng_strerror(NNG_ESYSERR | errors[i]), expected);
	}
#else
	char  expected[1024];
	DWORD len = FormatMessageA(
	    FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL,
	    ERROR_INVALID_PARAMETER, 0, expected, sizeof(expected), NULL);
	NUTS_ASSERT(len != 0);
	while ((len != 0) &&
	    ((expected[len - 1] == '\r') || (expected[len - 1] == '\n'))) {
		expected[--len] = '\0';
	}
	NUTS_MATCH(
	    nng_strerror(NNG_ESYSERR | ERROR_INVALID_PARAMETER), expected);
#endif
	NUTS_TRUE(strstr(nng_strerror(NNG_ESYSERR | 0x0fffffff),
	              "268435455") != NULL);
}

static void
overwrite_error_messages(void *arg)
{
	(void) arg;
	(void) nng_strerror(NNG_ESYSERR | 12345);
	(void) nng_strerror(NNG_ETRANERR | 12345);
	(void) nng_strerror(12345);
	(void) strerror(12345);
}

static void
test_error_message_lifetime(void)
{
	const char *system = nng_strerror(NNG_ESYSERR | 23456);
	const char *known  = nng_strerror(NNG_ESYSERR | ENOENT);
	const char *tran   = nng_strerror(NNG_ETRANERR | 23456);
	const char *other  = nng_strerror(23456);
	char        saved[128];
	char        known_saved[128];
	nng_thread *thread;

	NUTS_ASSERT(strlen(system) < sizeof(saved));
	strcpy(saved, system);
	NUTS_ASSERT(strlen(known) < sizeof(known_saved));
	strcpy(known_saved, known);
	// Calls in either this thread or another must not overwrite a message.
	overwrite_error_messages(NULL);
	NUTS_MATCH(system, saved);
	NUTS_PASS(nng_thread_create(&thread, overwrite_error_messages, NULL));
	nng_thread_destroy(thread);
	NUTS_MATCH(system, saved);
	NUTS_MATCH(known, known_saved);
	NUTS_MATCH(tran, "Transport error #23456");
	NUTS_MATCH(other, "Unknown error #23456");
	NUTS_TRUE(system == nng_strerror(NNG_ESYSERR | 23456));
}

struct error_thread_arg {
	nng_mtx    *gate;
	const char *message;
	bool        ok;
};

static void
format_errors(void *arg)
{
	struct error_thread_arg *a = arg;
	char                     expected[64];

	nng_mtx_lock(a->gate);
	nng_mtx_unlock(a->gate);
	a->ok = true;
	for (int i = 10000; i < 10256; i++) {
		snprintf(expected, sizeof(expected), "Unknown error #%d", i);
		if (strcmp(nng_strerror(i), expected) != 0) {
			a->ok = false;
		}
		snprintf(expected, sizeof(expected), "Transport error #%d", i);
		if (strcmp(nng_strerror(NNG_ETRANERR | i), expected) != 0) {
			a->ok = false;
		}
		// Exercise concurrent cache misses for system messages as
		// well.
		snprintf(expected, sizeof(expected), "%d", 0x0ff00000 + i);
		if (strstr(nng_strerror(NNG_ESYSERR | (0x0ff00000 + i)),
		        expected) == NULL) {
			a->ok = false;
		}
	}
	a->message = nng_strerror(10000);
}

static void
test_concurrent_errors(void)
{
	nng_mtx                *gate;
	nng_thread             *threads[8];
	struct error_thread_arg args[8] = { 0 };
	const char             *saved   = nng_strerror(NNG_ESYSERR | 23456);
	char                    copy[128];

	NUTS_ASSERT(strlen(saved) < sizeof(copy));
	strcpy(copy, saved);
	NUTS_PASS(nng_mtx_alloc(&gate));
	nng_mtx_lock(gate);
	for (int i = 0; i < 8; i++) {
		args[i].gate = gate;
		NUTS_PASS(
		    nng_thread_create(&threads[i], format_errors, &args[i]));
	}
	nng_mtx_unlock(gate);
	for (int i = 0; i < 8; i++) {
		nng_thread_destroy(threads[i]);
		NUTS_TRUE(args[i].ok);
		NUTS_TRUE(args[i].message == nng_strerror(10000));
	}
	NUTS_MATCH(saved, copy);
	nng_mtx_free(gate);
}

static void
test_error_cache_lifecycle(void)
{
	const char *msg;

	nng_fini();
	NUTS_MATCH(nng_strerror(NNG_ENOMEM), "Out of memory");
	NUTS_MATCH(nng_strerror(NNG_ESYSERR | 12345), "System error");
	NUTS_MATCH(nng_strerror(12345), "Unknown error");
	NUTS_PASS(nng_init(NULL));
	msg = nng_strerror(12345);
	NUTS_MATCH(msg, "Unknown error #12345");
	NUTS_PASS(nng_init(NULL));
	nng_fini();
	NUTS_TRUE(msg == nng_strerror(12345));
	nng_fini();
	NUTS_MATCH(nng_strerror(12345), "Unknown error");
	NUTS_PASS(nng_init(NULL));
	NUTS_MATCH(nng_strerror(12345), "Unknown error #12345");
}

static nni_atomic_bool fail_malloc;
static nni_atomic_bool fail_calloc;
static nni_atomic_int  allocations;

static void *
error_malloc(size_t size)
{
	void *ptr;
	if (nni_atomic_get_bool(&fail_malloc)) {
		return (NULL);
	}
	if ((ptr = malloc(size)) != NULL) {
		nni_atomic_inc(&allocations);
	}
	return (ptr);
}

static void *
error_calloc(size_t count, size_t size)
{
	void *ptr;
	if (nni_atomic_get_bool(&fail_calloc)) {
		return (NULL);
	}
	if ((ptr = calloc(count, size)) != NULL) {
		nni_atomic_inc(&allocations);
	}
	return (ptr);
}

static void
error_free(void *ptr, size_t size)
{
	(void) size;
	if (ptr != NULL) {
		nni_atomic_dec(&allocations);
		free(ptr);
	}
}

static void
test_error_cache_allocation_failure(void)
{
	nng_init_params original = {
		.malloc_fn = nni_malloc_fn,
		.calloc_fn = nni_calloc_fn,
		.free_fn   = nni_free_fn,
	};
	nng_init_params params = {
		.malloc_fn = error_malloc,
		.calloc_fn = error_calloc,
		.free_fn   = error_free,
	};
	const char *cached;

	nng_fini();
	nni_atomic_init_bool(&fail_malloc);
	nni_atomic_init_bool(&fail_calloc);
	nni_atomic_init(&allocations);
	NUTS_PASS(nng_init(&params));
	// The message allocation succeeds, but allocating the table fails.
	nni_atomic_set_bool(&fail_calloc, true);
	NUTS_MATCH(nng_strerror(12345), "Unknown error");
	nni_atomic_set_bool(&fail_calloc, false);
	cached = nng_strerror(12345);
	NUTS_MATCH(cached, "Unknown error #12345");
	// A failed insertion must not poison the cache or disturb old entries.
	nni_atomic_set_bool(&fail_malloc, true);
	NUTS_MATCH(nng_strerror(23456), "Unknown error");
	NUTS_MATCH(nng_strerror(NNG_ETRANERR | 23456), "Transport error");
	NUTS_MATCH(nng_strerror(NNG_ESYSERR | 23456), "System error");
	NUTS_MATCH(nng_strerror(NNG_ENOMEM), "Out of memory");
	NUTS_TRUE(cached == nng_strerror(12345));
	nni_atomic_set_bool(&fail_malloc, false);
	NUTS_MATCH(nng_strerror(23456), "Unknown error #23456");
	nng_fini();
	NUTS_TRUE(nni_atomic_get(&allocations) == 0);
	NUTS_PASS(nng_init(&original));
}

NUTS_TESTS = {
	{ "known errors", test_known_errors },
	{ "unknown errors", test_unknown_errors },
	{ "system errors", test_system_errors },
	{ "error message lifetime", test_error_message_lifetime },
	{ "concurrent errors", test_concurrent_errors },
	{ "error cache lifecycle", test_error_cache_lifecycle },
	{ "error cache allocation failure",
	    test_error_cache_allocation_failure },
	{ NULL, NULL },
};
