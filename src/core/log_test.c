//
// Copyright 2024 Staysail Systems, Inc. <info@staysail.tech>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <stdio.h>
#include <string.h>

#include "nuts.h"
#include <nng/nng.h>

#ifdef NNG_PLATFORM_POSIX
#include <stdlib.h>
#endif

void
test_log_stderr(void)
{
	nng_log_set_logger(nng_stderr_logger);
	nng_log_set_level(NNG_LOG_DEBUG);
	nng_log_info(NULL, "something wicked");
	nng_log_err(NULL, "This is an error message");
	nng_log_warn(NULL, "This is a warning message");
	nng_log_notice(NULL, "This is a notice message");
	nng_log_info(NULL, "This is an info message");
	nng_log_debug(NULL, "This is a debug message");
	nng_log_notice("TESTMSG", "This notice has a msg id");
#ifdef NNG_PLATFORM_POSIX
	setenv("NO_COLOR", "", 1);
	nng_log_err("MONO", "Uncolored messages");
	unsetenv("NO_COLOR");
	setenv("NNG_LOG_NO_COLOR", "", 1);
	nng_log_err("MONO", "Also uncolored messages");
#endif
	// these are intentionally unreasonably large
	nng_log_set_level((nng_log_level) 100);
	nng_log_auth(99, "WTF", "This should be NONE");
}

typedef struct test_log_entry {
	nng_log_level    level;
	nng_log_facility facility;
	const char      *msgid;
	char             msg[128];
} test_log_entry;

typedef struct {
	test_log_entry entries[16];
	int            count;
} test_logs;

void
custom_logger_base(test_logs *logs, nng_log_level level,
    nng_log_facility facility, const char *msgid, const char *msg)
{
	test_log_entry *entry;

	if (logs->count >= 16) {
		return;
	}
	entry           = &logs->entries[logs->count++];
	entry->level    = level;
	entry->facility = facility;
	entry->msgid    = msgid; // ok for constant strings
	snprintf(entry->msg, sizeof(entry->msg), "%s", msg);
}

static test_logs test_logs_priority;
void
test_log_priority_logger(nng_log_level level, nng_log_facility facility,
    const char *msgid, const char *msg)
{
	custom_logger_base(&test_logs_priority, level, facility, msgid, msg);
}

void
test_log_priority(void)
{
	nng_log_set_logger(test_log_priority_logger);
	nng_log_set_level(NNG_LOG_WARN);
	nng_log_debug(NULL, "This should be filtered");
	nng_log_err("ERR", "This gets through");
	nng_log_notice("NOT", "This gets filtered");
	nng_log_warn("WRN", "This makes it");
	nng_log_info("INF", "Filtered!");
	nng_log_err("ERR", "Another error message");
	nng_log_auth(NNG_LOG_ERR, "AUTH", "authentication err sample message");
	nng_log_set_level(NNG_LOG_NONE);
	nng_log_err("ERR", "Yet Another error message - filtered");
	NUTS_ASSERT(test_logs_priority.count == 4);
	NUTS_ASSERT(strcmp(test_logs_priority.entries[0].msgid, "ERR") == 0);
	NUTS_ASSERT(test_logs_priority.entries[0].level == NNG_LOG_ERR);
	NUTS_ASSERT(strcmp(test_logs_priority.entries[1].msgid, "WRN") == 0);
	NUTS_ASSERT(test_logs_priority.entries[1].level == NNG_LOG_WARN);
	NUTS_ASSERT(strcmp(test_logs_priority.entries[2].msgid, "ERR") == 0);
	NUTS_ASSERT(test_logs_priority.entries[2].level == NNG_LOG_ERR);
	NUTS_ASSERT(strcmp(test_logs_priority.entries[3].msgid, "AUTH") == 0);
	NUTS_ASSERT(test_logs_priority.entries[3].level == NNG_LOG_ERR);
	NUTS_ASSERT(test_logs_priority.entries[3].facility == NNG_LOG_AUTH);
}

static test_logs test_logs_facility;
void
test_log_facility_logger(nng_log_level level, nng_log_facility facility,
    const char *msgid, const char *msg)
{
	custom_logger_base(&test_logs_facility, level, facility, msgid, msg);
}

void
test_log_facility(void)
{
	nng_log_set_logger(test_log_facility_logger);
	nng_log_set_facility(NNG_LOG_LOCAL2);
	nng_log_set_level(NNG_LOG_WARN);
	nng_log_debug(NULL, "This should be filtered");
	nng_log_err("001", "This is local2");
	nng_log_set_facility(NNG_LOG_DAEMON);
	nng_log_warn("002", "This is Daemon");

	NUTS_ASSERT(test_logs_facility.count == 2);
	NUTS_ASSERT(strcmp(test_logs_facility.entries[0].msgid, "001") == 0);
	NUTS_ASSERT(test_logs_facility.entries[0].level == NNG_LOG_ERR);
	NUTS_ASSERT(test_logs_facility.entries[0].facility == NNG_LOG_LOCAL2);
	NUTS_ASSERT(strcmp(test_logs_facility.entries[1].msgid, "002") == 0);
	NUTS_ASSERT(test_logs_facility.entries[1].facility == NNG_LOG_DAEMON);
	NUTS_ASSERT(test_logs_facility.entries[1].level == NNG_LOG_WARN);
}

void
test_log_null_logger(void)
{
	nng_log_set_logger(nng_null_logger);
	nng_log_set_level(NNG_LOG_DEBUG);
	nng_log_debug(NULL, "This should be dropped");
	nng_log_err("001", "This is local2");
	nng_log_warn("002", "This is also dropped");

	// Lets also try setting it to NULL
	nng_log_set_logger(nng_null_logger);
	nng_log_warn("003", "This is also dropped");
}

void
test_log_system_logger(void)
{
	nng_log_set_logger(nng_system_logger);
	nng_log_set_level(NNG_LOG_DEBUG);
	nng_log_debug(NULL, "This is a test message, ignore me");
	nng_log_set_facility(NNG_LOG_DAEMON);
	nng_log_debug(NULL, "This is a test message (DAEMON), ignore me");
	nng_log_set_facility(NNG_LOG_LOCAL0);
	nng_log_debug(NULL, "This is a test message (LOCAL0), ignore me");
	nng_log_set_facility(NNG_LOG_LOCAL1);
	nng_log_debug(NULL, "This is a test message (LOCAL1), ignore me");
	nng_log_set_facility(NNG_LOG_LOCAL2);
	nng_log_debug(NULL, "This is a test message (LOCAL2), ignore me");
	nng_log_set_facility(NNG_LOG_LOCAL3);
	nng_log_debug(NULL, "This is a test message (LOCAL3), ignore me");
	nng_log_set_facility(NNG_LOG_LOCAL4);
	nng_log_debug(NULL, "This is a test message (LOCAL4), ignore me");
	nng_log_set_facility(NNG_LOG_LOCAL5);
	nng_log_debug(NULL, "This is a test message (LOCAL5), ignore me");
	nng_log_set_facility(NNG_LOG_LOCAL6);
	nng_log_debug(NULL, "This is a test message (LOCAL6), ignore me");
	nng_log_set_facility(NNG_LOG_LOCAL7);
	nng_log_debug(NULL, "This is a test message (LOCAL7), ignore me");

	nng_log_set_facility(NNG_LOG_USER);
	nng_log_debug(NULL, "This is a test message (LOCAL7), ignore me");
	nng_log_err("TEST", "This is only a test (ERR). Ignore me.");
	nng_log_warn("TEST", "This is only a test (WARN). Ignore me.");
	nng_log_notice("TEST", "This is only a test (NOTICE). Ignore me.");
	nng_log_info("TEST", "This is only a test (INFO). Ignore me.");
}

TEST_LIST = {
	{ "log stderr", test_log_stderr },
	{ "log priority", test_log_priority },
	{ "log facility", test_log_facility },
	{ "log null logger", test_log_null_logger },
	{ "log system logger", test_log_system_logger },
	{ NULL, NULL },
};
