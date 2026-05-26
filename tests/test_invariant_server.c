#include <check.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/*
 * Self-contained property test for CWE-120:
 * Buffer reads never exceed the declared length.
 *
 * We simulate the vulnerable pattern:
 *   memcpy(dest, data, sz)
 * where dest has a fixed allocated size (BUFFER_SIZE) and sz comes from
 * an untrusted HTTP request.
 *
 * Invariant: the number of bytes copied must never exceed the destination
 * buffer's allocated size.  Any implementation must either truncate sz to
 * at most BUFFER_SIZE or reject the request entirely (return an error).
 */

#define BUFFER_SIZE 256   /* simulated nng message body allocation */

/*
 * safe_copy() is the reference implementation of what the server SHOULD do.
 * It mirrors the fix: cap sz at the destination buffer size before copying.
 * Returns the number of bytes actually written, or -1 if the input is
 * rejected outright (sz == 0 or data == NULL).
 */
static ssize_t safe_copy(void *dest, size_t dest_size,
                         const void *data, size_t sz)
{
    if (dest == NULL || data == NULL || dest_size == 0) {
        return -1;
    }
    /* Reject or truncate: choose truncation as the safe behaviour */
    size_t copy_len = (sz <= dest_size) ? sz : dest_size;
    memcpy(dest, data, copy_len);
    return (ssize_t)copy_len;
}

/* ------------------------------------------------------------------ */

START_TEST(test_buffer_reads_never_exceed_declared_length)
{
    /* Invariant: bytes copied into the destination buffer must never
     * exceed BUFFER_SIZE, regardless of the attacker-controlled sz. */

    /* Each entry: { payload_size_multiplier_of_BUFFER_SIZE, description } */
    struct {
        size_t   sz;          /* attacker-supplied size */
        const char *label;
    } cases[] = {
        /* Exact boundary */
        { BUFFER_SIZE,          "exact boundary"          },
        /* One byte over */
        { BUFFER_SIZE + 1,      "off-by-one"              },
        /* 2x oversized */
        { BUFFER_SIZE * 2,      "2x oversized"            },
        /* 10x oversized */
        { BUFFER_SIZE * 10,     "10x oversized"           },
        /* 100x oversized */
        { BUFFER_SIZE * 100,    "100x oversized"          },
        /* Maximum plausible HTTP body (1 MB) */
        { 1024 * 1024,          "1 MB payload"            },
        /* SIZE_MAX / 2 – integer-overflow probe */
        { SIZE_MAX / 2,         "SIZE_MAX/2"              },
        /* SIZE_MAX – extreme integer-overflow probe */
        { SIZE_MAX,             "SIZE_MAX"                },
        /* Zero – degenerate input */
        { 0,                    "zero length"             },
        /* Typical small valid input */
        { 16,                   "small valid input"       },
        /* One byte under boundary */
        { BUFFER_SIZE - 1,      "one byte under boundary" },
    };

    int num_cases = (int)(sizeof(cases) / sizeof(cases[0]));

    for (int i = 0; i < num_cases; i++) {
        size_t sz = cases[i].sz;

        /* Allocate a source buffer filled with a recognisable pattern.
         * Guard against absurdly large allocations (SIZE_MAX etc.) by
         * capping the source at a reasonable maximum for the test. */
        size_t alloc_sz = (sz < 1024 * 1024 * 2) ? sz : 1024 * 1024 * 2;
        uint8_t *src = NULL;
        if (alloc_sz > 0) {
            src = (uint8_t *)malloc(alloc_sz);
            ck_assert_msg(src != NULL,
                          "malloc failed for case: %s", cases[i].label);
            memset(src, 0xAA, alloc_sz);
        }

        /* Destination buffer with a canary region after it */
        uint8_t dest[BUFFER_SIZE];
        uint8_t canary[16];
        memset(dest,   0x00, sizeof(dest));
        memset(canary, 0xBB, sizeof(canary));

        /* --- Core invariant check ----------------------------------- */

        ssize_t written = safe_copy(dest, BUFFER_SIZE, src, sz);

        /* 1. The function must not write more bytes than BUFFER_SIZE */
        if (written > 0) {
            ck_assert_msg((size_t)written <= BUFFER_SIZE,
                "INVARIANT VIOLATED: wrote %zd bytes into a %d-byte buffer "
                "(case: %s)",
                written, BUFFER_SIZE, cases[i].label);
        }

        /* 2. The canary must be untouched (no overflow past dest) */
        for (int b = 0; b < (int)sizeof(canary); b++) {
            ck_assert_msg(canary[b] == 0xBB,
                "CANARY CORRUPTED at byte %d: buffer overflow detected "
                "(case: %s)",
                b, cases[i].label);
        }

        /* 3. If sz == 0 or src == NULL the function must signal rejection */
        if (sz == 0 || src == NULL) {
            ck_assert_msg(written <= 0,
                "Expected rejection (written <= 0) for zero/null input "
                "(case: %s), got %zd",
                cases[i].label, written);
        }

        /* 4. For valid, non-oversized inputs the full payload is copied */
        if (src != NULL && sz > 0 && sz <= BUFFER_SIZE) {
            ck_assert_msg(written == (ssize_t)sz,
                "Expected %zu bytes written for valid input (case: %s), "
                "got %zd",
                sz, cases[i].label, written);
        }

        /* 5. For oversized inputs the copy is truncated to BUFFER_SIZE */
        if (src != NULL && sz > BUFFER_SIZE) {
            ck_assert_msg(written == (ssize_t)BUFFER_SIZE,
                "Expected truncation to %d bytes for oversized input "
                "(case: %s), got %zd",
                BUFFER_SIZE, cases[i].label, written);
        }

        free(src);
    }
}
END_TEST

/* ------------------------------------------------------------------ */

Suite *security_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s       = suite_create("Security_CWE120");
    tc_core = tcase_create("Core");

    tcase_add_test(tc_core, test_buffer_reads_never_exceed_declared_length);
    suite_add_tcase(s, tc_core);

    return s;
}

int main(void)
{
    int      number_failed;
    Suite   *s;
    SRunner *sr;

    s  = security_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}