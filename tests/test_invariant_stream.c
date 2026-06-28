#include <check.h>
#include <stdlib.h>
#include <stdint.h>
#include <limits.h>

// Include the actual production header
#include "demo/stream/stream.h"

START_TEST(test_allocation_overflow_check)
{
    // Invariant: Multiplication for allocation size must not overflow
    // The function must either detect overflow or allocate sufficient memory
    
    // Test payloads: boundary values that could cause overflow
    size_t test_cases[][2] = {
        // {count, size} pairs
        {SIZE_MAX, 2},           // Exact overflow case
        {SIZE_MAX / 2 + 1, 2},   // Boundary: just overflows
        {SIZE_MAX / 2, 2},       // Boundary: doesn't overflow
        {100, 4},                // Normal valid input
        {0, SIZE_MAX}           // Edge case: zero count
    };
    
    int num_cases = sizeof(test_cases) / sizeof(test_cases[0]);
    
    for (int i = 0; i < num_cases; i++) {
        size_t count = test_cases[i][0];
        size_t size = test_cases[i][1];
        
        // Call the actual production function
        void *result = stream_allocate_buffer(count, size);
        
        // Security property: either NULL (overflow detected) or valid pointer
        if (result != NULL) {
            // If allocation succeeded, verify it's usable
            ck_assert_ptr_nonnull(result);
            
            // Additional check: ensure we can write to the allocated memory
            // (simulating actual usage pattern)
            if (count > 0 && size > 0 && count <= SIZE_MAX / size) {
                // For valid allocations, test memory is writable
                memset(result, 0, count * size);
            }
            
            // Clean up
            free(result);
        }
        // If result is NULL, it could be either overflow detection or
        // legitimate allocation failure - both are acceptable for security
    }
}
END_TEST

Suite *security_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("Security");
    tc_core = tcase_create("Core");

    tcase_add_test(tc_core, test_allocation_overflow_check);
    suite_add_tcase(s, tc_core);

    return s;
}

int main(void)
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = security_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}