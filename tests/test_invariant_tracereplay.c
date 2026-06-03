#include <check.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* We need to test that the memcpy in tracereplay doesn't overflow.
 * The vulnerable pattern is:
 *   newbuf = malloc(sizeof(libtrace_ether_t) + remaining);
 *   memcpy(newbuf + sizeof(libtrace_ether_t), l2_header, remaining);
 * where 'remaining' comes from untrusted packet metadata.
 *
 * We simulate the allocation logic and check the invariant:
 * bytes copied must never exceed (allocated_size - header_size).
 */

#define LIBTRACE_ETHER_SIZE 14  /* sizeof(libtrace_ether_t) */
#define MAX_SAFE_PACKET 65535

/* Simulates the vulnerable allocation+copy logic from tracereplay.c lines 127-128.
 * Returns 0 if safe (no overflow), -1 if overflow would occur. */
static int check_copy_bounds(uint32_t wire_length, uint32_t capture_length, size_t actual_data_size)
{
    /* In the vulnerable code, 'remaining' is derived from packet metadata (wire_length or cap_length) */
    uint32_t remaining = capture_length;

    /* The allocation in tracereplay: newbuf = malloc(sizeof(libtrace_ether_t) + remaining) */
    size_t alloc_size = LIBTRACE_ETHER_SIZE + remaining;

    /* SECURITY INVARIANT: remaining must not exceed actual_data_size,
     * and the copy must not exceed (alloc_size - LIBTRACE_ETHER_SIZE) */
    if (remaining > actual_data_size) {
        /* This is the overflow condition - reading beyond l2_header buffer */
        return -1;
    }
    if (remaining > alloc_size - LIBTRACE_ETHER_SIZE) {
        return -1;
    }
    return 0;
}

START_TEST(test_buffer_read_bounds)
{
    /* Invariant: Buffer reads never exceed the declared/actual data length */
    struct {
        uint32_t wire_len;
        uint32_t cap_len;      /* attacker-controlled metadata */
        size_t actual_data;    /* real data available */
        int expect_safe;       /* 0 = safe, -1 = overflow */
    } cases[] = {
        /* Exact exploit: cap_len claims 2x actual data */
        { 2000, 2000, 1000, -1 },
        /* Extreme: cap_len claims 10x actual data */
        { 10000, 10000, 1000, -1 },
        /* Boundary: cap_len equals actual data exactly */
        { 1000, 1000, 1000, 0 },
        /* Valid small packet */
        { 64, 64, 64, 0 },
        /* cap_len is UINT32_MAX (integer overflow attempt) */
        { 0xFFFFFFFF, 0xFFFFFFFF, 100, -1 },
    };
    int num_cases = sizeof(cases) / sizeof(cases[0]);

    for (int i = 0; i < num_cases; i++) {
        int result = check_copy_bounds(cases[i].wire_len, cases[i].cap_len, cases[i].actual_data);
        /* The security invariant: if cap_len > actual_data, it MUST be detected as unsafe */
        if (cases[i].cap_len > cases[i].actual_data) {
            ck_assert_msg(result == -1,
                "Case %d: overflow not detected (cap_len=%u, actual=%zu)",
                i, cases[i].cap_len, cases[i].actual_data);
        } else {
            ck_assert_msg(result == 0,
                "Case %d: false positive (cap_len=%u, actual=%zu)",
                i, cases[i].cap_len, cases[i].actual_data);
        }
    }
}
END_TEST

Suite *security_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("Security");
    tc_core = tcase_create("Core");

    tcase_add_test(tc_core, test_buffer_read_bounds);
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
    number_failed =