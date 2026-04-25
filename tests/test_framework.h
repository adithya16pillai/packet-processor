/* Single-header micro test framework. */
#ifndef TEST_FRAMEWORK_H
#define TEST_FRAMEWORK_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int tf_total    = 0;
static int tf_failed   = 0;
static const char *tf_current = "";

#define TEST(name)  static void tf_##name(void)

#define RUN(name) do {                                                          \
    tf_total++;                                                                 \
    tf_current = #name;                                                         \
    int before_failures = tf_failed;                                            \
    tf_##name();                                                                \
    if (tf_failed == before_failures) {                                         \
        printf("  [PASS] %s\n", #name);                                         \
    }                                                                           \
} while (0)

#define FAIL_MSG(fmt, ...) do {                                                 \
    printf("  [FAIL] %s @ %s:%d - " fmt "\n",                                   \
           tf_current, __FILE__, __LINE__, ##__VA_ARGS__);                      \
    tf_failed++;                                                                \
    return;                                                                     \
} while (0)

#define ASSERT(cond) do {                                                       \
    if (!(cond)) FAIL_MSG("assertion failed: %s", #cond);                       \
} while (0)

#define ASSERT_EQ_INT(a, b) do {                                                \
    long long _a = (long long)(a), _b = (long long)(b);                         \
    if (_a != _b) FAIL_MSG("expected %lld, got %lld (%s vs %s)",                \
                            _b, _a, #a, #b);                                    \
} while (0)

#define ASSERT_EQ_U32(a, b) do {                                                \
    unsigned long _a = (unsigned long)(a), _b = (unsigned long)(b);             \
    if (_a != _b) FAIL_MSG("expected 0x%lx, got 0x%lx", _b, _a);                \
} while (0)

#define ASSERT_EQ_STR(a, b) do {                                                \
    const char *_a = (a), *_b = (b);                                            \
    if (strcmp(_a, _b) != 0)                                                    \
        FAIL_MSG("expected \"%s\", got \"%s\"", _b, _a);                        \
} while (0)

static inline int test_finish(void) {
    printf("\nResult: %d/%d passed\n", tf_total - tf_failed, tf_total);
    return tf_failed == 0 ? 0 : 1;
}

#endif
