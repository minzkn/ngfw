#ifndef NGFW_TEST_H
#define NGFW_TEST_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define TEST_ASSERT(condition, message) \
    do { \
        if (!(condition)) { \
            printf("FAIL: %s (%s:%d)\n", message, __FILE__, __LINE__); \
            return 1; \
        } \
    } while(0)

#define TEST_ASSERT_EQUAL(expected, actual) \
    do { \
        if ((expected) != (actual)) { \
            printf("FAIL: Expected %ld, got %ld (%s:%d)\n", \
                   (long)(expected), (long)(actual), __FILE__, __LINE__); \
            return 1; \
        } \
    } while(0)

#define TEST_ASSERT_NULL(ptr) \
    do { \
        if ((ptr) != NULL) { \
            printf("FAIL: Expected NULL (%s:%d)\n", __FILE__, __LINE__); \
            return 1; \
        } \
    } while(0)

#define TEST_ASSERT_NOT_NULL(ptr) \
    do { \
        if ((ptr) == NULL) { \
            printf("FAIL: Expected non-NULL (%s:%d)\n", __FILE__, __LINE__); \
            return 1; \
        } \
    } while(0)

#define TEST_ASSERT_STR_EQUAL(expected, actual) \
    do { \
        if (strcmp((expected), (actual)) != 0) { \
            printf("FAIL: Expected '%s', got '%s' (%s:%d)\n", \
                   (expected), (actual), __FILE__, __LINE__); \
            return 1; \
        } \
    } while(0)

#define TEST_ASSERT_TRUE(condition) TEST_ASSERT(condition, "Expected true")
#define TEST_ASSERT_FALSE(condition) TEST_ASSERT(!(condition), "Expected false")

#define TEST_SUITE(name) \
    static int suite_##name##_run(void)

#define TEST_CASE(name) \
    static int test_##name##_run(void)

#define RUN_SUITE(name) \
    do { \
        printf("Running suite: %s\n", #name); \
        int result = suite_##name##_run(); \
        if (result == 0) { \
            printf("PASS: %s\n\n", #name); \
            suites_passed++; \
        } else { \
            printf("FAIL: %s (%d tests failed)\n\n", #name, result); \
            suites_failed++; \
        } \
        total_tests++; \
    } while(0)

#define RUN_TEST(name) \
    do { \
        printf("  Running test: %s\n", #name); \
        int result = test_##name##_run(); \
        if (result == 0) { \
            printf("    PASS\n"); \
            tests_passed++; \
        } else { \
            printf("    FAIL\n"); \
            tests_failed++; \
        } \
        total_tests++; \
    } while(0)

extern int suites_passed;
extern int suites_failed;
extern int tests_passed;
extern int tests_failed;
extern int total_tests;

void test_summary(void);

#endif
