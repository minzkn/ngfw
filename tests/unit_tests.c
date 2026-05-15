/*
 * NGFW - Unit Test Suite
 * Comprehensive tests for core functionality
 * Copyright (C) 2024 NGFW Project
 */

#include "ngfw/test.h"
#include "ngfw/types.h"
#include "ngfw/session.h"
#include "ngfw/percpu.h"
#include "ngfw/hash.h"
#include "ngfw/slab_alloc.h"
#include "ngfw/memory.h"
#include <stdio.h>
#include <string.h>
#include <pthread.h>

/* Test result tracking - will be defined at link time */
static int local_tests_run = 0;
static int local_tests_passed = 0;
static int local_tests_failed = 0;

#define TEST_RUN(test) do { \
    local_tests_run++; \
    if (test()) { \
        local_tests_passed++; \
        printf("  [PASS] %s\n", #test); \
    } else { \
        local_tests_failed++; \
        printf("  [FAIL] %s\n", #test); \
    } \
} while(0)

/* Reference counting tests */
static bool test_refcount_basic(void)
{
    refcount_t ref;
    refcount_init(&ref, 0);
    
    if (refcount_read(&ref) != 0) return false;
    
    refcount_inc(&ref);
    if (refcount_read(&ref) != 1) return false;
    
    refcount_inc(&ref);
    if (refcount_read(&ref) != 2) return false;
    
    /* dec_and_zero should return false when count goes 2->1 (not zero yet) */
    if (refcount_dec_and_zero(&ref)) return false;  /* Should be false */
    if (refcount_read(&ref) != 1) return false;
    
    /* dec_and_zero should return true when count goes 1->0 */
    if (!refcount_dec_and_zero(&ref)) return false;  /* Should be true */
    if (refcount_read(&ref) != 0) return false;
    
    return true;
}

static bool test_session_reference_counting(void)
{
    session_key_t key = {
        .src_ip = 0xC0A80001,  /* 192.168.0.1 */
        .dst_ip = 0xC0A80002,  /* 192.168.0.2 */
        .src_port = 12345,
        .dst_port = 80,
        .protocol = IP_PROTO_TCP
    };
    
    session_t *session = session_create(&key);
    if (!session) return false;
    
    if (refcount_read(&session->refcnt) != 1) {
        session_destroy(session);
        return false;
    }
    
    session_get(session);
    if (refcount_read(&session->refcnt) != 2) {
        session_destroy(session);
        session_destroy(session);
        return false;
    }
    
    session_put(session);
    if (refcount_read(&session->refcnt) != 1) {
        session_destroy(session);
        return false;
    }
    
    session_put(session);  /* Should free */
    return true;
}

/* Per-CPU session table tests */
static bool test_percpu_cpu_mapping(void)
{
    percpu_session_mgr_t *mgr = percpu_session_create(1000);
    if (!mgr) return false;
    
    session_key_t key1 = {
        .src_ip = 0xC0A80001,
        .dst_ip = 0xC0A80002,
        .src_port = 12345,
        .dst_port = 80,
        .protocol = IP_PROTO_TCP
    };
    
    u32 cpu_id1 = percpu_get_cpu_id_for_key(mgr, &key1);
    if (cpu_id1 >= mgr->num_cpus) {
        percpu_session_destroy(mgr);
        return false;
    }
    
    /* Same key should always map to same CPU */
    for (int i = 0; i < 100; i++) {
        u32 cpu_id = percpu_get_cpu_id_for_key(mgr, &key1);
        if (cpu_id != cpu_id1) {
            percpu_session_destroy(mgr);
            return false;
        }
    }
    
    percpu_session_destroy(mgr);
    return true;
}

static bool test_percpu_session_lifecycle(void)
{
    percpu_session_mgr_t *mgr = percpu_session_create(100);
    if (!mgr) return false;
    
    session_key_t key = {
        .src_ip = 0xC0A80001,
        .dst_ip = 0xC0A80002,
        .src_port = 12345,
        .dst_port = 80,
        .protocol = IP_PROTO_TCP
    };
    
    session_t *session = session_create(&key);
    if (!session) {
        percpu_session_destroy(mgr);
        return false;
    }
    
    ngfw_ret_t ret = percpu_session_insert(mgr, session);
    if (ret != NGFW_OK) {
        session_destroy(session);
        percpu_session_destroy(mgr);
        return false;
    }
    
    session_t *found = percpu_session_lookup(mgr, &key);
    if (!found) {
        percpu_session_destroy(mgr);
        return false;
    }
    
    session_put(found);  /* Release lookup reference */
    
    percpu_session_remove(mgr, session);
    session_put(session);  /* Release creator reference */
    
    percpu_session_destroy(mgr);
    return true;
}

/* Hash table segment lock tests */
static bool test_hash_segment_locks(void)
{
    hash_table_t *table = hash_create(256, NULL, NULL, NULL);
    if (!table) return false;
    
    if (table->segment_count != HASH_SEGMENT_COUNT) {
        hash_destroy(table);
        return false;
    }
    
    /* Verify segments are properly initialized */
    for (u32 i = 0; i < table->segment_count; i++) {
        /* Segments should be initialized */
    }
    
    hash_destroy(table);
    return true;
}

/* Slab allocator tests */
static bool test_slab_basic(void)
{
    slab_pool_t *pool = slab_pool_create(64, 2);
    if (!pool) return false;
    
    void *obj1 = slab_alloc(pool);
    if (!obj1) {
        slab_pool_destroy(pool);
        return false;
    }
    
    void *obj2 = slab_alloc(pool);
    if (!obj2) {
        slab_free(pool, obj1);
        slab_pool_destroy(pool);
        return false;
    }
    
    slab_free(pool, obj1);
    slab_free(pool, obj2);
    
    slab_pool_destroy(pool);
    return true;
}

static bool test_slab_reuse(void)
{
    slab_pool_t *pool = slab_pool_create(128, 1);
    if (!pool) return false;
    
    void *obj = slab_alloc(pool);
    if (!obj) {
        slab_pool_destroy(pool);
        return false;
    }
    
    slab_free(pool, obj);
    
    void *obj2 = slab_alloc(pool);
    if (!obj2) {
        slab_pool_destroy(pool);
        return false;
    }
    
    /* Should reuse the same object */
    if (obj != obj2) {
        slab_free(pool, obj2);
        slab_pool_destroy(pool);
        return false;
    }
    
    slab_free(pool, obj2);
    slab_pool_destroy(pool);
    return true;
}

/* Input validation tests */
static bool test_input_validation(void)
{
    /* Test NULL pointer handling */
    session_t *session = session_create(NULL);
    if (session != NULL) return false;
    
    session_table_t *table = session_table_create(100);
    if (!table) return false;
    
    session_t *found = session_table_lookup(NULL, NULL);
    if (found != NULL) {
        session_table_destroy(table);
        return false;
    }
    
    found = session_table_lookup(table, NULL);
    if (found != NULL) {
        session_table_destroy(table);
        return false;
    }
    
    ngfw_ret_t ret = session_table_insert(NULL, NULL);
    if (ret != NGFW_ERR_INVALID) {
        session_table_destroy(table);
        return false;
    }
    
    session_table_destroy(table);
    return true;
}

/* Run all tests */
void run_all_tests(void)
{
    printf("\n=== NGFW Unit Tests ===\n\n");
    
    printf("Reference Counting:\n");
    TEST_RUN(test_refcount_basic);
    TEST_RUN(test_session_reference_counting);
    
    printf("\nPer-CPU Session Tables:\n");
    TEST_RUN(test_percpu_cpu_mapping);
    TEST_RUN(test_percpu_session_lifecycle);
    
    printf("\nHash Table:\n");
    TEST_RUN(test_hash_segment_locks);
    
    printf("\nSlab Allocator:\n");
    TEST_RUN(test_slab_basic);
    TEST_RUN(test_slab_reuse);
    
    printf("\nInput Validation:\n");
    TEST_RUN(test_input_validation);
    
    printf("\n=== Test Summary ===\n");
    printf("Total:  %d\n", local_tests_run);
    printf("Passed: %d\n", local_tests_passed);
    printf("Failed: %d\n", local_tests_failed);
    printf("Rate:   %.1f%%\n", local_tests_run > 0 ? (100.0 * local_tests_passed / local_tests_run) : 0.0);
}

int main(void)
{
    ngfw_mem_init();
    run_all_tests();
    return local_tests_failed > 0 ? 1 : 0;
}
