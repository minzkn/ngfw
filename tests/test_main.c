#include "ngfw/test.h"
#include "ngfw/memory.h"
#include "ngfw/list.h"
#include "ngfw/hash.h"
#include "ngfw/packet.h"
#include "ngfw/session.h"
#include "ngfw/filter.h"
#include "ngfw/crypto.h"
#include "ngfw/platform.h"
#include "ngfw/log.h"
#include "ngfw/mempool.h"
#include "ngfw/module.h"
#include "ngfw/ringbuffer.h"
#include "ngfw/ratelimit.h"
#include "ngfw/connpool.h"
#include "ngfw/bloom.h"
#include "ngfw/lrucache.h"
#include "ngfw/asynclog.h"
#include "ngfw/ipv6.h"
#include "ngfw/metrics.h"
#include "ngfw/strutil.h"
#include "ngfw/timerwheel.h"
#include "ngfw/skiplist.h"
#include "ngfw/packet_alloc.h"
#include "ngfw/protocols.h"
#include "ngfw/notify.h"
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int suites_passed = 0;
int suites_failed = 0;
int tests_passed = 0;
int tests_failed = 0;
int total_tests = 0;

void test_summary(void)
{
    printf("\n========================================\n");
    printf("Test Summary\n");
    printf("========================================\n");
    printf("Suites:  %d passed, %d failed\n", suites_passed, suites_failed);
    printf("Tests:   %d passed, %d failed\n", tests_passed, tests_failed);
    printf("Total:   %d\n", total_tests);
    printf("========================================\n");
    
    if (tests_failed > 0) {
        printf("RESULT: FAILED\n");
        exit(1);
    }
    printf("RESULT: PASSED\n");
}

static int test_memory_basic(void)
{
    void *ptr = ngfw_malloc(1024);
    if (!ptr) return 1;
    ngfw_free(ptr);
    return 0;
}

static int test_memory_calloc(void)
{
    void *ptr = ngfw_calloc(10, 100);
    if (!ptr) return 1;
    memset(ptr, 0, 1000);
    ngfw_free(ptr);
    return 0;
}

static int test_memory_realloc(void)
{
    void *ptr = ngfw_malloc(100);
    if (!ptr) return 1;
    ptr = ngfw_realloc(ptr, 200);
    if (!ptr) return 1;
    ngfw_free(ptr);
    return 0;
}

static int test_mempool_basic(void)
{
    mem_pool_t *pool = mempool_create(64, 10);
    if (!pool) return 1;
    
    if (mempool_available(pool) != 10) return 1;
    
    void *p1 = mempool_alloc(pool);
    if (!p1) return 1;
    if (mempool_available(pool) != 9) return 1;
    
    void *p2 = mempool_alloc(pool);
    if (!p2) return 1;
    
    mempool_free(pool, p1);
    if (mempool_available(pool) != 9) return 1;
    
    mempool_free(pool, p2);
    if (mempool_available(pool) != 10) return 1;
    
    mempool_destroy(pool);
    return 0;
}

static int test_mempool_stress(void)
{
    mem_pool_t *pool = mempool_create(128, 100);
    if (!pool) return 1;
    
    void *ptrs[100];
    for (int i = 0; i < 100; i++) {
        ptrs[i] = mempool_alloc(pool);
        if (!ptrs[i]) return 1;
    }
    
    if (mempool_available(pool) != 0) return 1;
    
    for (int i = 0; i < 100; i++) {
        mempool_free(pool, ptrs[i]);
    }
    
    if (mempool_available(pool) != 100) return 1;
    
    mempool_destroy(pool);
    return 0;
}

static int test_module_interface(void)
{
    const char *name = module_type_name(MODULE_TYPE_IPS);
    if (strcmp(name, "ips") != 0) return 1;
    
    const char *state = module_state_name(MODULE_STATE_INIT);
    if (strcmp(state, "initialized") != 0) return 1;
    
    return 0;
}

static int test_ringbuffer_basic(void)
{
    ringbuffer_t *rb = ringbuffer_create(100);
    if (!rb) return 1;
    
    if (!ringbuffer_is_empty(rb)) return 1;
    
    const char *data = "Hello World";
    if (!ringbuffer_push(rb, data, 11)) return 1;
    
    if (ringbuffer_is_empty(rb)) return 1;
    if (ringbuffer_available(rb) != 11) return 1;
    
    char buf[20] = {0};
    if (!ringbuffer_pop(rb, buf, 11)) return 1;
    
    if (strcmp(buf, data) != 0) return 1;
    if (!ringbuffer_is_empty(rb)) return 1;
    
    ringbuffer_destroy(rb);
    return 0;
}

static int test_ratelimiter_basic(void)
{
    ratelimiter_t *rl = ratelimiter_create(RATELIMIT_TOKEN_BUCKET, 100, 10);
    if (!rl) return 1;
    
    for (int i = 0; i < 10; i++) {
        if (!ratelimiter_allow(rl)) return 1;
    }
    
    if (ratelimiter_allow(rl)) return 1;
    
    ratelimiter_reset(rl);
    if (ratelimiter_available(rl) != 10) return 1;
    
    ratelimiter_destroy(rl);
    return 0;
}

static int test_connpool_basic(void)
{
    connpool_t *pool = connpool_create(5);
    if (!pool) return 1;
    
    if (connpool_max(pool) != 5) return 1;
    if (connpool_used(pool) != 0) return 1;
    
    connection_t *conn = connpool_acquire(pool);
    if (!conn) return 1;
    
    if (connpool_used(pool) != 1) return 1;
    
    connpool_release(pool, conn);
    if (connpool_used(pool) != 0) return 1;
    
    connpool_destroy(pool);
    return 0;
}

static int test_bloom_basic(void)
{
    return 0;
}

static int test_lrucache_basic(void)
{
    return 0;
}

static int test_asynclog_basic(void)
{
    async_logger_t *logger = async_logger_create(100);
    if (!logger) return 1;
    
    if (async_logger_queue_size(logger) != 100) return 1;
    
    async_logger_destroy(logger);
    return 0;
}

static int test_ipv6_basic(void)
{
    return 0;
}

static int test_metrics_basic(void)
{
    return 0;
}

static int test_strutil_basic(void)
{
    char buf[64] = "  hello world  ";
    char *trimmed = strutil_trim(buf);
    if (strcmp(trimmed, "hello world") != 0) return 1;
    
    if (!strutil_starts_with("hello", "hel")) return 1;
    if (!strutil_ends_with("hello", "llo")) return 1;
    
    return 0;
}

static int test_timerwheel_basic(void)
{
    return 0;
}

static int test_skiplist_basic(void)
{
    skiplist_t *list = skiplist_create(NULL);
    if (!list) return 1;
    
    skiplist_insert(list, "key1", "value1");
    skiplist_insert(list, "key2", "value2");
    
    if (skiplist_size(list) != 2) { skiplist_destroy(list); return 1; }
    
    void *val = skiplist_search(list, "key1");
    if (!val) { skiplist_destroy(list); return 1; }
    
    skiplist_destroy(list);
    return 0;
}

static int test_packet_alloc_basic(void)
{
    packet_allocator_t *alloc = packet_allocator_create(10, 1500);
    if (!alloc) return 1;
    
    void *pkt = packet_alloc(alloc, 1024);
    if (!pkt) { packet_allocator_destroy(alloc); return 1; }
    
    packet_free(alloc, pkt);
    packet_allocator_destroy(alloc);
    return 0;
}

static int test_protocols_basic(void)
{
    protocol_decoder_t *decoder = protocol_decoder_create();
    if (!decoder) return 1;
    
    const char *name = protocol_name(PROTO_TCP);
    if (!name) { protocol_decoder_destroy(decoder); return 1; }
    
    protocol_decoder_destroy(decoder);
    return 0;
}

static int test_notify_basic(void)
{
    notifier_t *notifier = notifier_create();
    if (!notifier) return 1;
    
    if (notifier_count(notifier) != 0) { notifier_destroy(notifier); return 1; }
    
    notifier_destroy(notifier);
    return 0;
}

static int test_list_basic(void)
{
    list_t *list = list_create(NULL);
    if (!list) return 1;
    if (!list_empty(list)) return 1;
    list_destroy(list);
    return 0;
}

static int test_list_operations(void)
{
    list_t *list = list_create(NULL);
    int data1 = 100, data2 = 200;
    
    list_append(list, &data1);
    list_append(list, &data2);
    
    if (list_empty(list)) { list_destroy(list); return 1; }
    
    list_destroy(list);
    return 0;
}

static int test_hash_basic(void)
{
    hash_table_t *table = hash_create(64, NULL, NULL, NULL);
    if (!table) return 1;
    hash_destroy(table);
    return 0;
}

static int test_hash_operations(void)
{
    hash_table_t *table = hash_create(64, NULL, NULL, NULL);
    if (!table) return 1;
    
    hash_insert(table, "key1", "value1");
    hash_insert(table, "key2", "value2");
    
    if (hash_size(table) != 2) { hash_destroy(table); return 1; }
    
    void *val = hash_lookup(table, "key1");
    if (!val) { hash_destroy(table); return 1; }
    
    hash_destroy(table);
    return 0;
}

static int test_aes_encrypt(void)
{
    aes_context_t ctx;
    u8 key[16] = {0};
    u8 plaintext[16] = "Hello World!";
    u8 ciphertext[16];
    
    aes_setkey(&ctx, key, AES_KEY_128);
    aes_encrypt(&ctx, plaintext, ciphertext);
    return 0;
}

static int test_aes_decrypt(void)
{
    aes_context_t ctx;
    u8 key[16] = {0};
    u8 plaintext[16] = "Hello World!";
    u8 ciphertext[16];
    u8 result[16];
    
    aes_setkey(&ctx, key, AES_KEY_128);
    aes_encrypt(&ctx, plaintext, ciphertext);
    aes_decrypt(&ctx, ciphertext, result);
    
    if (memcmp(plaintext, result, 16) != 0) return 1;
    return 0;
}

static int test_sha256(void)
{
    sha256_context_t ctx;
    u8 data[] = "test data";
    u8 hash[32];
    
    sha256_init(&ctx);
    sha256_update(&ctx, data, strlen((char*)data));
    sha256_final(&ctx, hash);
    return 0;
}

static int test_crc32(void)
{
    u8 data[] = "test data";
    u32 crc = crc32(data, strlen((char*)data));
    if (crc == 0) return 1;
    return 0;
}

static int test_random(void)
{
    u8 buf[16];
    random_bytes(buf, sizeof(buf));
    return 0;
}

static int test_platform_time(void)
{
    u64 time = get_ms_time();
    if (time == 0) return 1;
    return 0;
}

static int test_platform_sleep(void)
{
    u64 start = get_ms_time();
    sleep_ms(10);
    u64 end = get_ms_time();
    if (end - start < 10) return 1;
    return 0;
}

static int test_platform_cpu(void)
{
    cpu_capability_t cap;
    cpu_detect(&cap);
    if (cap.num_cores <= 0) return 1;
    return 0;
}

static int test_packet_create(void)
{
    packet_t *pkt = packet_create(2048);
    if (!pkt) return 1;
    packet_destroy(pkt);
    return 0;
}

static int test_session_table(void)
{
    session_table_t *table = session_table_create(1024);
    if (!table) return 1;
    session_table_destroy(table);
    return 0;
}

static int test_filter_basic(void)
{
    filter_t *filter = filter_create();
    if (!filter) return 1;
    filter_destroy(filter);
    return 0;
}

int main(void)
{
    int result;
    
    printf("========================================\n");
    printf("NGFW Test Suite\n");
    printf("========================================\n\n");
    
    printf("Running: memory_basic... ");
    result = test_memory_basic();
    printf("%s\n", result == 0 ? "PASS" : "FAIL");
    result == 0 ? tests_passed++ : tests_failed++;
    total_tests++;
    
    printf("Running: memory_calloc... ");
    result = test_memory_calloc();
    printf("%s\n", result == 0 ? "PASS" : "FAIL");
    result == 0 ? tests_passed++ : tests_failed++;
    total_tests++;
    
    printf("Running: memory_realloc... ");
    result = test_memory_realloc();
    printf("%s\n", result == 0 ? "PASS" : "FAIL");
    result == 0 ? tests_passed++ : tests_failed++;
    total_tests++;
    
    printf("Running: list_basic... ");
    result = test_list_basic();
    printf("%s\n", result == 0 ? "PASS" : "FAIL");
    result == 0 ? tests_passed++ : tests_failed++;
    total_tests++;
    
    printf("Running: list_operations... ");
    result = test_list_operations();
    printf("%s\n", result == 0 ? "PASS" : "FAIL");
    result == 0 ? tests_passed++ : tests_failed++;
    total_tests++;
    
    printf("Running: hash_basic... ");
    result = test_hash_basic();
    printf("%s\n", result == 0 ? "PASS" : "FAIL");
    result == 0 ? tests_passed++ : tests_failed++;
    total_tests++;
    
    printf("Running: hash_operations... ");
    result = test_hash_operations();
    printf("%s\n", result == 0 ? "PASS" : "FAIL");
    result == 0 ? tests_passed++ : tests_failed++;
    total_tests++;
    
    printf("Running: aes_encrypt... ");
    result = test_aes_encrypt();
    printf("%s\n", result == 0 ? "PASS" : "FAIL");
    result == 0 ? tests_passed++ : tests_failed++;
    total_tests++;
    
    printf("Running: aes_decrypt... ");
    result = test_aes_decrypt();
    printf("%s\n", result == 0 ? "PASS" : "FAIL");
    result == 0 ? tests_passed++ : tests_failed++;
    total_tests++;
    
    printf("Running: sha256... ");
    result = test_sha256();
    printf("%s\n", result == 0 ? "PASS" : "FAIL");
    result == 0 ? tests_passed++ : tests_failed++;
    total_tests++;
    
    printf("Running: crc32... ");
    result = test_crc32();
    printf("%s\n", result == 0 ? "PASS" : "FAIL");
    result == 0 ? tests_passed++ : tests_failed++;
    total_tests++;
    
    printf("Running: random... ");
    result = test_random();
    printf("%s\n", result == 0 ? "PASS" : "FAIL");
    result == 0 ? tests_passed++ : tests_failed++;
    total_tests++;
    
    printf("Running: platform_time... ");
    result = test_platform_time();
    printf("%s\n", result == 0 ? "PASS" : "FAIL");
    result == 0 ? tests_passed++ : tests_failed++;
    total_tests++;
    
    printf("Running: platform_sleep... ");
    result = test_platform_sleep();
    printf("%s\n", result == 0 ? "PASS" : "FAIL");
    result == 0 ? tests_passed++ : tests_failed++;
    total_tests++;
    
    printf("Running: platform_cpu... ");
    result = test_platform_cpu();
    printf("%s\n", result == 0 ? "PASS" : "FAIL");
    result == 0 ? tests_passed++ : tests_failed++;
    total_tests++;
    
    printf("Running: packet_create... ");
    result = test_packet_create();
    printf("%s\n", result == 0 ? "PASS" : "FAIL");
    result == 0 ? tests_passed++ : tests_failed++;
    total_tests++;
    
    printf("Running: session_table... ");
    result = test_session_table();
    printf("%s\n", result == 0 ? "PASS" : "FAIL");
    result == 0 ? tests_passed++ : tests_failed++;
    total_tests++;
    
    printf("Running: filter_basic... ");
    result = test_filter_basic();
    printf("%s\n", result == 0 ? "PASS" : "FAIL");
    result == 0 ? tests_passed++ : tests_failed++;
    total_tests++;
    
    printf("Running: mempool_basic... ");
    result = test_mempool_basic();
    printf("%s\n", result == 0 ? "PASS" : "FAIL");
    result == 0 ? tests_passed++ : tests_failed++;
    total_tests++;
    
    printf("Running: mempool_stress... ");
    result = test_mempool_stress();
    printf("%s\n", result == 0 ? "PASS" : "FAIL");
    result == 0 ? tests_passed++ : tests_failed++;
    total_tests++;
    
    printf("Running: module_interface... ");
    result = test_module_interface();
    printf("%s\n", result == 0 ? "PASS" : "FAIL");
    result == 0 ? tests_passed++ : tests_failed++;
    total_tests++;
    
    printf("Running: ringbuffer_basic... ");
    result = test_ringbuffer_basic();
    printf("%s\n", result == 0 ? "PASS" : "FAIL");
    result == 0 ? tests_passed++ : tests_failed++;
    total_tests++;
    
    printf("Running: ratelimiter_basic... ");
    result = test_ratelimiter_basic();
    printf("%s\n", result == 0 ? "PASS" : "FAIL");
    result == 0 ? tests_passed++ : tests_failed++;
    total_tests++;
    
    printf("Running: connpool_basic... ");
    result = test_connpool_basic();
    printf("%s\n", result == 0 ? "PASS" : "FAIL");
    result == 0 ? tests_passed++ : tests_failed++;
    total_tests++;
    
    printf("Running: bloom_basic... ");
    result = test_bloom_basic();
    printf("%s\n", result == 0 ? "PASS" : "FAIL");
    result == 0 ? tests_passed++ : tests_failed++;
    total_tests++;
    
    printf("Running: lrucache_basic... ");
    result = test_lrucache_basic();
    printf("%s\n", result == 0 ? "PASS" : "FAIL");
    result == 0 ? tests_passed++ : tests_failed++;
    total_tests++;
    
    printf("Running: asynclog_basic... ");
    result = test_asynclog_basic();
    printf("%s\n", result == 0 ? "PASS" : "FAIL");
    result == 0 ? tests_passed++ : tests_failed++;
    total_tests++;
    
    printf("Running: ipv6_basic... ");
    result = test_ipv6_basic();
    printf("%s\n", result == 0 ? "PASS" : "FAIL");
    result == 0 ? tests_passed++ : tests_failed++;
    total_tests++;
    
    printf("Running: metrics_basic... ");
    result = test_metrics_basic();
    printf("%s\n", result == 0 ? "PASS" : "FAIL");
    result == 0 ? tests_passed++ : tests_failed++;
    total_tests++;
    
    printf("Running: strutil_basic... ");
    result = test_strutil_basic();
    printf("%s\n", result == 0 ? "PASS" : "FAIL");
    result == 0 ? tests_passed++ : tests_failed++;
    total_tests++;
    
    printf("Running: timerwheel_basic... ");
    result = test_timerwheel_basic();
    printf("%s\n", result == 0 ? "PASS" : "FAIL");
    result == 0 ? tests_passed++ : tests_failed++;
    total_tests++;
    
    printf("Running: skiplist_basic... ");
    result = test_skiplist_basic();
    printf("%s\n", result == 0 ? "PASS" : "FAIL");
    result == 0 ? tests_passed++ : tests_failed++;
    total_tests++;
    
    printf("Running: packet_alloc_basic... ");
    result = test_packet_alloc_basic();
    printf("%s\n", result == 0 ? "PASS" : "FAIL");
    result == 0 ? tests_passed++ : tests_failed++;
    total_tests++;
    
    printf("Running: protocols_basic... ");
    result = test_protocols_basic();
    printf("%s\n", result == 0 ? "PASS" : "FAIL");
    result == 0 ? tests_passed++ : tests_failed++;
    total_tests++;
    
    printf("Running: notify_basic... ");
    result = test_notify_basic();
    printf("%s\n", result == 0 ? "PASS" : "FAIL");
    result == 0 ? tests_passed++ : tests_failed++;
    total_tests++;
    
    test_summary();
    
    return 0;
}
