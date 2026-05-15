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
#include "ngfw/ips.h"
#include "ngfw/nat.h"
#include "ngfw/ddos.h"
#include "ngfw/qos.h"
#include "ngfw/vpn.h"
#include "ngfw/antivirus.h"
#include "ngfw/urlfilter.h"
#include "ngfw/netfilter.h"
#include "ngfw/hwaccel.h"
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
    bloom_filter_t *bf = bloom_create(100, 0.01);
    if (!bf) return 1;

    bloom_add(bf, "test_key", 8);
    if (!bloom_test(bf, "test_key", 8)) { bloom_destroy(bf); return 1; }

    if (bloom_test(bf, "no_such_key", 11)) { bloom_destroy(bf); return 1; }

    bloom_clear(bf);
    if (bloom_test(bf, "test_key", 8)) { bloom_destroy(bf); return 1; }

    bloom_destroy(bf);
    return 0;
}

static void test_lru_destructor(void *key, void *value)
{
    (void)key;
    ngfw_free(value);
}

static int test_lrucache_basic(void)
{
    lru_cache_t *cache = lru_create(3, test_lru_destructor);
    if (!cache) return 1;

    if (lru_capacity(cache) != 3) { lru_destroy(cache); return 1; }

    int *a = ngfw_malloc(sizeof(int)); *a = 1;
    int *b = ngfw_malloc(sizeof(int)); *b = 2;
    int *c = ngfw_malloc(sizeof(int)); *c = 3;
    int *d = ngfw_malloc(sizeof(int)); *d = 4;

    if (!lru_put(cache, "a", a)) { lru_destroy(cache); return 1; }
    if (!lru_put(cache, "b", b)) { lru_destroy(cache); return 1; }
    if (!lru_put(cache, "c", c)) { lru_destroy(cache); return 1; }
    if (lru_size(cache) != 3) { lru_destroy(cache); return 1; }

    /* Access 'a' to make it recently used */
    int *val = (int *)lru_get(cache, "a");
    if (!val || *val != 1) { lru_destroy(cache); return 1; }

    /* Insert 'd' - should evict 'b' (LRU) */
    if (!lru_put(cache, "d", d)) { lru_destroy(cache); return 1; }
    if (lru_size(cache) != 3) { lru_destroy(cache); return 1; }
    if (lru_contains(cache, "b")) { lru_destroy(cache); return 1; }
    if (!lru_contains(cache, "d")) { lru_destroy(cache); return 1; }

    /* Remove 'a' */
    val = (int *)lru_remove(cache, "a");
    if (!val || *val != 1) { lru_destroy(cache); return 1; }
    ngfw_free(val);
    if (lru_size(cache) != 2) { lru_destroy(cache); return 1; }

    lru_destroy(cache);
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
    u8 addr[16];

    /* Parse a valid IPv6 address */
    if (!ipv6_parse("::1", addr)) return 1;
    if (!ipv6_is_loopback(addr)) return 1;

    if (!ipv6_parse("fe80::1", addr)) return 1;
    if (!ipv6_is_link_local(addr)) return 1;

    if (!ipv6_parse("ff02::1", addr)) return 1;
    if (!ipv6_is_multicast(addr)) return 1;

    if (!ipv6_parse("fc00::1", addr)) return 1;
    if (!ipv6_is_unique_local(addr)) return 1;

    if (!ipv6_parse("2001:db8::1", addr)) return 1;
    if (!ipv6_is_global_unicast(addr)) return 1;

    /* Test string conversion */
    char buf[64];
    char *result = ipv6_to_string(addr, buf, sizeof(buf));
    if (!result) return 1;

    /* Test compare */
    u8 addr_a[16], addr_b[16];
    ipv6_parse("::1", addr_a);
    ipv6_parse("::1", addr_b);
    if (ipv6_compare(addr_a, addr_b) != 0) return 1;

    ipv6_parse("::2", addr_b);
    if (ipv6_compare(addr_a, addr_b) >= 0) return 1;

    /* Test range */
    u8 net[16];
    ipv6_parse("2001:db8::", net);
    if (!ipv6_in_range(addr, net, 32)) return 1;

    return 0;
}

static int test_metrics_basic(void)
{
    metrics_registry_t *reg = metrics_create();
    if (!reg) return 1;

    /* Register and test counter */
    if (metrics_register(reg, "test_counter", "Test counter", METRIC_TYPE_COUNTER) != NGFW_OK) {
        metrics_destroy(reg); return 1;
    }
    if (metrics_counter_inc(reg, "test_counter") != NGFW_OK) { metrics_destroy(reg); return 1; }
    if (metrics_counter_add(reg, "test_counter", 5) != NGFW_OK) { metrics_destroy(reg); return 1; }

    /* Register duplicate should fail */
    if (metrics_register(reg, "test_counter", "dup", METRIC_TYPE_COUNTER) != NGFW_ERR_EXISTS) {
        metrics_destroy(reg); return 1;
    }

    /* Register and test gauge */
    if (metrics_register(reg, "test_gauge", "Test gauge", METRIC_TYPE_GAUGE) != NGFW_OK) {
        metrics_destroy(reg); return 1;
    }
    if (metrics_gauge_set(reg, "test_gauge", 42) != NGFW_OK) { metrics_destroy(reg); return 1; }
    if (metrics_gauge_inc(reg, "test_gauge") != NGFW_OK) { metrics_destroy(reg); return 1; }
    if (metrics_gauge_dec(reg, "test_gauge") != NGFW_OK) { metrics_destroy(reg); return 1; }

    /* Verify values */
    metric_t m;
    if (metrics_get(reg, "test_counter", &m) != NGFW_OK) { metrics_destroy(reg); return 1; }
    if (m.type != METRIC_TYPE_COUNTER || m.data.counter.value != 6) { metrics_destroy(reg); return 1; }

    if (metrics_get(reg, "test_gauge", &m) != NGFW_OK) { metrics_destroy(reg); return 1; }
    if (m.type != METRIC_TYPE_GAUGE || m.data.gauge.value != 42) { metrics_destroy(reg); return 1; }

    /* Test JSON export */
    char *json = metrics_export_json(reg);
    if (!json) { metrics_destroy(reg); return 1; }

    metrics_destroy(reg);
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
    timer_wheel_t *wheel = timer_wheel_create(10);
    if (!wheel) return 1;

    if (timer_wheel_get_active_timers(wheel) != 0) { timer_wheel_destroy(wheel); return 1; }

    /* NULL callback should be rejected */
    timer_entry_t *entry = timer_wheel_add_timer(wheel, 100, NULL, NULL);
    if (entry) { timer_wheel_destroy(wheel); return 1; }

    /* Add a timer with valid callback */
    entry = timer_wheel_add_timer(wheel, 100, (timer_callback_t)1, NULL);
    if (!entry) { timer_wheel_destroy(wheel); return 1; }

    if (timer_wheel_get_active_timers(wheel) != 1) { timer_wheel_destroy(wheel); return 1; }

    /* Cancel the timer */
    timer_wheel_cancel_timer(entry);

    timer_wheel_destroy(wheel);
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
    hash_table_t *table = hash_create(64, hash_str, equal_str, NULL);
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

static int test_ips_basic(void)
{
    ips_t *ips = ips_create();
    if (!ips) return 1;

    ips_stats_t *stats = ips_get_stats(ips);
    if (!stats) { ips_destroy(ips); return 1; }
    if (stats->signatures_loaded == 0) { ips_destroy(ips); return 1; }

    ips_destroy(ips);
    return 0;
}

static int test_ips_check_packet(void)
{
    ips_t *ips = ips_create();
    if (!ips) return 1;

    packet_t *pkt = packet_create(256);
    if (!pkt) { ips_destroy(ips); return 1; }

    /* Create a minimal IP packet with some data */
    u8 raw_data[] = {0x45, 0x00, 0x00, 0x30, 0x00, 0x00, 0x00, 0x00,
                     0x40, 0x06, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x01,
                     0x0a, 0x00, 0x00, 0x02, 0x00, 0x50, 0x00, 0x50,
                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                     0x50, 0x02, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00,
                     '<', 's', 'c', 'r', 'i', 'p', 't', '>'};
    packet_append(pkt, raw_data, sizeof(raw_data));

    ips_alert_t alert;
    bool drop = false;
    ngfw_ret_t ret = ips_check_packet_with_action(ips, pkt, &alert, &drop);
    (void)ret;

    packet_destroy(pkt);
    ips_destroy(ips);
    return 0;
}

static int test_ips_block_ip(void)
{
    ips_t *ips = ips_create();
    if (!ips) return 1;

    if (ips_is_ip_blocked(ips, 0x0a000001)) { ips_destroy(ips); return 1; }

    ips_block_ip(ips, 0x0a000001, 60);
    if (!ips_is_ip_blocked(ips, 0x0a000001)) { ips_destroy(ips); return 1; }

    ips_unblock_ip(ips, 0x0a000001);
    if (ips_is_ip_blocked(ips, 0x0a000001)) { ips_destroy(ips); return 1; }

    ips_destroy(ips);
    return 0;
}

static int test_nat_basic(void)
{
    nat_t *nat = nat_create();
    if (!nat) return 1;

    nat_stats_t *stats = nat_get_stats(nat);
    if (!stats) { nat_destroy(nat); return 1; }

    nat_destroy(nat);
    return 0;
}

static int test_nat_rule(void)
{
    nat_t *nat = nat_create();
    if (!nat) return 1;

    nat_rule_t rule = {0};
    rule.type = NAT_TYPE_SNAT;
    rule.enabled = true;
    rule.src_ip = 0x0a000000;
    rule.src_mask = 0xffffff00;
    rule.new_src_ip = 0x0a000001;

    if (nat_add_rule(nat, &rule) != NGFW_OK) { nat_destroy(nat); return 1; }
    if (nat_del_rule(nat, rule.id) != NGFW_OK) { nat_destroy(nat); return 1; }

    nat_destroy(nat);
    return 0;
}

static int test_nat_translate(void)
{
    nat_t *nat = nat_create();
    if (!nat) return 1;

    nat_rule_t rule = {0};
    rule.type = NAT_TYPE_SNAT;
    rule.enabled = true;
    rule.src_ip = 0x0a000000;
    rule.src_mask = 0xffffff00;
    rule.new_src_ip = 0x0a000001;
    nat_add_rule(nat, &rule);

    packet_t *pkt = packet_create(64);
    u8 raw_ip[] = {0x45, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x00, 0x00,
                   0x40, 0x06, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x01,
                   0x0a, 0x00, 0x00, 0x02, 0x00, 0x50, 0x00, 0x50,
                   0x00, 0x00, 0x00, 0x00};
    packet_append(pkt, raw_ip, sizeof(raw_ip));

    nat_entry_t entry;
    ngfw_ret_t ret = nat_translate_packet(nat, pkt, &entry);
    (void)ret;

    packet_destroy(pkt);
    nat_destroy(nat);
    return 0;
}

static int test_ddos_basic(void)
{
    ddos_t *ddos = ddos_create();
    if (!ddos) return 1;

    ddos_profile_t *profile = ddos_get_profile(ddos);
    if (!profile) { ddos_destroy(ddos); return 1; }
    if (!profile->enabled) { ddos_destroy(ddos); return 1; }

    ddos_stats_t *stats = ddos_get_stats(ddos);
    if (!stats) { ddos_destroy(ddos); return 1; }

    ddos_destroy(ddos);
    return 0;
}

static int test_ddos_block_ip(void)
{
    ddos_t *ddos = ddos_create();
    if (!ddos) return 1;

    bool should_block = false;
    ddos_check_ip(ddos, 0x0a000001, &should_block);
    if (should_block) { ddos_destroy(ddos); return 1; }

    ddos_block_ip(ddos, 0x0a000001, 60, "test block");
    ddos_check_ip(ddos, 0x0a000001, &should_block);
    if (!should_block) { ddos_destroy(ddos); return 1; }

    ddos_unblock_ip(ddos, 0x0a000001);
    ddos_check_ip(ddos, 0x0a000001, &should_block);
    if (should_block) { ddos_destroy(ddos); return 1; }

    ddos_destroy(ddos);
    return 0;
}

static int test_qos_basic(void)
{
    qos_t *qos = qos_create();
    if (!qos) return 1;

    if (qos_init(qos, QOS_SCHEDULER_FIFO) != NGFW_OK) { qos_destroy(qos); return 1; }

    packet_t *pkt = packet_create(64);
    if (!pkt) { qos_destroy(qos); return 1; }
    u8 data[] = "test packet data";
    packet_append(pkt, data, sizeof(data));

    if (qos_enqueue(qos, pkt, QOS_CLASS_BEST_EFFORT) != NGFW_OK) {
        packet_destroy(pkt); qos_destroy(qos); return 1;
    }

    packet_t *out = qos_dequeue(qos, QOS_CLASS_BEST_EFFORT);
    if (!out) { qos_destroy(qos); return 1; }
    packet_destroy(out);

    qos_destroy(qos);
    return 0;
}

static int test_qos_ratelimit(void)
{
    qos_rate_limiter_t *limiter = rate_limiter_create(1000, 100);
    if (!limiter) return 1;

    if (!rate_limiter_allow(limiter, 50)) { rate_limiter_destroy(limiter); return 1; }
    if (!rate_limiter_allow(limiter, 50)) { rate_limiter_destroy(limiter); return 1; }

    rate_limiter_destroy(limiter);
    return 0;
}

static int test_qos_diffserv(void)
{
    qos_diffserv_t ds;
    if (diffserv_init(&ds) != NGFW_OK) return 1;

    u8 dscp = diffserv_encode(&ds, QOS_CLASS_VOICE);
    if (dscp != 46) return 1;

    qos_class_type_t cls = diffserv_decode(&ds, 46);
    if (cls != QOS_CLASS_VOICE) return 1;

    return 0;
}

static int test_vpn_basic(void)
{
    vpn_t *vpn = vpn_create(VPN_TYPE_IPSEC);
    if (!vpn) return 1;

    vpn_stats_t *stats = vpn_get_stats(vpn);
    if (!stats) { vpn_destroy(vpn); return 1; }

    vpn_destroy(vpn);
    return 0;
}

static int test_vpn_tunnel(void)
{
    vpn_t *vpn = vpn_create(VPN_TYPE_IPSEC);
    if (!vpn) return 1;

    vpn_tunnel_t config = {0};
    config.id = 1;
    snprintf(config.name, sizeof(config.name), "test-tunnel");
    snprintf(config.local_addr, sizeof(config.local_addr), "192.168.1.1");
    snprintf(config.remote_addr, sizeof(config.remote_addr), "10.0.0.1");
    snprintf(config.local_net, sizeof(config.local_net), "192.168.1.0/24");
    snprintf(config.remote_net, sizeof(config.remote_net), "10.0.0.0/24");

    vpn_tunnel_t *tunnel = NULL;
    if (vpn_tunnel_create(vpn, &config, &tunnel) != NGFW_OK) { vpn_destroy(vpn); return 1; }
    if (!tunnel) { vpn_destroy(vpn); return 1; }

    if (vpn_tunnel_establish(vpn, tunnel) != NGFW_OK) { vpn_destroy(vpn); return 1; }
    if (!tunnel->established) { vpn_destroy(vpn); return 1; }

    if (vpn_tunnel_close(vpn, tunnel) != NGFW_OK) { vpn_destroy(vpn); return 1; }
    if (tunnel->established) { vpn_destroy(vpn); return 1; }

    vpn_tunnel_destroy(vpn, tunnel->id);
    vpn_destroy(vpn);
    return 0;
}

static int test_vpn_psk(void)
{
    vpn_t *vpn = vpn_create(VPN_TYPE_IPSEC);
    if (!vpn) return 1;

    if (vpn_set_psk(vpn, "test-psk-key") != NGFW_OK) { vpn_destroy(vpn); return 1; }

    vpn_destroy(vpn);
    return 0;
}

static int test_antivirus_basic(void)
{
    antivirus_t *av = antivirus_create();
    if (!av) return 1;

    av_stats_t *stats = antivirus_get_stats(av);
    if (!stats) { antivirus_destroy(av); return 1; }

    const u8 clean_data[] = "This is clean data without malware";
    av_scan_result_t result = AV_SCAN_RESULT_CLEAN;
    if (antivirus_scan_buffer(av, clean_data, sizeof(clean_data), &result, NULL) != NGFW_OK) {
        antivirus_destroy(av); return 1;
    }

    antivirus_destroy(av);
    return 0;
}

static int test_antivirus_eicar(void)
{
    antivirus_t *av = antivirus_create();
    if (!av) return 1;

    const u8 eicar[] = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
    av_scan_result_t result = AV_SCAN_RESULT_CLEAN;
    av_alert_t alert;
    if (antivirus_scan_buffer(av, eicar, sizeof(eicar), &result, &alert) != NGFW_OK) {
        antivirus_destroy(av); return 1;
    }

    if (result != AV_SCAN_RESULT_INFECTED) { antivirus_destroy(av); return 1; }

    antivirus_destroy(av);
    return 0;
}

static int test_urlfilter_basic(void)
{
    urlfilter_t *filter = urlfilter_create();
    if (!filter) return 1;

    url_stats_t *stats = urlfilter_get_stats(filter);
    if (!stats) { urlfilter_destroy(filter); return 1; }

    urlfilter_destroy(filter);
    return 0;
}

static int test_urlfilter_dns(void)
{
    urlfilter_t *filter = urlfilter_create();
    if (!filter) return 1;

    dns_rule_t rule = {0};
    rule.id = 1;
    snprintf(rule.domain, sizeof(rule.domain), "malware.example.com");
    rule.category = URL_CATEGORY_MALWARE;
    rule.block = true;
    rule.enabled = true;
    urlfilter_add_dns_rule(filter, &rule);

    bool blocked = false;
    ngfw_ret_t ret = urlfilter_check_domain(filter, "malware.example.com", &blocked);
    if (ret != NGFW_OK || !blocked) { urlfilter_destroy(filter); return 1; }

    blocked = false;
    ret = urlfilter_check_domain(filter, "good.example.com", &blocked);
    if (blocked) { urlfilter_destroy(filter); return 1; }

    urlfilter_destroy(filter);
    return 0;
}

static int test_urlfilter_url(void)
{
    urlfilter_t *filter = urlfilter_create();
    if (!filter) return 1;

    dns_rule_t rule = {0};
    rule.id = 1;
    snprintf(rule.domain, sizeof(rule.domain), "blocked.test.com");
    rule.category = URL_CATEGORY_ADULT;
    rule.block = true;
    rule.enabled = true;
    urlfilter_add_dns_rule(filter, &rule);

    url_category_t category = URL_CATEGORY_NONE;
    ngfw_ret_t ret = urlfilter_check_url(filter, "http://blocked.test.com/page.html", &category);
    if (ret != NGFW_OK) { urlfilter_destroy(filter); return 1; }

    urlfilter_destroy(filter);
    return 0;
}

static int test_netfilter_basic(void)
{
    netfilter_t *nf = netfilter_create();
    if (!nf) return 1;

    if (netfilter_init(nf) != NGFW_OK) { netfilter_destroy(nf); return 1; }

    nf_stats_t *stats = netfilter_get_stats(nf);
    if (!stats) { netfilter_shutdown(nf); netfilter_destroy(nf); return 1; }

    netfilter_shutdown(nf);
    netfilter_destroy(nf);
    return 0;
}

static int test_netfilter_rules(void)
{
    netfilter_t *nf = netfilter_create();
    if (!nf) return 1;

    netfilter_init(nf);

    netfilter_rule_t rule = {0};
    rule.id = 1;
    rule.table = NF_TABLE_FILTER;
    rule.chain = NF_CHAIN_FORWARD;
    rule.target = NF_TARGET_ACCEPT;
    rule.enabled = true;
    rule.protocol = NF_PROTO_ALL;

    if (netfilter_add_rule(nf, &rule) != NGFW_OK) { netfilter_shutdown(nf); netfilter_destroy(nf); return 1; }
    if (netfilter_del_rule(nf, 1) != NGFW_OK) { netfilter_shutdown(nf); netfilter_destroy(nf); return 1; }

    netfilter_shutdown(nf);
    netfilter_destroy(nf);
    return 0;
}

static int test_netfilter_check_packet(void)
{
    netfilter_t *nf = netfilter_create();
    if (!nf) return 1;

    netfilter_init(nf);

    packet_t *pkt = packet_create(64);
    if (!pkt) { netfilter_shutdown(nf); netfilter_destroy(nf); return 1; }
    u8 data[] = {0x45, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x00, 0x00,
                 0x40, 0x06, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x01,
                 0x0a, 0x00, 0x00, 0x02};
    packet_append(pkt, data, sizeof(data));

    int verdict = netfilter_check_packet(nf, pkt);
    if (verdict != NF_TARGET_ACCEPT) { packet_destroy(pkt); netfilter_shutdown(nf); netfilter_destroy(nf); return 1; }

    netfilter_rule_t rule = {0};
    rule.id = 1;
    rule.table = NF_TABLE_FILTER;
    rule.chain = NF_CHAIN_FORWARD;
    rule.target = NF_TARGET_DROP;
    rule.enabled = true;
    rule.protocol = NF_PROTO_ALL;
    netfilter_add_rule(nf, &rule);

    verdict = netfilter_check_packet(nf, pkt);
    if (verdict != NF_TARGET_DROP) { packet_destroy(pkt); netfilter_shutdown(nf); netfilter_destroy(nf); return 1; }

    packet_destroy(pkt);
    netfilter_shutdown(nf);
    netfilter_destroy(nf);
    return 0;
}

static int test_hwaccel_basic(void)
{
    hwaccel_t *hw = hwaccel_create();
    if (!hw) return 1;

    if (hwaccel_init(hw) != NGFW_OK) { hwaccel_destroy(hw); return 1; }

    hwaccel_info_t info[8];
    int count = hwaccel_detect(info, 8);
    if (count < 0) { hwaccel_shutdown(hw); hwaccel_destroy(hw); return 1; }

    hwaccel_shutdown(hw);
    hwaccel_destroy(hw);
    return 0;
}

static int test_hwaccel_crypto(void)
{
    hwaccel_t *hw = hwaccel_create();
    if (!hw) return 1;

    hwaccel_init(hw);

    u8 key[16] = {0};
    u8 iv[16] = {0};
    u8 plaintext[32] = "Hello World! AES test Data.";
    u8 ciphertext[32];
    u8 decrypted[32];
    memset(ciphertext, 0, 32);
    memset(decrypted, 0, 32);

    if (hwaccel_crypto_aes_encrypt(hw, key, iv, plaintext, ciphertext, 32) != NGFW_OK) {
        hwaccel_shutdown(hw); hwaccel_destroy(hw); return 1;
    }

    if (hwaccel_crypto_aes_decrypt(hw, key, iv, ciphertext, decrypted, 32) != NGFW_OK) {
        hwaccel_shutdown(hw); hwaccel_destroy(hw); return 1;
    }

    if (memcmp(plaintext, decrypted, 32) != 0) {
        hwaccel_shutdown(hw); hwaccel_destroy(hw); return 1;
    }

    hwaccel_shutdown(hw);
    hwaccel_destroy(hw);
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
    
    printf("Running: ips_basic... ");
    result = test_ips_basic();
    printf("%s\n", result == 0 ? "PASS" : "FAIL");
    result == 0 ? tests_passed++ : tests_failed++;
    total_tests++;

    printf("Running: ips_check_packet... ");
    result = test_ips_check_packet();
    printf("%s\n", result == 0 ? "PASS" : "FAIL");
    result == 0 ? tests_passed++ : tests_failed++;
    total_tests++;

    printf("Running: ips_block_ip... ");
    result = test_ips_block_ip();
    printf("%s\n", result == 0 ? "PASS" : "FAIL");
    result == 0 ? tests_passed++ : tests_failed++;
    total_tests++;

    printf("Running: nat_basic... ");
    result = test_nat_basic();
    printf("%s\n", result == 0 ? "PASS" : "FAIL");
    result == 0 ? tests_passed++ : tests_failed++;
    total_tests++;

    printf("Running: nat_rule... ");
    result = test_nat_rule();
    printf("%s\n", result == 0 ? "PASS" : "FAIL");
    result == 0 ? tests_passed++ : tests_failed++;
    total_tests++;

    printf("Running: nat_translate... ");
    result = test_nat_translate();
    printf("%s\n", result == 0 ? "PASS" : "FAIL");
    result == 0 ? tests_passed++ : tests_failed++;
    total_tests++;

    printf("Running: ddos_basic... ");
    result = test_ddos_basic();
    printf("%s\n", result == 0 ? "PASS" : "FAIL");
    result == 0 ? tests_passed++ : tests_failed++;
    total_tests++;

    printf("Running: ddos_block_ip... ");
    result = test_ddos_block_ip();
    printf("%s\n", result == 0 ? "PASS" : "FAIL");
    result == 0 ? tests_passed++ : tests_failed++;
    total_tests++;

    printf("Running: qos_basic... ");
    result = test_qos_basic();
    printf("%s\n", result == 0 ? "PASS" : "FAIL");
    result == 0 ? tests_passed++ : tests_failed++;
    total_tests++;

    printf("Running: qos_ratelimit... ");
    result = test_qos_ratelimit();
    printf("%s\n", result == 0 ? "PASS" : "FAIL");
    result == 0 ? tests_passed++ : tests_failed++;
    total_tests++;

    printf("Running: qos_diffserv... ");
    result = test_qos_diffserv();
    printf("%s\n", result == 0 ? "PASS" : "FAIL");
    result == 0 ? tests_passed++ : tests_failed++;
    total_tests++;

    printf("Running: vpn_basic... ");
    result = test_vpn_basic();
    printf("%s\n", result == 0 ? "PASS" : "FAIL");
    result == 0 ? tests_passed++ : tests_failed++;
    total_tests++;

    printf("Running: vpn_tunnel... ");
    result = test_vpn_tunnel();
    printf("%s\n", result == 0 ? "PASS" : "FAIL");
    result == 0 ? tests_passed++ : tests_failed++;
    total_tests++;

    printf("Running: vpn_psk... ");
    result = test_vpn_psk();
    printf("%s\n", result == 0 ? "PASS" : "FAIL");
    result == 0 ? tests_passed++ : tests_failed++;
    total_tests++;

    printf("Running: antivirus_basic... ");
    result = test_antivirus_basic();
    printf("%s\n", result == 0 ? "PASS" : "FAIL");
    result == 0 ? tests_passed++ : tests_failed++;
    total_tests++;

    printf("Running: antivirus_eicar... ");
    result = test_antivirus_eicar();
    printf("%s\n", result == 0 ? "PASS" : "FAIL");
    result == 0 ? tests_passed++ : tests_failed++;
    total_tests++;

    printf("Running: urlfilter_basic... ");
    result = test_urlfilter_basic();
    printf("%s\n", result == 0 ? "PASS" : "FAIL");
    result == 0 ? tests_passed++ : tests_failed++;
    total_tests++;

    printf("Running: urlfilter_dns... ");
    result = test_urlfilter_dns();
    printf("%s\n", result == 0 ? "PASS" : "FAIL");
    result == 0 ? tests_passed++ : tests_failed++;
    total_tests++;

    printf("Running: urlfilter_url... ");
    result = test_urlfilter_url();
    printf("%s\n", result == 0 ? "PASS" : "FAIL");
    result == 0 ? tests_passed++ : tests_failed++;
    total_tests++;

    printf("Running: netfilter_basic... ");
    result = test_netfilter_basic();
    printf("%s\n", result == 0 ? "PASS" : "FAIL");
    result == 0 ? tests_passed++ : tests_failed++;
    total_tests++;

    printf("Running: netfilter_rules... ");
    result = test_netfilter_rules();
    printf("%s\n", result == 0 ? "PASS" : "FAIL");
    result == 0 ? tests_passed++ : tests_failed++;
    total_tests++;

    printf("Running: netfilter_check_packet... ");
    result = test_netfilter_check_packet();
    printf("%s\n", result == 0 ? "PASS" : "FAIL");
    result == 0 ? tests_passed++ : tests_failed++;
    total_tests++;

    printf("Running: hwaccel_basic... ");
    result = test_hwaccel_basic();
    printf("%s\n", result == 0 ? "PASS" : "FAIL");
    result == 0 ? tests_passed++ : tests_failed++;
    total_tests++;

    printf("Running: hwaccel_crypto... ");
    result = test_hwaccel_crypto();
    printf("%s\n", result == 0 ? "PASS" : "FAIL");
    result == 0 ? tests_passed++ : tests_failed++;
    total_tests++;

    test_summary();
    
    return 0;
}
