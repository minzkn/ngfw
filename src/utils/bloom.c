#include "ngfw/bloom.h"
#include "ngfw/memory.h"
#include "ngfw/crypto.h"
#include <stddef.h>
#include <string.h>
#include <math.h>

#define MAX_HASH_FUNCTIONS 16
#define MIN_BITS_PER_ITEM 4

struct bloom_filter {
    u8 *bits;
    u64 size;
    u64 capacity;
    u64 items_added;
    u32 num_hash_functions;
    double false_positive_rate;
};

static u32 hash_function(bloom_filter_t *bloom, const void *data, u32 len, u32 seed)
{
    u8 hash[16];
    sha256((const u8 *)data, len, hash);
    
    u32 h1 = *(u32 *)hash;
    u32 h2 = *(u32 *)(hash + 4);
    
    return (h1 + seed * h2) % bloom->size;
}

bloom_filter_t *bloom_create(u64 expected_items, double false_positive_rate)
{
    if (expected_items == 0 || false_positive_rate <= 0 || false_positive_rate >= 1) {
        return NULL;
    }
    
    bloom_filter_t *bloom = ngfw_malloc(sizeof(bloom_filter_t));
    if (!bloom) return NULL;
    
    double m = -((double)expected_items * log(false_positive_rate)) / (log(2) * log(2));
    double k = (m / expected_items) * log(2);
    
    u64 size = (u64)ceil(m);
    u32 num_hash = (u32)ceil(k);
    
    if (num_hash > MAX_HASH_FUNCTIONS) num_hash = MAX_HASH_FUNCTIONS;
    if (num_hash < 2) num_hash = 2;
    
    u64 bytes = (size + 7) / 8;
    u8 *bits = ngfw_malloc(bytes);
    if (!bits) {
        ngfw_free(bloom);
        return NULL;
    }
    
    memset(bits, 0, bytes);
    
    bloom->bits = bits;
    bloom->size = size;
    bloom->capacity = expected_items;
    bloom->items_added = 0;
    bloom->num_hash_functions = num_hash;
    bloom->false_positive_rate = false_positive_rate;
    
    return bloom;
}

void bloom_destroy(bloom_filter_t *bloom)
{
    if (!bloom) return;
    ngfw_free(bloom->bits);
    ngfw_free(bloom);
}

void bloom_add(bloom_filter_t *bloom, const void *data, u32 len)
{
    if (!bloom || !data || len == 0) return;
    if (bloom->items_added >= bloom->capacity) return;
    
    for (u32 i = 0; i < bloom->num_hash_functions; i++) {
        u32 idx = hash_function(bloom, data, len, i);
        bloom->bits[idx / 8] |= (1 << (idx % 8));
    }
    
    bloom->items_added++;
}

bool bloom_test(bloom_filter_t *bloom, const void *data, u32 len)
{
    if (!bloom || !data || len == 0) return false;
    
    for (u32 i = 0; i < bloom->num_hash_functions; i++) {
        u32 idx = hash_function(bloom, data, len, i);
        if (!(bloom->bits[idx / 8] & (1 << (idx % 8)))) {
            return false;
        }
    }
    
    return true;
}

void bloom_clear(bloom_filter_t *bloom)
{
    if (!bloom) return;
    memset(bloom->bits, 0, (bloom->size + 7) / 8);
    bloom->items_added = 0;
}

u64 bloom_size(bloom_filter_t *bloom)
{
    return bloom ? bloom->size : 0;
}

u64 bloom_capacity(bloom_filter_t *bloom)
{
    return bloom ? bloom->capacity : 0;
}

double bloom_false_positive_rate(bloom_filter_t *bloom)
{
    if (!bloom) return 0;
    
    double k = bloom->num_hash_functions;
    double m = bloom->size;
    double n = bloom->items_added;
    
    if (n == 0) return 0;
    
    return pow(1 - exp(-k * n / m), k);
}
