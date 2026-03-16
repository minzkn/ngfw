/*
 * NGFW - Next-Generation Firewall
 * Copyright (C) 2024 NGFW Project
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 */

#include "ngfw/ratelimit.h"
#include "ngfw/memory.h"
#include "ngfw/platform.h"
#include "ngfw/hash.h"
#include <stddef.h>
#include <string.h>

struct ratelimiter {
    ratelimit_algorithm_t algo;
    u32 rate;
    u32 burst;
    u32 tokens;
    u64 last_update;
};

ratelimiter_t *ratelimiter_create(ratelimit_algorithm_t algo, u32 rate, u32 burst)
{
    ratelimiter_t *rl = ngfw_malloc(sizeof(ratelimiter_t));
    if (!rl) return NULL;
    
    rl->algo = algo;
    rl->rate = rate;
    rl->burst = burst;
    rl->tokens = burst;
    rl->last_update = get_us_time();
    
    return rl;
}

void ratelimiter_destroy(ratelimiter_t *rl)
{
    if (rl) ngfw_free(rl);
}

bool ratelimiter_allow(ratelimiter_t *rl)
{
    return ratelimiter_allow_n(rl, 1);
}

bool ratelimiter_allow_n(ratelimiter_t *rl, u32 n)
{
    if (!rl) return false;
    
    u64 now = get_us_time();
    u64 elapsed = now - rl->last_update;
    
    rl->tokens = (rl->tokens + (u32)((elapsed * rl->rate) / 1000000));
    if (rl->tokens > rl->burst) rl->tokens = rl->burst;
    
    rl->last_update = now;
    
    if (rl->tokens >= n) {
        rl->tokens -= n;
        return true;
    }
    
    return false;
}

u32 ratelimiter_available(ratelimiter_t *rl)
{
    return rl ? rl->tokens : 0;
}

void ratelimiter_reset(ratelimiter_t *rl)
{
    if (!rl) return;
    rl->tokens = rl->burst;
    rl->last_update = get_us_time();
}

void ratelimiter_set_rate(ratelimiter_t *rl, u32 rate)
{
    if (!rl) return;
    rl->rate = rate;
}

void ratelimiter_set_burst(ratelimiter_t *rl, u32 burst)
{
    if (!rl) return;
    rl->burst = burst;
    if (rl->tokens > burst) rl->tokens = burst;
}

static u32 hash_ip(const void *key, u32 size)
{
    (void)size;
    return (u32)(uintptr_t)key;
}

static bool equal_ip(const void *a, const void *b)
{
    return a == b;
}

static void destroy_entry(void *key, void *value)
{
    (void)key;
    if (value) ngfw_free(value);
}

struct ratelimit_table {
    hash_table_t *hash;
    u32 max_entries;
    u32 rate;
    u32 burst;
    u64 last_cleanup;
};

ratelimit_table_t *ratelimit_table_create(u32 max_entries, u32 rate, u32 burst)
{
    ratelimit_table_t *table = ngfw_malloc(sizeof(ratelimit_table_t));
    if (!table) return NULL;
    
    table->hash = hash_create(max_entries, hash_ip, equal_ip, destroy_entry);
    if (!table->hash) {
        ngfw_free(table);
        return NULL;
    }
    
    table->max_entries = max_entries;
    table->rate = rate;
    table->burst = burst;
    table->last_cleanup = get_ms_time();
    
    return table;
}

void ratelimit_table_destroy(ratelimit_table_t *table)
{
    if (!table) return;
    if (table->hash) hash_destroy(table->hash);
    ngfw_free(table);
}

bool ratelimit_table_check(ratelimit_table_t *table, u32 ip)
{
    if (!table) return false;
    
    u64 now = get_ms_time();
    if (now - table->last_cleanup > 60000) {
        ratelimit_table_cleanup(table, now);
        table->last_cleanup = now;
    }
    
    ratelimit_entry_t *entry = hash_lookup(table->hash, (const void *)(uintptr_t)ip);
    
    if (!entry) {
        if (hash_size(table->hash) >= table->max_entries) {
            return false;
        }
        
        entry = ngfw_malloc(sizeof(ratelimit_entry_t));
        if (!entry) return false;
        
        entry->ip = ip;
        entry->tokens = table->burst;
        entry->last_update = now;
        entry->blocked = false;
        
        hash_insert(table->hash, (void *)(uintptr_t)ip, entry);
    }
    
    u64 elapsed = now - entry->last_update;
    entry->tokens = (entry->tokens + (u32)((elapsed * table->rate) / 1000));
    if (entry->tokens > table->burst) entry->tokens = table->burst;
    entry->last_update = now;
    
    if (entry->tokens > 0) {
        entry->tokens--;
        return true;
    }
    
    entry->blocked = true;
    return false;
}

void ratelimit_table_cleanup(ratelimit_table_t *table, u64 now)
{
    (void)now;
    if (!table) return;
}

u32 ratelimit_table_count(ratelimit_table_t *table)
{
    return table ? hash_size(table->hash) : 0;
}
