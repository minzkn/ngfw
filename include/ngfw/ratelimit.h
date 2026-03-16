#ifndef NGFW_RATELIMIT_H
#define NGFW_RATELIMIT_H

#include "ngfw/types.h"
#include <stddef.h>

typedef struct ratelimiter ratelimiter_t;

typedef enum {
    RATELIMIT_BURST,
    RATELIMIT_TOKEN_BUCKET
} ratelimit_algorithm_t;

ratelimiter_t *ratelimiter_create(ratelimit_algorithm_t algo, u32 rate, u32 burst);
void ratelimiter_destroy(ratelimiter_t *rl);
bool ratelimiter_allow(ratelimiter_t *rl);
bool ratelimiter_allow_n(ratelimiter_t *rl, u32 n);
u32 ratelimiter_available(ratelimiter_t *rl);
void ratelimiter_reset(ratelimiter_t *rl);
void ratelimiter_set_rate(ratelimiter_t *rl, u32 rate);
void ratelimiter_set_burst(ratelimiter_t *rl, u32 burst);

typedef struct ratelimit_entry {
    u32 ip;
    u32 tokens;
    u32 last_update;
    bool blocked;
} ratelimit_entry_t;

typedef struct ratelimit_table ratelimit_table_t;

ratelimit_table_t *ratelimit_table_create(u32 max_entries, u32 rate, u32 burst);
void ratelimit_table_destroy(ratelimit_table_t *table);
bool ratelimit_table_check(ratelimit_table_t *table, u32 ip);
void ratelimit_table_cleanup(ratelimit_table_t *table, u64 now);
u32 ratelimit_table_count(ratelimit_table_t *table);

#endif
