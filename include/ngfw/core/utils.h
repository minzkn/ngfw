/*
 * NGFW - Next-Generation Firewall
 * Copyright (C) 2024 NGFW Project
 */

#ifndef NGFW_CORE_UTILS_H
#define NGFW_CORE_UTILS_H

#include "ngfw/types.h"

/*
 * Core Utilities
 * Timer, string utilities, rate limiting
 */

/* High-resolution timer */
u64 get_ms_time(void);
u64 get_us_time(void);
u64 get_ns_time(void);

/* Timer wheel for efficient timeout management */
typedef struct timerwheel timerwheel_t;
typedef void (*timer_callback_t)(void *data);

timerwheel_t *timerwheel_create(u32 slots);
void timerwheel_destroy(timerwheel_t *tw);
ngfw_ret_t timerwheel_add(timerwheel_t *tw, u64 timeout_ms, timer_callback_t cb, void *data);
ngfw_ret_t timerwheel_remove(timerwheel_t *tw, void *data);
void timerwheel_tick(timerwheel_t *tw);

/* String utilities */
ngfw_ret_t str_copy(char *dst, const char *src, size_t dst_size);
ngfw_ret_t str_format(char *buf, size_t size, const char *fmt, ...);
bool str_starts_with(const char *str, const char *prefix);
bool str_ends_with(const char *str, const char *suffix);
char *str_trim(char *str);
u32 str_hash(const char *str);

/* Rate limiting */
typedef struct ratelimiter ratelimiter_t;

ratelimiter_t *ratelimiter_create(u32 rate, u32 burst);
void ratelimiter_destroy(ratelimiter_t *rl);
bool ratelimiter_allow(ratelimiter_t *rl, u32 tokens);
void ratelimiter_reset(ratelimiter_t *rl);

#endif
