#ifndef NGFW_TIMERWHEEL_H
#define NGFW_TIMERWHEEL_H

#include "ngfw/types.h"
#include <stdbool.h>
#include <stddef.h>

typedef struct timer_wheel timer_wheel_t;
typedef void (*timer_callback_t)(void *arg);

typedef struct timer_entry {
    u64 expires;
    u64 interval;
    timer_callback_t callback;
    void *arg;
    bool active;
    struct timer_entry *next;
} timer_entry_t;

timer_wheel_t *timer_wheel_create(u64 tick_ms);
void timer_wheel_destroy(timer_wheel_t *wheel);
timer_entry_t *timer_wheel_add_timer(timer_wheel_t *wheel, u64 interval_ms, timer_callback_t cb, void *arg);
void timer_wheel_cancel_timer(timer_entry_t *entry);
ngfw_ret_t timer_wheel_tick(timer_wheel_t *wheel);
u64 timer_wheel_get_next_expiry(timer_wheel_t *wheel);
u32 timer_wheel_get_active_timers(timer_wheel_t *wheel);

#endif
