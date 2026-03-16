#include "ngfw/timerwheel.h"
#include "ngfw/memory.h"
#include "ngfw/platform.h"
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#define TIMER_WHEEL_SLOTS 256
#define TIMER_WHEEL_MASK 255

struct timer_wheel {
    timer_entry_t *slots[TIMER_WHEEL_SLOTS];
    u64 tick_ms;
    u64 current_time;
    u32 cursor;
    u32 active_timers;
};

timer_wheel_t *timer_wheel_create(u64 tick_ms)
{
    if (tick_ms == 0) tick_ms = 100;
    
    timer_wheel_t *wheel = ngfw_malloc(sizeof(timer_wheel_t));
    if (!wheel) return NULL;
    
    memset(wheel, 0, sizeof(timer_wheel_t));
    wheel->tick_ms = tick_ms;
    wheel->current_time = get_ms_time();
    wheel->cursor = wheel->current_time & TIMER_WHEEL_MASK;
    
    return wheel;
}

void timer_wheel_destroy(timer_wheel_t *wheel)
{
    if (!wheel) return;
    
    for (u32 i = 0; i < TIMER_WHEEL_SLOTS; i++) {
        timer_entry_t *entry = wheel->slots[i];
        while (entry) {
            timer_entry_t *next = entry->next;
            ngfw_free(entry);
            entry = next;
        }
    }
    
    ngfw_free(wheel);
}

timer_entry_t *timer_wheel_add_timer(timer_wheel_t *wheel, u64 interval_ms, timer_callback_t cb, void *arg)
{
    if (!wheel || !cb || interval_ms == 0) return NULL;
    
    timer_entry_t *entry = ngfw_malloc(sizeof(timer_entry_t));
    if (!entry) return NULL;
    
    entry->expires = wheel->current_time + interval_ms;
    entry->interval = interval_ms;
    entry->callback = cb;
    entry->arg = arg;
    entry->active = true;
    entry->next = NULL;
    
    u32 slot = entry->expires & TIMER_WHEEL_MASK;
    entry->next = wheel->slots[slot];
    wheel->slots[slot] = entry;
    wheel->active_timers++;
    
    return entry;
}

void timer_wheel_cancel_timer(timer_entry_t *entry)
{
    if (!entry) return;
    entry->active = false;
}

ngfw_ret_t timer_wheel_tick(timer_wheel_t *wheel)
{
    if (!wheel) return NGFW_ERR_INVALID;
    
    wheel->current_time = get_ms_time();
    u32 slot = wheel->cursor;
    
    timer_entry_t **prev = &wheel->slots[slot];
    timer_entry_t *entry = wheel->slots[slot];
    
    while (entry) {
        if (!entry->active || entry->expires > wheel->current_time) {
            prev = &entry->next;
            entry = entry->next;
            continue;
        }
        
        timer_callback_t cb = entry->callback;
        void *arg = entry->arg;
        u64 interval = entry->interval;
        
        *prev = entry->next;
        
        if (interval > 0) {
            entry->expires = wheel->current_time + interval;
            entry->next = wheel->slots[entry->expires & TIMER_WHEEL_MASK];
            wheel->slots[entry->expires & TIMER_WHEEL_MASK] = entry;
        } else {
            ngfw_free(entry);
            wheel->active_timers--;
        }
        
        if (cb) {
            cb(arg);
        }
        
        entry = *prev;
    }
    
    wheel->cursor = (wheel->cursor + 1) & TIMER_WHEEL_MASK;
    
    return NGFW_OK;
}

u64 timer_wheel_get_next_expiry(timer_wheel_t *wheel)
{
    if (!wheel) return 0;
    
    u32 search = wheel->cursor;
    for (u32 i = 0; i < TIMER_WHEEL_SLOTS; i++) {
        u32 slot = (search + i) & TIMER_WHEEL_MASK;
        timer_entry_t *entry = wheel->slots[slot];
        while (entry) {
            if (entry->active && entry->expires > wheel->current_time) {
                return entry->expires;
            }
            entry = entry->next;
        }
    }
    
    return 0;
}

u32 timer_wheel_get_active_timers(timer_wheel_t *wheel)
{
    return wheel ? wheel->active_timers : 0;
}
