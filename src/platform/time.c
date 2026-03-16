#include "ngfw/platform.h"
#include <time.h>
#include <stddef.h>

u64 get_ticks_per_second(void)
{
    return 1000000000UL;
}

u64 get_tick_count(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (u64)ts.tv_sec * 1000000000UL + ts.tv_nsec;
}

u64 get_ms_time(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (u64)ts.tv_sec * 1000UL + ts.tv_nsec / 1000000UL;
}

u64 get_us_time(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (u64)ts.tv_sec * 1000000UL + ts.tv_nsec / 1000UL;
}

void sleep_ms(u32 ms)
{
    struct timespec ts;
    ts.tv_sec = ms / 1000;
    ts.tv_nsec = (ms % 1000) * 1000000;
    nanosleep(&ts, NULL);
}

void sleep_us(u32 us)
{
    struct timespec ts;
    ts.tv_sec = us / 1000000;
    ts.tv_nsec = (us % 1000000) * 1000;
    nanosleep(&ts, NULL);
}
