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

#include "ngfw/types.h"
#include <pthread.h>

typedef struct spinlock {
    pthread_spinlock_t lock;
    volatile int locked;
} spinlock_t;

void spinlock_init(void *lock)
{
    pthread_spin_init((pthread_spinlock_t *)lock, PTHREAD_PROCESS_PRIVATE);
}

void spinlock_destroy(void *lock)
{
    pthread_spin_destroy((pthread_spinlock_t *)lock);
}

void spinlock_lock(void *lock)
{
    pthread_spin_lock((pthread_spinlock_t *)lock);
}

void spinlock_unlock(void *lock)
{
    pthread_spin_unlock((pthread_spinlock_t *)lock);
}

bool spinlock_trylock(void *lock)
{
    return pthread_spin_trylock((pthread_spinlock_t *)lock) == 0;
}
