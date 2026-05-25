/*
 * NGFW - Next-Generation Firewall
 * Copyright (C) 2024 NGFW Project
 */

#ifndef NGFW_CORE_SYNC_H
#define NGFW_CORE_SYNC_H

#include "ngfw/types.h"
#include <pthread.h>

/*
 * Synchronization Primitives
 * Spinlock, RW lock, barrier, once flag
 */

/* Spinlock (fast, short critical sections) */
typedef struct spinlock {
    pthread_spinlock_t lock;
} spinlock_t;

ngfw_ret_t spinlock_init(spinlock_t *lock);
void spinlock_destroy(spinlock_t *lock);
void spinlock_lock(spinlock_t *lock);
void spinlock_unlock(spinlock_t *lock);

/* Read-Write lock (for read-heavy workloads) */
typedef struct rwlock {
    pthread_rwlock_t lock;
} rwlock_t;

ngfw_ret_t rwlock_init(rwlock_t *lock);
void rwlock_destroy(rwlock_t *lock);
ngfw_ret_t rwlock_rdlock(rwlock_t *lock);
ngfw_ret_t rwlock_wrlock(rwlock_t *lock);
ngfw_ret_t rwlock_unlock(rwlock_t *lock);

/* Barrier (thread synchronization point) */
typedef struct barrier {
    pthread_mutex_t lock;
    pthread_cond_t cond;
    u32 count;
    u32 waiting;
} barrier_t;

barrier_t *barrier_create(u32 count);
void barrier_destroy(barrier_t *barrier);
ngfw_ret_t barrier_wait(barrier_t *barrier);

/* Once flag (one-time initialization) */
typedef struct once_flag {
    pthread_once_t flag;
} once_flag_t;

#define ONCE_FLAG_INIT { PTHREAD_ONCE_INIT }

void call_once(once_flag_t *flag, void (*init)(void));

/* Atomic reference counting */
typedef struct {
    volatile s32 count;
} refcount_t;

static inline void refcount_init(refcount_t *ref, s32 value)
{
    ref->count = value;
}

static inline s32 refcount_read(refcount_t *ref)
{
    return __atomic_load_n(&ref->count, __ATOMIC_SEQ_CST);
}

static inline void refcount_inc(refcount_t *ref)
{
    __atomic_fetch_add(&ref->count, 1, __ATOMIC_SEQ_CST);
}

static inline bool refcount_dec_and_test(refcount_t *ref)
{
    return __atomic_fetch_sub(&ref->count, 1, __ATOMIC_SEQ_CST) == 1;
}

static inline bool refcount_dec_and_zero(refcount_t *ref)
{
    return __atomic_fetch_sub(&ref->count, 1, __ATOMIC_SEQ_CST) <= 1;
}

#endif
