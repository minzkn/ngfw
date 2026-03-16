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

#ifndef NGFW_THREADPOOL_H
#define NGFW_THREADPOOL_H

#include "types.h"

typedef enum {
    TASK_PRIORITY_LOW,
    TASK_PRIORITY_NORMAL,
    TASK_PRIORITY_HIGH,
    TASK_PRIORITY_CRITICAL
} task_priority_t;

typedef struct task {
    void (*function)(void *);
    void *argument;
    task_priority_t priority;
    u64 submit_time;
    u64 start_time;
    u64 complete_time;
} task_t;

typedef struct thread_pool thread_pool_t;

typedef void (*task_callback_t)(void *result);

thread_pool_t *thread_pool_create(u32 num_threads);
void thread_pool_destroy(thread_pool_t *pool);

ngfw_ret_t thread_pool_init(thread_pool_t *pool);
ngfw_ret_t thread_pool_shutdown(thread_pool_t *pool);

ngfw_ret_t thread_pool_submit(thread_pool_t *pool, task_t *task);
ngfw_ret_t thread_pool_submit_fn(thread_pool_t *pool, void (*fn)(void *), void *arg);

ngfw_ret_t thread_pool_wait(task_t *task);
ngfw_ret_t thread_pool_wait_all(thread_pool_t *pool);

u32 thread_pool_get_active_count(thread_pool_t *pool);
u32 thread_pool_get_queue_size(thread_pool_t *pool);

typedef struct worker_thread {
    pthread_t handle;
    thread_pool_t *pool;
    u32 id;
    bool running;
} worker_thread_t;

typedef struct affinity {
    u32 cpu_mask;
    u32 numa_node;
} affinity_t;

ngfw_ret_t thread_set_affinity(affinity_t *affinity);
ngfw_ret_t thread_get_affinity(affinity_t *affinity);

typedef struct ring_queue {
    void **buffer;
    u32 size;
    u32 head;
    u32 tail;
    u32 count;
    pthread_mutex_t lock;
    pthread_cond_t not_empty;
    pthread_cond_t not_full;
} ring_queue_t;

ring_queue_t *ring_queue_create(u32 size);
void ring_queue_destroy(ring_queue_t *queue);
ngfw_ret_t ring_queue_push(ring_queue_t *queue, void *item);
void *ring_queue_pop(ring_queue_t *queue);
u32 ring_queue_size(ring_queue_t *queue);
bool ring_queue_empty(ring_queue_t *queue);
bool ring_queue_full(ring_queue_t *queue);

typedef struct thread_local {
    pthread_key_t key;
    void (*destructor)(void *);
} thread_local_t;

ngfw_ret_t thread_local_create(thread_local_t *tl, void (*destructor)(void *));
void thread_local_destroy(thread_local_t *tl);
void *thread_local_get(thread_local_t *tl);
ngfw_ret_t thread_local_set(thread_local_t *tl, void *value);

typedef struct barrier {
    pthread_mutex_t lock;
    pthread_cond_t cond;
    u32 count;
    u32 waiting;
} barrier_t;

barrier_t *barrier_create(u32 count);
void barrier_destroy(barrier_t *barrier);
ngfw_ret_t barrier_wait(barrier_t *barrier);

typedef struct once_flag {
    pthread_once_t flag;
} once_flag_t;

#define ONCE_FLAG_INIT { PTHREAD_ONCE_INIT }

void call_once(once_flag_t *flag, void (*init)(void));

typedef struct rwlock {
    pthread_rwlock_t lock;
} rwlock_t;

ngfw_ret_t rwlock_init(rwlock_t *rwlock);
void rwlock_destroy(rwlock_t *rwlock);
ngfw_ret_t rwlock_rdlock(rwlock_t *rwlock);
ngfw_ret_t rwlock_wrlock(rwlock_t *rwlock);
ngfw_ret_t rwlock_unlock(rwlock_t *rwlock);

typedef struct spinlock_native {
    pthread_spinlock_t lock;
} spinlock_native_t;

ngfw_ret_t spinlock_native_init(spinlock_native_t *lock);
void spinlock_native_destroy(spinlock_native_t *lock);
void spinlock_native_lock(spinlock_native_t *lock);
void spinlock_native_unlock(spinlock_native_t *lock);

#endif
