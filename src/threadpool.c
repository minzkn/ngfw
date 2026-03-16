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

#define _GNU_SOURCE
#include "ngfw/threadpool.h"
#include "ngfw/memory.h"
#include "ngfw/log.h"
#include "ngfw/platform.h"
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <sched.h>

#define DEFAULT_QUEUE_SIZE 4096

struct thread_pool {
    worker_thread_t *workers;
    u32 num_workers;
    ring_queue_t *queue;
    pthread_mutex_t state_lock;
    bool shutdown;
    bool initialized;
    u64 tasks_completed;
    u64 tasks_submitted;
};

static void *worker_routine(void *arg)
{
    worker_thread_t *worker = (worker_thread_t *)arg;
    thread_pool_t *pool = worker->pool;

    while (worker->running) {
        task_t *task = (task_t *)ring_queue_pop(pool->queue);

        if (!task) {
            if (worker->running) {
                usleep(1000);
            }
            continue;
        }

        task->start_time = get_us_time();
        task->function(task->argument);
        task->complete_time = get_us_time();

        __atomic_fetch_add(&pool->tasks_completed, 1, __ATOMIC_SEQ_CST);
    }

    return NULL;
}

thread_pool_t *thread_pool_create(u32 num_threads)
{
    thread_pool_t *pool = ngfw_malloc(sizeof(thread_pool_t));
    if (!pool) return NULL;

    pool->num_workers = num_threads > 0 ? num_threads : 4;
    pool->workers = ngfw_malloc(sizeof(worker_thread_t) * pool->num_workers);
    pool->queue = ring_queue_create(DEFAULT_QUEUE_SIZE);

    if (!pool->workers || !pool->queue) {
        if (pool->workers) ngfw_free(pool->workers);
        if (pool->queue) ring_queue_destroy(pool->queue);
        ngfw_free(pool);
        return NULL;
    }

    pthread_mutex_init(&pool->state_lock, NULL);
    pool->shutdown = false;
    pool->initialized = false;
    pool->tasks_completed = 0;
    pool->tasks_submitted = 0;

    return pool;
}

void thread_pool_destroy(thread_pool_t *pool)
{
    if (!pool) return;

    if (pool->initialized) {
        thread_pool_shutdown(pool);
    }

    for (u32 i = 0; i < pool->num_workers; i++) {
        ngfw_free(&pool->workers[i]);
    }

    ngfw_free(pool->workers);
    ring_queue_destroy(pool->queue);
    pthread_mutex_destroy(&pool->state_lock);
    ngfw_free(pool);
}

ngfw_ret_t thread_pool_init(thread_pool_t *pool)
{
    if (!pool) return NGFW_ERR_INVALID;

    for (u32 i = 0; i < pool->num_workers; i++) {
        pool->workers[i].pool = pool;
        pool->workers[i].id = i;
        pool->workers[i].running = true;

        if (pthread_create(&pool->workers[i].handle, NULL, worker_routine, &pool->workers[i]) != 0) {
            log_err("Failed to create worker thread %u", i);
            for (u32 j = 0; j < i; j++) {
                pool->workers[j].running = false;
            }
            return NGFW_ERR;
        }
    }

    pool->initialized = true;
    log_info("Thread pool initialized with %u workers", pool->num_workers);

    return NGFW_OK;
}

ngfw_ret_t thread_pool_shutdown(thread_pool_t *pool)
{
    if (!pool) return NGFW_ERR_INVALID;

    pthread_mutex_lock(&pool->state_lock);
    pool->shutdown = true;
    pthread_mutex_unlock(&pool->state_lock);

    for (u32 i = 0; i < pool->num_workers; i++) {
        pool->workers[i].running = false;
    }

    for (u32 i = 0; i < pool->num_workers; i++) {
        pthread_join(pool->workers[i].handle, NULL);
    }

    pool->initialized = false;
    log_info("Thread pool shutdown");

    return NGFW_OK;
}

ngfw_ret_t thread_pool_submit(thread_pool_t *pool, task_t *task)
{
    if (!pool || !task) return NGFW_ERR_INVALID;

    task->submit_time = get_us_time();

    ngfw_ret_t ret = ring_queue_push(pool->queue, task);
    if (ret == NGFW_OK) {
        __atomic_fetch_add(&pool->tasks_submitted, 1, __ATOMIC_SEQ_CST);
    }

    return ret;
}

ngfw_ret_t thread_pool_submit_fn(thread_pool_t *pool, void (*fn)(void *), void *arg)
{
    task_t task = {
        .function = fn,
        .argument = arg,
        .priority = TASK_PRIORITY_NORMAL,
        .submit_time = get_us_time()
    };

    return thread_pool_submit(pool, &task);
}

ngfw_ret_t thread_pool_wait(task_t *task)
{
    if (!task) return NGFW_ERR_INVALID;

    while (task->complete_time == 0) {
        usleep(100);
    }

    return NGFW_OK;
}

ngfw_ret_t thread_pool_wait_all(thread_pool_t *pool)
{
    if (!pool) return NGFW_ERR_INVALID;

    while (ring_queue_size(pool->queue) > 0) {
        usleep(100);
    }

    return NGFW_OK;
}

u32 thread_pool_get_active_count(thread_pool_t *pool)
{
    if (!pool) return 0;

    u32 active = 0;
    for (u32 i = 0; i < pool->num_workers; i++) {
        if (pool->workers[i].running) {
            active++;
        }
    }

    return active;
}

u32 thread_pool_get_queue_size(thread_pool_t *pool)
{
    return pool ? ring_queue_size(pool->queue) : 0;
}

ngfw_ret_t thread_set_affinity(affinity_t *affinity)
{
    if (!affinity) return NGFW_ERR_INVALID;

    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);

    for (u32 i = 0; i < 32; i++) {
        if (affinity->cpu_mask & (1 << i)) {
            CPU_SET(i, &cpuset);
        }
    }

    return pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset) == 0 ? NGFW_OK : NGFW_ERR;
}

ngfw_ret_t thread_get_affinity(affinity_t *affinity)
{
    if (!affinity) return NGFW_ERR_INVALID;

    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);

    if (pthread_getaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset) != 0) {
        return NGFW_ERR;
    }

    affinity->cpu_mask = 0;
    for (u32 i = 0; i < 32; i++) {
        if (CPU_ISSET(i, &cpuset)) {
            affinity->cpu_mask |= (1 << i);
        }
    }

    return NGFW_OK;
}

ring_queue_t *ring_queue_create(u32 size)
{
    ring_queue_t *queue = ngfw_malloc(sizeof(ring_queue_t));
    if (!queue) return NULL;

    queue->buffer = ngfw_malloc(sizeof(void *) * size);
    if (!queue->buffer) {
        ngfw_free(queue);
        return NULL;
    }

    queue->size = size;
    queue->head = 0;
    queue->tail = 0;
    queue->count = 0;

    pthread_mutex_init(&queue->lock, NULL);
    pthread_cond_init(&queue->not_empty, NULL);
    pthread_cond_init(&queue->not_full, NULL);

    return queue;
}

void ring_queue_destroy(ring_queue_t *queue)
{
    if (!queue) return;

    pthread_mutex_destroy(&queue->lock);
    pthread_cond_destroy(&queue->not_empty);
    pthread_cond_destroy(&queue->not_full);
    ngfw_free(queue->buffer);
    ngfw_free(queue);
}

ngfw_ret_t ring_queue_push(ring_queue_t *queue, void *item)
{
    if (!queue || !item) return NGFW_ERR_INVALID;

    pthread_mutex_lock(&queue->lock);

    if (queue->count >= queue->size) {
        pthread_mutex_unlock(&queue->lock);
        return NGFW_ERR_NO_RESOURCE;
    }

    queue->buffer[queue->tail] = item;
    queue->tail = (queue->tail + 1) % queue->size;
    queue->count++;

    pthread_cond_signal(&queue->not_empty);
    pthread_mutex_unlock(&queue->lock);

    return NGFW_OK;
}

void *ring_queue_pop(ring_queue_t *queue)
{
    if (!queue) return NULL;

    pthread_mutex_lock(&queue->lock);

    while (queue->count == 0) {
        pthread_cond_wait(&queue->not_empty, &queue->lock);
    }

    void *item = queue->buffer[queue->head];
    queue->head = (queue->head + 1) % queue->size;
    queue->count--;

    pthread_cond_signal(&queue->not_full);
    pthread_mutex_unlock(&queue->lock);

    return item;
}

u32 ring_queue_size(ring_queue_t *queue)
{
    if (!queue) return 0;

    pthread_mutex_lock(&queue->lock);
    u32 size = queue->count;
    pthread_mutex_unlock(&queue->lock);

    return size;
}

bool ring_queue_empty(ring_queue_t *queue)
{
    return queue && queue->count == 0;
}

bool ring_queue_full(ring_queue_t *queue)
{
    return queue && queue->count >= queue->size;
}

ngfw_ret_t thread_local_create(thread_local_t *tl, void (*destructor)(void *))
{
    if (!tl) return NGFW_ERR_INVALID;

    tl->destructor = destructor;
    return pthread_key_create(&tl->key, destructor) == 0 ? NGFW_OK : NGFW_ERR;
}

void thread_local_destroy(thread_local_t *tl)
{
    if (tl) {
        pthread_key_delete(tl->key);
    }
}

void *thread_local_get(thread_local_t *tl)
{
    if (!tl) return NULL;
    return pthread_getspecific(tl->key);
}

ngfw_ret_t thread_local_set(thread_local_t *tl, void *value)
{
    if (!tl) return NGFW_ERR_INVALID;
    return pthread_setspecific(tl->key, value) == 0 ? NGFW_OK : NGFW_ERR;
}

barrier_t *barrier_create(u32 count)
{
    barrier_t *barrier = ngfw_malloc(sizeof(barrier_t));
    if (!barrier) return NULL;

    pthread_mutex_init(&barrier->lock, NULL);
    pthread_cond_init(&barrier->cond, NULL);
    barrier->count = count;
    barrier->waiting = 0;

    return barrier;
}

void barrier_destroy(barrier_t *barrier)
{
    if (!barrier) return;

    pthread_mutex_destroy(&barrier->lock);
    pthread_cond_destroy(&barrier->cond);
    ngfw_free(barrier);
}

ngfw_ret_t barrier_wait(barrier_t *barrier)
{
    if (!barrier) return NGFW_ERR_INVALID;

    pthread_mutex_lock(&barrier->lock);
    barrier->waiting++;

    if (barrier->waiting >= barrier->count) {
        barrier->waiting = 0;
        pthread_cond_broadcast(&barrier->cond);
    } else {
        pthread_cond_wait(&barrier->cond, &barrier->lock);
    }

    pthread_mutex_unlock(&barrier->lock);
    return NGFW_OK;
}

void call_once(once_flag_t *flag, void (*init)(void))
{
    pthread_once(&flag->flag, init);
}

ngfw_ret_t rwlock_init(rwlock_t *rwlock)
{
    if (!rwlock) return NGFW_ERR_INVALID;
    return pthread_rwlock_init(&rwlock->lock, NULL) == 0 ? NGFW_OK : NGFW_ERR;
}

void rwlock_destroy(rwlock_t *rwlock)
{
    if (rwlock) {
        pthread_rwlock_destroy(&rwlock->lock);
    }
}

ngfw_ret_t rwlock_rdlock(rwlock_t *rwlock)
{
    if (!rwlock) return NGFW_ERR_INVALID;
    return pthread_rwlock_rdlock(&rwlock->lock) == 0 ? NGFW_OK : NGFW_ERR;
}

ngfw_ret_t rwlock_wrlock(rwlock_t *rwlock)
{
    if (!rwlock) return NGFW_ERR_INVALID;
    return pthread_rwlock_wrlock(&rwlock->lock) == 0 ? NGFW_OK : NGFW_ERR;
}

ngfw_ret_t rwlock_unlock(rwlock_t *rwlock)
{
    if (!rwlock) return NGFW_ERR_INVALID;
    return pthread_rwlock_unlock(&rwlock->lock) == 0 ? NGFW_OK : NGFW_ERR;
}

ngfw_ret_t spinlock_native_init(spinlock_native_t *lock)
{
    if (!lock) return NGFW_ERR_INVALID;
    return pthread_spin_init(&lock->lock, PTHREAD_PROCESS_PRIVATE) == 0 ? NGFW_OK : NGFW_ERR;
}

void spinlock_native_destroy(spinlock_native_t *lock)
{
    if (lock) {
        pthread_spin_destroy(&lock->lock);
    }
}

void spinlock_native_lock(spinlock_native_t *lock)
{
    if (lock) {
        pthread_spin_lock(&lock->lock);
    }
}

void spinlock_native_unlock(spinlock_native_t *lock)
{
    if (lock) {
        pthread_spin_unlock(&lock->lock);
    }
}
