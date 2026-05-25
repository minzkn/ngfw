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
#include "ngfw/memory.h"
#include <pthread.h>
#include <stddef.h>

typedef struct thread {
    pthread_t handle;
    void *(*start_routine)(void *);
    void *arg;
    bool started;
} thread_t;

int thread_create(void **thread, void *(*start_routine)(void *), void *arg)
{
    if (!thread) return -1;
    
    thread_t *t = ngfw_malloc(sizeof(thread_t));
    if (!t) return -1;
    
    t->start_routine = start_routine;
    t->arg = arg;
    t->started = false;
    
    if (pthread_create(&t->handle, NULL, start_routine, arg) != 0) {
        ngfw_free(t);
        return -1;
    }
    
    t->started = true;
    *thread = t;
    return 0;
}

int thread_join(void *thread)
{
    if (!thread) return -1;
    
    thread_t *t = (thread_t *)thread;
    if (t->started) {
        pthread_join(t->handle, NULL);
    }
    ngfw_free(t);
    return 0;
}

void thread_exit(void *retval)
{
    pthread_exit(retval);
}

int thread_detach(void *thread)
{
    if (!thread) return -1;
    
    thread_t *t = (thread_t *)thread;
    if (t->started) {
        pthread_detach(t->handle);
    }
    ngfw_free(t);
    return 0;
}

typedef struct mutex {
    pthread_mutex_t handle;
} mutex_t;

int mutex_init(void **mutex)
{
    if (!mutex) return -1;
    
    mutex_t *m = ngfw_malloc(sizeof(mutex_t));
    if (!m) return -1;
    
    pthread_mutex_init(&m->handle, NULL);
    *mutex = m;
    return 0;
}

int mutex_destroy(void *mutex)
{
    if (!mutex) return -1;
    
    mutex_t *m = (mutex_t *)mutex;
    pthread_mutex_destroy(&m->handle);
    ngfw_free(m);
    return 0;
}

int mutex_lock(void *mutex)
{
    if (!mutex) return -1;
    
    mutex_t *m = (mutex_t *)mutex;
    return pthread_mutex_lock(&m->handle);
}

int mutex_unlock(void *mutex)
{
    if (!mutex) return -1;
    
    mutex_t *m = (mutex_t *)mutex;
    return pthread_mutex_unlock(&m->handle);
}

typedef struct cond {
    pthread_cond_t handle;
} cond_t;

int cond_init(void **cond)
{
    if (!cond) return -1;
    
    cond_t *c = ngfw_malloc(sizeof(cond_t));
    if (!c) return -1;
    
    pthread_cond_init(&c->handle, NULL);
    *cond = c;
    return 0;
}

int cond_destroy(void *cond)
{
    if (!cond) return -1;
    
    cond_t *c = (cond_t *)cond;
    pthread_cond_destroy(&c->handle);
    ngfw_free(c);
    return 0;
}

int cond_signal(void *cond)
{
    if (!cond) return -1;
    
    cond_t *c = (cond_t *)cond;
    return pthread_cond_signal(&c->handle);
}

int cond_broadcast(void *cond)
{
    if (!cond) return -1;
    
    cond_t *c = (cond_t *)cond;
    return pthread_cond_broadcast(&c->handle);
}

int cond_wait(void *cond, void *mutex)
{
    if (!cond || !mutex) return -1;
    
    cond_t *c = (cond_t *)cond;
    mutex_t *m = (mutex_t *)mutex;
    return pthread_cond_wait(&c->handle, &m->handle);
}
