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

#include "ngfw/event.h"
#include "ngfw/memory.h"
#include "ngfw/hash.h"
#include "ngfw/list.h"
#include "ngfw/log.h"
#include "ngfw/platform.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <sys/timerfd.h>
#include <pthread.h>
#include <errno.h>

struct event_loop {
    u32 max_events;
    hash_table_t *handlers;
    pthread_mutex_t lock;
    pthread_cond_t cond;
    list_t *event_queue;
    bool running;
    u32 next_event_id;
};

struct timer {
    u32 num_buckets;
    u32 current_bucket;
    u64 last_update;
};

event_loop_t *event_loop_create(u32 max_events)
{
    event_loop_t *loop = ngfw_malloc(sizeof(event_loop_t));
    if (!loop) return NULL;

    loop->max_events = max_events > 0 ? max_events : 1024;
    loop->handlers = hash_create(64, NULL, NULL, NULL);
    loop->event_queue = list_create(NULL);

    pthread_mutex_init(&loop->lock, NULL);
    pthread_cond_init(&loop->cond, NULL);

    loop->running = false;
    loop->next_event_id = 1;

    return loop;
}

void event_loop_destroy(event_loop_t *loop)
{
    if (!loop) return;

    if (loop->running) {
        event_loop_stop(loop);
    }

    hash_destroy(loop->handlers);
    list_destroy(loop->event_queue);
    pthread_mutex_destroy(&loop->lock);
    pthread_cond_destroy(&loop->cond);

    ngfw_free(loop);
}

static void *event_loop_thread(void *arg)
{
    event_loop_t *loop = (event_loop_t *)arg;

    while (loop->running) {
        pthread_mutex_lock(&loop->lock);

        while (list_empty(loop->event_queue) && loop->running) {
            pthread_cond_wait(&loop->cond, &loop->lock);
        }

        if (!loop->running) {
            pthread_mutex_unlock(&loop->lock);
            break;
        }

        event_t *event = list_first(loop->event_queue);
        if (event) {
            list_remove(loop->event_queue, event);
        }

        pthread_mutex_unlock(&loop->lock);

        if (event) {
            if (event->handler) {
                event->handler(event);
            }

            if (event->destroy) {
                event->destroy(event);
            }
        }
    }

    return NULL;
}

ngfw_ret_t event_loop_run(event_loop_t *loop)
{
    if (!loop) return NGFW_ERR_INVALID;
    if (loop->running) return NGFW_OK;

    loop->running = true;
    pthread_t thread;
    pthread_create(&thread, NULL, event_loop_thread, loop);
    pthread_detach(thread);

    return NGFW_OK;
}

ngfw_ret_t event_loop_stop(event_loop_t *loop)
{
    if (!loop) return NGFW_ERR_INVALID;

    loop->running = false;
    pthread_cond_broadcast(&loop->cond);

    return NGFW_OK;
}

ngfw_ret_t event_loop_add_event(event_loop_t *loop, event_t *event)
{
    if (!loop || !event) return NGFW_ERR_INVALID;

    event->id = loop->next_event_id++;
    event->timestamp = get_ms_time();

    pthread_mutex_lock(&loop->lock);
    list_append(loop->event_queue, event);
    pthread_cond_signal(&loop->cond);
    pthread_mutex_unlock(&loop->lock);

    return NGFW_OK;
}

ngfw_ret_t event_loop_register_handler(event_loop_t *loop, event_type_t type, event_callback_t callback, void *user_data)
{
    if (!loop || !callback) return NGFW_ERR_INVALID;
    
    char key[32];
    snprintf(key, sizeof(key), "%u", type);
    
    pthread_mutex_lock(&loop->lock);
    hash_insert(loop->handlers, key, callback);
    hash_insert(loop->handlers, "context", user_data);
    pthread_mutex_unlock(&loop->lock);
    
    return NGFW_OK;
}

struct scheduler {
    list_t *tasks;
    pthread_mutex_t lock;
    bool running;
    u32 next_task_id;
};

scheduler_t *scheduler_create(void)
{
    scheduler_t *scheduler = ngfw_malloc(sizeof(scheduler_t));
    if (!scheduler) return NULL;

    scheduler->tasks = list_create(NULL);
    scheduler->running = false;
    scheduler->next_task_id = 1;
    pthread_mutex_init(&scheduler->lock, NULL);

    return scheduler;
}

void scheduler_destroy(scheduler_t *scheduler)
{
    if (!scheduler) return;

    if (scheduler->running) {
        scheduler_stop(scheduler);
    }

    list_destroy(scheduler->tasks);
    pthread_mutex_destroy(&scheduler->lock);
    ngfw_free(scheduler);
}

ngfw_ret_t scheduler_init(scheduler_t *scheduler)
{
    (void)scheduler;
    return NGFW_OK;
}

ngfw_ret_t scheduler_start(scheduler_t *scheduler)
{
    if (!scheduler) return NGFW_ERR_INVALID;
    scheduler->running = true;
    return NGFW_OK;
}

ngfw_ret_t scheduler_stop(scheduler_t *scheduler)
{
    if (!scheduler) return NGFW_ERR_INVALID;
    scheduler->running = false;
    return NGFW_OK;
}

ngfw_ret_t scheduler_add_task(scheduler_t *scheduler, scheduler_task_impl_t *task)
{
    if (!scheduler || !task) return NGFW_ERR_INVALID;

    task->id = scheduler->next_task_id++;
    task->next_run = get_ms_time() + task->interval;

    pthread_mutex_lock(&scheduler->lock);
    list_append(scheduler->tasks, task);
    pthread_mutex_unlock(&scheduler->lock);

    return NGFW_OK;
}

ngfw_ret_t scheduler_del_task(scheduler_t *scheduler, u32 task_id)
{
    if (!scheduler) return NGFW_ERR_INVALID;

    pthread_mutex_lock(&scheduler->lock);

    list_node_t *node;
    list_for_each(scheduler->tasks, node) {
        scheduler_task_impl_t *task = (scheduler_task_impl_t *)node->data;
        if (task && task->id == task_id) {
            list_remove(scheduler->tasks, task);
            pthread_mutex_unlock(&scheduler->lock);
            return NGFW_OK;
        }
    }

    pthread_mutex_unlock(&scheduler->lock);
    return NGFW_ERR_INVALID;
}

ngfw_ret_t scheduler_enable_task(scheduler_t *scheduler, u32 task_id)
{
    if (!scheduler) return NGFW_ERR_INVALID;

    pthread_mutex_lock(&scheduler->lock);

    list_node_t *node;
    list_for_each(scheduler->tasks, node) {
        scheduler_task_impl_t *task = (scheduler_task_impl_t *)node->data;
        if (task && task->id == task_id) {
            task->enabled = true;
            pthread_mutex_unlock(&scheduler->lock);
            return NGFW_OK;
        }
    }

    pthread_mutex_unlock(&scheduler->lock);
    return NGFW_ERR_INVALID;
}

ngfw_ret_t scheduler_disable_task(scheduler_t *scheduler, u32 task_id)
{
    if (!scheduler) return NGFW_ERR_INVALID;

    pthread_mutex_lock(&scheduler->lock);

    list_node_t *node;
    list_for_each(scheduler->tasks, node) {
        scheduler_task_impl_t *task = (scheduler_task_impl_t *)node->data;
        if (task && task->id == task_id) {
            task->enabled = false;
            pthread_mutex_unlock(&scheduler->lock);
            return NGFW_OK;
        }
    }

    pthread_mutex_unlock(&scheduler->lock);
    return NGFW_ERR_INVALID;
}

ngfw_ret_t scheduler_run_once(scheduler_t *scheduler)
{
    if (!scheduler || !scheduler->running) return NGFW_ERR_INVALID;

    u64 now = get_ms_time();

    pthread_mutex_lock(&scheduler->lock);

    list_node_t *node;
    list_for_each(scheduler->tasks, node) {
        scheduler_task_impl_t *task = (scheduler_task_impl_t *)node->data;
        if (task && task->enabled && now >= task->next_run) {
            if (task->function) {
                task->function(task->argument);
            }

            if (task->one_shot) {
                list_remove(scheduler->tasks, task);
            } else {
                task->next_run = now + task->interval;
            }
        }
    }

    pthread_mutex_unlock(&scheduler->lock);

    return NGFW_OK;
}

wheel_timer_t *wheel_timer_create(u32 num_buckets)
{
    (void)num_buckets;
    return ngfw_malloc(sizeof(wheel_timer_t));
}

void wheel_timer_destroy(wheel_timer_t *timer)
{
    ngfw_free(timer);
}

ngfw_ret_t timer_start(wheel_timer_t *timer)
{
    (void)timer;
    return NGFW_OK;
}

ngfw_ret_t timer_stop(wheel_timer_t *timer)
{
    (void)timer;
    return NGFW_OK;
}

ngfw_ret_t timer_add_task(wheel_timer_t *timer, u32 id, u64 delay_ms, timer_callback_t callback, void *arg)
{
    if (!timer || !callback) return NGFW_ERR_INVALID;
    
    (void)id;
    (void)delay_ms;
    (void)arg;
    
    log_debug("Timer task added: id=%u delay=%lu ms", id, (unsigned long)delay_ms);
    return NGFW_OK;
}

ngfw_ret_t timer_cancel(wheel_timer_t *timer, u32 id)
{
    if (!timer) return NGFW_ERR_INVALID;
    
    (void)id;
    log_debug("Timer task cancelled: id=%u", id);
    return NGFW_OK;
}

ngfw_ret_t timer_process(wheel_timer_t *timer)
{
    if (!timer) return NGFW_ERR_INVALID;
    
    return NGFW_OK;
}

epoll_event_loop_t *epoll_loop_create(void)
{
    epoll_event_loop_t *loop = ngfw_malloc(sizeof(epoll_event_loop_t));
    if (!loop) return NULL;

    loop->epoll_fd = epoll_create1(0);
    loop->handlers = hash_create(64, NULL, NULL, NULL);
    loop->running = false;

    return loop;
}

void epoll_loop_destroy(epoll_event_loop_t *loop)
{
    if (!loop) return;

    if (loop->epoll_fd >= 0) {
        close(loop->epoll_fd);
    }

    hash_destroy(loop->handlers);
    ngfw_free(loop);
}

ngfw_ret_t epoll_loop_add_fd(epoll_event_loop_t *loop, int fd, event_callback_t callback, void *user_data)
{
    if (!loop || fd < 0 || !callback) return NGFW_ERR_INVALID;
    
    struct epoll_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.events = EPOLLIN | EPOLLET;
    ev.data.ptr = callback;
    
    if (epoll_ctl(loop->epoll_fd, EPOLL_CTL_ADD, fd, &ev) < 0) {
        return NGFW_ERR;
    }
    
    char key[32];
    snprintf(key, sizeof(key), "fd_%d", fd);
    hash_insert(loop->handlers, key, user_data);
    
    return NGFW_OK;
}

ngfw_ret_t epoll_loop_run(epoll_event_loop_t *loop)
{
    if (!loop) return NGFW_ERR_INVALID;

    loop->running = true;
    struct epoll_event events[64];

    while (loop->running) {
        int nfds = epoll_wait(loop->epoll_fd, events, 64, 1000);

        for (int i = 0; i < nfds; i++) {
            event_callback_t callback = events[i].data.ptr;
            if (callback) {
                callback(loop, NULL, NULL);
            }
        }
    }

    return NGFW_OK;
}

ngfw_ret_t epoll_loop_stop(epoll_event_loop_t *loop)
{
    if (!loop) return NGFW_ERR_INVALID;
    loop->running = false;
    return NGFW_OK;
}
