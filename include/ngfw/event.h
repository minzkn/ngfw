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

#ifndef NGFW_EVENT_H
#define NGFW_EVENT_H

#include "types.h"
#include "list.h"
#include "hash.h"

typedef enum {
    EVENT_TYPE_PACKET,
    EVENT_TYPE_TIMER,
    EVENT_TYPE_SESSION_EXPIRE,
    EVENT_TYPE_CONFIG_CHANGE,
    EVENT_TYPE_LOG,
    EVENT_TYPE_ALERT,
    EVENT_TYPE_INTERFACE_CHANGE,
    EVENT_TYPE_SYSTEM
} event_type_t;

typedef enum {
    EVENT_PRIORITY_LOW,
    EVENT_PRIORITY_NORMAL,
    EVENT_PRIORITY_HIGH,
    EVENT_PRIORITY_CRITICAL
} event_priority_t;

typedef struct event {
    u32 id;
    event_type_t type;
    event_priority_t priority;
    u64 timestamp;
    void *data;
    void (*handler)(struct event *event);
    void (*destroy)(struct event *event);
} event_t;

typedef struct event_loop event_loop_t;

typedef void (*event_callback_t)(event_loop_t *loop, event_t *event, void *user_data);

event_loop_t *event_loop_create(u32 max_events);
void event_loop_destroy(event_loop_t *loop);

ngfw_ret_t event_loop_run(event_loop_t *loop);
ngfw_ret_t event_loop_stop(event_loop_t *loop);
ngfw_ret_t event_loop_add_event(event_loop_t *loop, event_t *event);

ngfw_ret_t event_loop_register_handler(event_loop_t *loop, event_type_t type, event_callback_t callback, void *user_data);

typedef struct scheduler scheduler_t;

typedef void (*scheduler_task_fn_t)(void *arg);

typedef struct scheduler_task_impl {
    u32 id;
    char name[64];
    scheduler_task_fn_t function;
    void *argument;
    u64 interval;
    u64 next_run;
    bool enabled;
    bool one_shot;
} scheduler_task_impl_t;

scheduler_t *scheduler_create(void);
void scheduler_destroy(scheduler_t *scheduler);

ngfw_ret_t scheduler_init(scheduler_t *scheduler);
ngfw_ret_t scheduler_start(scheduler_t *scheduler);
ngfw_ret_t scheduler_stop(scheduler_t *scheduler);

ngfw_ret_t scheduler_add_task(scheduler_t *scheduler, scheduler_task_impl_t *task);
ngfw_ret_t scheduler_del_task(scheduler_t *scheduler, u32 task_id);
ngfw_ret_t scheduler_enable_task(scheduler_t *scheduler, u32 task_id);
ngfw_ret_t scheduler_disable_task(scheduler_t *scheduler, u32 task_id);

ngfw_ret_t scheduler_run_once(scheduler_t *scheduler);

typedef struct timer wheel_timer_t;

typedef void (*timer_callback_t)(void *arg);

wheel_timer_t *wheel_timer_create(u32 num_buckets);
void wheel_timer_destroy(wheel_timer_t *timer);

ngfw_ret_t timer_start(wheel_timer_t *timer);
ngfw_ret_t timer_stop(wheel_timer_t *timer);

ngfw_ret_t timer_add_task(wheel_timer_t *timer, u32 id, u64 delay_ms, timer_callback_t callback, void *arg);
ngfw_ret_t timer_cancel(wheel_timer_t *timer, u32 id);
ngfw_ret_t timer_process(wheel_timer_t *timer);

typedef struct epoll_event_loop {
    int epoll_fd;
    int timer_fd;
    hash_table_t *handlers;
    bool running;
} epoll_event_loop_t;

epoll_event_loop_t *epoll_loop_create(void);
void epoll_loop_destroy(epoll_event_loop_t *loop);
ngfw_ret_t epoll_loop_add_fd(epoll_event_loop_t *loop, int fd, event_callback_t callback, void *user_data);
ngfw_ret_t epoll_loop_run(epoll_event_loop_t *loop);
ngfw_ret_t epoll_loop_stop(epoll_event_loop_t *loop);

#endif
