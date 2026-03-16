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

#ifndef NGFW_ASYNCLOG_H
#define NGFW_ASYNCLOG_H

#include "ngfw/types.h"
#include <stdbool.h>
#include <stddef.h>

typedef struct async_logger async_logger_t;

typedef enum {
    ASYNC_LOG_DEBUG,
    ASYNC_LOG_INFO,
    ASYNC_LOG_WARN,
    ASYNC_LOG_ERROR
} async_log_level_t;

async_logger_t *async_logger_create(u32 queue_size);
void async_logger_destroy(async_logger_t *logger);
ngfw_ret_t async_logger_log(async_logger_t *logger, async_log_level_t level, const char *fmt, ...);
ngfw_ret_t async_logger_start(async_logger_t *logger);
void async_logger_stop(async_logger_t *logger);
u32 async_logger_queue_size(async_logger_t *logger);
u32 async_logger_queued(async_logger_t *logger);

#endif
