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

#define _DEFAULT_SOURCE
#include "ngfw/asynclog.h"
#include "ngfw/memory.h"
#include "ngfw/ringbuffer.h"
#include "ngfw/platform.h"
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <time.h>
#include <unistd.h>

#define MAX_LOG_MESSAGE 512
#define MAX_LOG_QUEUE 8192

typedef struct log_entry {
    u64 timestamp;
    async_log_level_t level;
    char message[MAX_LOG_MESSAGE];
} log_entry_t;

struct async_logger {
    ringbuffer_t *queue;
    pthread_t worker;
    bool running;
    FILE *output;
    pthread_mutex_t lock;
};

static const char *level_strings[] = {
    "DEBUG", "INFO", "WARN", "ERROR"
};

static void *log_worker(void *arg)
{
    async_logger_t *logger = (async_logger_t *)arg;
    log_entry_t entry;
    
    while (logger->running) {
        if (ringbuffer_pop(logger->queue, &entry, sizeof(log_entry_t))) {
            time_t t = entry.timestamp;
            struct tm *tm = localtime(&t);
            char time_str[32];
            strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm);
            
            pthread_mutex_lock(&logger->lock);
            if (logger->output) {
                fprintf(logger->output, "[%s] [%s] %s\n", 
                        time_str, level_strings[entry.level], entry.message);
                fflush(logger->output);
            }
            pthread_mutex_unlock(&logger->lock);
        } else {
            usleep(1000);
        }
    }
    
    return NULL;
}

async_logger_t *async_logger_create(u32 queue_size)
{
    if (queue_size == 0) queue_size = MAX_LOG_QUEUE;
    
    async_logger_t *logger = ngfw_malloc(sizeof(async_logger_t));
    if (!logger) return NULL;
    
    logger->queue = ringbuffer_create(queue_size * sizeof(log_entry_t));
    if (!logger->queue) {
        ngfw_free(logger);
        return NULL;
    }
    
    logger->output = NULL;
    logger->running = false;
    pthread_mutex_init(&logger->lock, NULL);
    
    return logger;
}

void async_logger_destroy(async_logger_t *logger)
{
    if (!logger) return;
    
    async_logger_stop(logger);
    
    pthread_mutex_destroy(&logger->lock);
    ringbuffer_destroy(logger->queue);
    
    if (logger->output && logger->output != stdout && logger->output != stderr) {
        fclose(logger->output);
    }
    
    ngfw_free(logger);
}

ngfw_ret_t async_logger_log(async_logger_t *logger, async_log_level_t level, const char *fmt, ...)
{
    if (!logger || !fmt) return NGFW_ERR_INVALID;
    
    log_entry_t entry;
    entry.timestamp = get_ms_time() / 1000;
    entry.level = level;
    
    va_list args;
    va_start(args, fmt);
    vsnprintf(entry.message, sizeof(entry.message), fmt, args);
    va_end(args);
    
    if (ringbuffer_push(logger->queue, &entry, sizeof(log_entry_t))) {
        return NGFW_OK;
    }
    
    return NGFW_ERR_NO_RESOURCE;
}

ngfw_ret_t async_logger_start(async_logger_t *logger)
{
    if (!logger) return NGFW_ERR_INVALID;
    if (logger->running) return NGFW_OK;
    
    logger->running = true;
    
    if (pthread_create(&logger->worker, NULL, log_worker, logger) != 0) {
        logger->running = false;
        return NGFW_ERR;
    }
    
    return NGFW_OK;
}

void async_logger_stop(async_logger_t *logger)
{
    if (!logger || !logger->running) return;
    
    logger->running = false;
    pthread_join(logger->worker, NULL);
}

u32 async_logger_queue_size(async_logger_t *logger)
{
    if (!logger || !logger->queue) return 0;
    return ringbuffer_capacity(logger->queue) / sizeof(log_entry_t);
}

u32 async_logger_queued(async_logger_t *logger)
{
    if (!logger || !logger->queue) return 0;
    return ringbuffer_available(logger->queue) / sizeof(log_entry_t);
}
