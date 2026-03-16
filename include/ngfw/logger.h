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

#ifndef NGFW_LOGGER_H
#define NGFW_LOGGER_H

#include "types.h"
#include "log.h"

typedef enum {
    LOG_TARGET_CONSOLE,
    LOG_TARGET_FILE,
    LOG_TARGET_SYSLOG,
    LOG_TARGET_ROTATING
} log_target_t;

typedef struct logger_config {
    log_target_t target;
    char filename[256];
    u32 max_size;
    u32 max_files;
    log_level_t level;
    bool timestamp;
    bool colors;
    bool syslog_enabled;
    char syslog_ident[64];
    int syslog_facility;
} logger_config_t;

typedef struct logger logger_t;

logger_t *logger_create(const logger_config_t *config);
void logger_destroy(logger_t *logger);

ngfw_ret_t logger_init(logger_t *logger);
ngfw_ret_t logger_shutdown(logger_t *logger);

ngfw_ret_t logger_set_level(logger_t *logger, log_level_t level);
ngfw_ret_t logger_set_target(logger_t *logger, log_target_t target);

ngfw_ret_t logger_log(logger_t *logger, log_level_t level, const char *fmt, ...);
ngfw_ret_t logger_vlog(logger_t *logger, log_level_t level, const char *fmt, va_list args);

ngfw_ret_t logger_rotate(logger_t *logger);
bool logger_should_rotate(logger_t *logger);

typedef struct log_entry {
    u64 timestamp;
    log_level_t level;
    char message[1024];
    char source_file[128];
    u32 source_line;
} log_entry_t;

typedef struct log_buffer {
    log_entry_t *entries;
    u32 size;
    u32 head;
    u32 tail;
    u32 count;
} log_buffer_t;

log_buffer_t *log_buffer_create(u32 size);
void log_buffer_destroy(log_buffer_t *buffer);
ngfw_ret_t log_buffer_push(log_buffer_t *buffer, const log_entry_t *entry);
bool log_buffer_pop(log_buffer_t *buffer, log_entry_t *entry);
u32 log_buffer_count(log_buffer_t *buffer);

ngfw_ret_t logger_open_syslog(const char *ident, int facility);
ngfw_ret_t logger_close_syslog(void);
ngfw_ret_t logger_write_syslog(log_level_t level, const char *message);

#endif
