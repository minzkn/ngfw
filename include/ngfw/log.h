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

#ifndef NGFW_LOG_H
#define NGFW_LOG_H

#include "types.h"
#include <stdarg.h>

typedef enum {
    LOG_EMERG = 0,
    LOG_ALERT = 1,
    LOG_CRIT = 2,
    LOG_ERR = 3,
    LOG_WARN = 4,
    LOG_NOTICE = 5,
    LOG_INFO = 6,
    LOG_DEBUG = 7
} log_level_t;

#define LOG_LEVEL_MAX LOG_DEBUG

void log_init(const char *filename);
void log_set_level(log_level_t level);
void log_set_syslog(bool enable);
void log_close(void);

void log_emerg(const char *fmt, ...);
void log_alert(const char *fmt, ...);
void log_crit(const char *fmt, ...);
void log_err(const char *fmt, ...);
void log_warn(const char *fmt, ...);
void log_notice(const char *fmt, ...);
void log_info(const char *fmt, ...);
void log_debug(const char *fmt, ...);

void log_write(log_level_t level, const char *fmt, va_list args);

#define log(level, ...) log_##level(__VA_ARGS__)

#endif
