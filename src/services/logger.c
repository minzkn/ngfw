#include "ngfw/logger.h"
#include "ngfw/memory.h"
#include "ngfw/log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <pthread.h>
#include <errno.h>

#ifdef LOG_USE_SYSLOG
#include <syslog.h>
#endif

static const char *level_strings[] = {
    "EMERG", "ALERT", "CRIT", "ERR", "WARN", "NOTICE", "INFO", "DEBUG"
};

static const char *level_colors[] = {
    "\033[1;31m", "\033[1;35m", "\033[1;31m", "\033[0;31m",
    "\033[0;33m", "\033[0;36m", "\033[0;32m", "\033[0;34m"
};

static const char *color_reset = "\033[0m";

struct logger {
    logger_config_t config;
    FILE *file;
    int syslog_fd;
    pthread_mutex_t lock;
    u64 bytes_written;
    u32 current_file;
    bool initialized;
};

logger_t *logger_create(const logger_config_t *config)
{
    logger_t *logger = ngfw_malloc(sizeof(logger_t));
    if (!logger) return NULL;

    if (config) {
        memcpy(&logger->config, config, sizeof(logger_config_t));
    } else {
        memset(&logger->config, 0, sizeof(logger_config_t));
        logger->config.target = LOG_TARGET_CONSOLE;
        logger->config.level = LOG_INFO;
        logger->config.timestamp = true;
        logger->config.max_size = 10 * 1024 * 1024;
        logger->config.max_files = 5;
    }

    logger->file = NULL;
    logger->syslog_fd = -1;
    logger->bytes_written = 0;
    logger->current_file = 0;
    logger->initialized = false;

    pthread_mutex_init(&logger->lock, NULL);

    return logger;
}

void logger_destroy(logger_t *logger)
{
    if (!logger) return;

    if (logger->initialized) {
        logger_shutdown(logger);
    }

    pthread_mutex_destroy(&logger->lock);
    ngfw_free(logger);
}

ngfw_ret_t logger_init(logger_t *logger)
{
    if (!logger) return NGFW_ERR_INVALID;

    pthread_mutex_lock(&logger->lock);

    switch (logger->config.target) {
        case LOG_TARGET_FILE:
        case LOG_TARGET_ROTATING:
            logger->file = fopen(logger->config.filename, "a");
            if (!logger->file) {
                pthread_mutex_unlock(&logger->lock);
                return NGFW_ERR_INVALID;
            }
            break;

        case LOG_TARGET_SYSLOG:
#ifdef LOG_USE_SYSLOG
            openlog(logger->config.syslog_ident ? logger->config.syslog_ident : "ngfw",
                    LOG_PID, logger->config.syslog_facility ? logger->config.syslog_facility : LOG_DAEMON);
#else
            logger->syslog_fd = open("/dev/log", O_WRONLY | O_NONBLOCK);
#endif
            break;

        default:
            break;
    }

    logger->initialized = true;
    pthread_mutex_unlock(&logger->lock);

    return NGFW_OK;
}

ngfw_ret_t logger_shutdown(logger_t *logger)
{
    if (!logger) return NGFW_ERR_INVALID;

    pthread_mutex_lock(&logger->lock);

    if (logger->file) {
        fclose(logger->file);
        logger->file = NULL;
    }

#ifdef LOG_USE_SYSLOG
    closelog();
#else
    if (logger->syslog_fd >= 0) {
        close(logger->syslog_fd);
        logger->syslog_fd = -1;
    }
#endif

    logger->initialized = false;
    pthread_mutex_unlock(&logger->lock);

    return NGFW_OK;
}

ngfw_ret_t logger_set_level(logger_t *logger, log_level_t level)
{
    if (!logger) return NGFW_ERR_INVALID;

    pthread_mutex_lock(&logger->lock);
    logger->config.level = level;
    pthread_mutex_unlock(&logger->lock);

    return NGFW_OK;
}

ngfw_ret_t logger_set_target(logger_t *logger, log_target_t target)
{
    if (!logger) return NGFW_ERR_INVALID;

    pthread_mutex_lock(&logger->lock);

    if (logger->file) {
        fclose(logger->file);
        logger->file = NULL;
    }

    logger->config.target = target;
    pthread_mutex_unlock(&logger->lock);

    return NGFW_OK;
}

bool logger_should_rotate(logger_t *logger)
{
    if (!logger) return false;

    if (logger->config.target == LOG_TARGET_ROTATING &&
        logger->config.max_size > 0 &&
        logger->bytes_written >= logger->config.max_size) {
        return true;
    }

    return false;
}

ngfw_ret_t logger_rotate(logger_t *logger)
{
    if (!logger || logger->config.target != LOG_TARGET_ROTATING) {
        return NGFW_ERR_INVALID;
    }

    pthread_mutex_lock(&logger->lock);

    if (logger->file) {
        fclose(logger->file);
        logger->file = NULL;
    }

    for (int i = logger->config.max_files - 1; i >= 1; i--) {
        char old_name[512];
        char new_name[512];
        snprintf(old_name, sizeof(old_name), "%s.%d", logger->config.filename, i - 1);
        snprintf(new_name, sizeof(new_name), "%s.%d", logger->config.filename, i);
        rename(old_name, new_name);
    }

    char rotated[512];
    snprintf(rotated, sizeof(rotated), "%s.0", logger->config.filename);
    rename(logger->config.filename, rotated);

    logger->file = fopen(logger->config.filename, "a");
    logger->bytes_written = 0;
    logger->current_file = 0;

    pthread_mutex_unlock(&logger->lock);

    return NGFW_OK;
}

static void format_timestamp(char *buf, size_t len)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);

    struct tm *tm = localtime(&tv.tv_sec);
    snprintf(buf, len, "%04d-%02d-%02d %02d:%02d:%02d.%06ld",
             tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
             tm->tm_hour, tm->tm_min, tm->tm_sec, tv.tv_usec);
}

ngfw_ret_t logger_log(logger_t *logger, log_level_t level, const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    ngfw_ret_t ret = logger_vlog(logger, level, fmt, args);
    va_end(args);
    return ret;
}

ngfw_ret_t logger_vlog(logger_t *logger, log_level_t level, const char *fmt, va_list args)
{
    if (!logger || !logger->initialized) return NGFW_ERR_INVALID;
    if (level > logger->config.level) return NGFW_OK;

    char message[2048];
    vsnprintf(message, sizeof(message), fmt, args);

    pthread_mutex_lock(&logger->lock);

    if (logger_should_rotate(logger)) {
        logger_rotate(logger);
    }

    char timestamp[64] = "";
    if (logger->config.timestamp) {
        format_timestamp(timestamp, sizeof(timestamp));
    }

    switch (logger->config.target) {
        case LOG_TARGET_CONSOLE:
            if (logger->config.colors) {
                fprintf(stderr, "%s[%s%s%s] %s%s\n",
                        timestamp,
                        level_colors[level], level_strings[level], color_reset,
                        color_reset, message);
            } else {
                fprintf(stderr, "[%s] [%s] %s\n", timestamp, level_strings[level], message);
            }
            break;

        case LOG_TARGET_FILE:
        case LOG_TARGET_ROTATING:
            if (logger->file) {
                fprintf(logger->file, "[%s] [%s] %s\n",
                        timestamp, level_strings[level], message);
                fflush(logger->file);
            }
            break;

        case LOG_TARGET_SYSLOG:
#ifdef LOG_USE_SYSLOG
            syslog(level, "%s", message);
#else
            if (logger->syslog_fd >= 0) {
                char syslog_msg[2048];
                snprintf(syslog_msg, sizeof(syslog_msg), "[%s] %s\n",
                         level_strings[level], message);
                ssize_t written = write(logger->syslog_fd, syslog_msg, strlen(syslog_msg));
                (void)written;
            }
#endif
            break;
    }

    logger->bytes_written += strlen(message);

    pthread_mutex_unlock(&logger->lock);

    return NGFW_OK;
}

log_buffer_t *log_buffer_create(u32 size)
{
    log_buffer_t *buffer = ngfw_malloc(sizeof(log_buffer_t));
    if (!buffer) return NULL;

    buffer->entries = ngfw_malloc(sizeof(log_entry_t) * size);
    if (!buffer->entries) {
        ngfw_free(buffer);
        return NULL;
    }

    buffer->size = size;
    buffer->head = 0;
    buffer->tail = 0;
    buffer->count = 0;

    return buffer;
}

void log_buffer_destroy(log_buffer_t *buffer)
{
    if (!buffer) return;
    ngfw_free(buffer->entries);
    ngfw_free(buffer);
}

ngfw_ret_t log_buffer_push(log_buffer_t *buffer, const log_entry_t *entry)
{
    if (!buffer || !entry) return NGFW_ERR_INVALID;

    if (buffer->count >= buffer->size) {
        return NGFW_ERR_NO_RESOURCE;
    }

    memcpy(&buffer->entries[buffer->tail], entry, sizeof(log_entry_t));
    buffer->tail = (buffer->tail + 1) % buffer->size;
    buffer->count++;

    return NGFW_OK;
}

bool log_buffer_pop(log_buffer_t *buffer, log_entry_t *entry)
{
    if (!buffer || buffer->count == 0) return false;

    if (entry) {
        memcpy(entry, &buffer->entries[buffer->head], sizeof(log_entry_t));
    }

    buffer->head = (buffer->head + 1) % buffer->size;
    buffer->count--;

    return true;
}

u32 log_buffer_count(log_buffer_t *buffer)
{
    return buffer ? buffer->count : 0;
}

ngfw_ret_t logger_open_syslog(const char *ident, int facility)
{
#ifdef LOG_USE_SYSLOG
    openlog(ident ? ident : "ngfw", LOG_PID, facility ? facility : LOG_DAEMON);
    return NGFW_OK;
#else
    (void)ident;
    (void)facility;
    return NGFW_ERR_NOT_SUPPORTED;
#endif
}

ngfw_ret_t logger_close_syslog(void)
{
#ifdef LOG_USE_SYSLOG
    closelog();
    return NGFW_OK;
#else
    return NGFW_ERR_NOT_SUPPORTED;
#endif
}

ngfw_ret_t logger_write_syslog(log_level_t level, const char *message)
{
#ifdef LOG_USE_SYSLOG
    syslog(level, "%s", message);
    return NGFW_OK;
#else
    (void)level;
    (void)message;
    return NGFW_ERR_NOT_SUPPORTED;
#endif
}
