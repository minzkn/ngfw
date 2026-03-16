#include "ngfw/log.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <sys/time.h>

static FILE *log_file = NULL;
static log_level_t log_level = LOG_INFO;
static pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;
static bool log_initialized = false;

static const char *level_strings[] = {
    "EMERG", "ALERT", "CRIT", "ERR", "WARN", "NOTICE", "INFO", "DEBUG"
};

void log_init(const char *filename)
{
    pthread_mutex_lock(&log_mutex);
    
    if (log_initialized && log_file && log_file != stderr) {
        fclose(log_file);
    }
    
    if (filename) {
        log_file = fopen(filename, "a");
        if (!log_file) {
            log_file = stderr;
        }
    } else {
        log_file = stderr;
    }
    
    log_initialized = true;
    pthread_mutex_unlock(&log_mutex);
}

void log_set_level(log_level_t level)
{
    log_level = level;
}

void log_set_syslog(bool enable)
{
    (void)enable;
}

void log_close(void)
{
    pthread_mutex_lock(&log_mutex);
    
    if (log_file && log_file != stderr) {
        fclose(log_file);
    }
    log_file = NULL;
    log_initialized = false;
    
    pthread_mutex_unlock(&log_mutex);
}

void log_write(log_level_t level, const char *fmt, va_list args)
{
    if (level > log_level) return;
    if (!log_initialized) log_init(NULL);
    
    pthread_mutex_lock(&log_mutex);
    
    struct timeval tv;
    gettimeofday(&tv, NULL);
    
    struct tm *tm = localtime(&tv.tv_sec);
    char timestamp[64];
    snprintf(timestamp, sizeof(timestamp), "%04d-%02d-%02d %02d:%02d:%02d.%06ld",
             tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
             tm->tm_hour, tm->tm_min, tm->tm_sec, tv.tv_usec);
    
    if (log_file) {
        fprintf(log_file, "[%s] [%s] ", timestamp, level_strings[level]);
        vfprintf(log_file, fmt, args);
        fprintf(log_file, "\n");
        fflush(log_file);
    }
    
    pthread_mutex_unlock(&log_mutex);
}

void log_emerg(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    log_write(LOG_EMERG, fmt, args);
    va_end(args);
}

void log_alert(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    log_write(LOG_ALERT, fmt, args);
    va_end(args);
}

void log_crit(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    log_write(LOG_CRIT, fmt, args);
    va_end(args);
}

void log_err(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    log_write(LOG_ERR, fmt, args);
    va_end(args);
}

void log_warn(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    log_write(LOG_WARN, fmt, args);
    va_end(args);
}

void log_notice(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    log_write(LOG_NOTICE, fmt, args);
    va_end(args);
}

void log_info(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    log_write(LOG_INFO, fmt, args);
    va_end(args);
}

void log_debug(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    log_write(LOG_DEBUG, fmt, args);
    va_end(args);
}
