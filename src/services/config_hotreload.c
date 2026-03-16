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

#include "ngfw/config_hotreload.h"
#include "ngfw/memory.h"
#include "ngfw/platform.h"
#include "ngfw/log.h"
#include <stddef.h>
#include <string.h>
#include <sys/stat.h>
#include <pthread.h>
#include <unistd.h>

#define MAX_WATCHERS 16

struct config_watcher {
    config_t *config;
    char *filename;
    u64 last_modified;
    config_change_callback_t callbacks[MAX_WATCHERS];
    void *callback_data[MAX_WATCHERS];
    u32 callback_count;
    pthread_t thread;
    bool running;
    pthread_mutex_t lock;
};

static u64 get_file_modified_time(const char *filename)
{
    struct stat st;
    if (stat(filename, &st) != 0) return 0;
    return st.st_mtime;
}

config_watcher_t *config_watcher_create(config_t *config)
{
    if (!config) return NULL;
    
    config_watcher_t *watcher = ngfw_malloc(sizeof(config_watcher_t));
    if (!watcher) return NULL;
    
    watcher->config = config;
    watcher->filename = NULL;
    watcher->last_modified = 0;
    watcher->callback_count = 0;
    watcher->running = false;
    watcher->thread = 0;
    pthread_mutex_init(&watcher->lock, NULL);
    
    return watcher;
}

void config_watcher_destroy(config_watcher_t *watcher)
{
    if (!watcher) return;
    
    config_watcher_stop(watcher);
    
    pthread_mutex_destroy(&watcher->lock);
    ngfw_free(watcher->filename);
    ngfw_free(watcher);
}

ngfw_ret_t config_watcher_add_callback(config_watcher_t *watcher, config_change_callback_t cb, void *user_data)
{
    if (!watcher || !cb) return NGFW_ERR_INVALID;
    if (watcher->callback_count >= MAX_WATCHERS) return NGFW_ERR_NO_RESOURCE;
    
    pthread_mutex_lock(&watcher->lock);
    watcher->callbacks[watcher->callback_count] = cb;
    watcher->callback_data[watcher->callback_count] = user_data;
    watcher->callback_count++;
    pthread_mutex_unlock(&watcher->lock);
    
    return NGFW_OK;
}

ngfw_ret_t config_watcher_watch_file(config_watcher_t *watcher, const char *filename)
{
    if (!watcher || !filename) return NGFW_ERR_INVALID;
    
    pthread_mutex_lock(&watcher->lock);
    ngfw_free(watcher->filename);
    watcher->filename = ngfw_malloc(strlen(filename) + 1);
    if (!watcher->filename) {
        pthread_mutex_unlock(&watcher->lock);
        return NGFW_ERR_NO_MEM;
    }
    strcpy(watcher->filename, filename);
    watcher->last_modified = get_file_modified_time(filename);
    pthread_mutex_unlock(&watcher->lock);
    
    return NGFW_OK;
}

static void *watcher_thread(void *arg)
{
    config_watcher_t *watcher = (config_watcher_t *)arg;
    
    while (watcher->running) {
        sleep(1);
        
        if (!watcher->filename) continue;
        
        u64 current_modified = get_file_modified_time(watcher->filename);
        
        if (current_modified > watcher->last_modified) {
            log_info("Config file changed: %s", watcher->filename);
            
            watcher->last_modified = current_modified;
            
            pthread_mutex_lock(&watcher->lock);
            for (u32 i = 0; i < watcher->callback_count; i++) {
                if (watcher->callbacks[i]) {
                    watcher->callbacks[i](watcher->filename, watcher->callback_data[i]);
                }
            }
            pthread_mutex_unlock(&watcher->lock);
        }
    }
    
    return NULL;
}

ngfw_ret_t config_watcher_check(config_watcher_t *watcher)
{
    if (!watcher || !watcher->filename) return NGFW_ERR_INVALID;
    
    u64 current_modified = get_file_modified_time(watcher->filename);
    
    if (current_modified > watcher->last_modified) {
        log_info("Config file changed: %s", watcher->filename);
        watcher->last_modified = current_modified;
        
        pthread_mutex_lock(&watcher->lock);
        for (u32 i = 0; i < watcher->callback_count; i++) {
            if (watcher->callbacks[i]) {
                watcher->callbacks[i](watcher->filename, watcher->callback_data[i]);
            }
        }
        pthread_mutex_unlock(&watcher->lock);
        
        return NGFW_OK;
    }
    
    return NGFW_ERR_NOT_FOUND;
}

ngfw_ret_t config_watcher_start(config_watcher_t *watcher)
{
    if (!watcher) return NGFW_ERR_INVALID;
    if (watcher->running) return NGFW_ERR_INVALID;
    
    watcher->running = true;
    if (pthread_create(&watcher->thread, NULL, watcher_thread, watcher) != 0) {
        watcher->running = false;
        return NGFW_ERR;
    }
    
    return NGFW_OK;
}

void config_watcher_stop(config_watcher_t *watcher)
{
    if (!watcher || !watcher->running) return;
    
    watcher->running = false;
    pthread_join(watcher->thread, NULL);
}
