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

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
#include "ngfw/plugin.h"
#include "ngfw/memory.h"
#include "ngfw/log.h"
#include "ngfw/hash.h"
#include <stddef.h>
#include <string.h>
#include <dlfcn.h>
#include <stdlib.h>
#pragma GCC diagnostic pop

#define MAX_PLUGINS 64

struct plugin {
    char *path;
    char *name;
    void *handle;
    plugin_info_t *info;
    bool loaded;
};

static hash_table_t *plugins = NULL;
static bool plugin_system_initialized = false;

ngfw_ret_t plugin_init(void)
{
    if (plugin_system_initialized) return NGFW_OK;
    
    plugins = hash_create(64, NULL, NULL, NULL);
    if (!plugins) return NGFW_ERR_NO_MEM;
    
    plugin_system_initialized = true;
    log_info("Plugin system initialized");
    return NGFW_OK;
}

void plugin_shutdown(void)
{
    if (!plugins) return;
    
    void **iter = hash_iterate_start(plugins);
    while (hash_iterate_has_next(iter)) {
        plugin_t *pl = hash_iterate_next(plugins, iter);
        if (pl) {
            if (pl->info && pl->info->exit) {
                pl->info->exit();
            }
            if (pl->handle) {
                dlclose(pl->handle);
            }
            ngfw_free(pl->path);
            ngfw_free(pl->name);
            ngfw_free(pl);
        }
    }
    
    hash_destroy(plugins);
    plugins = NULL;
    plugin_system_initialized = false;
    log_info("Plugin system shutdown");
}

ngfw_ret_t plugin_load(const char *path)
{
    if (!path || !plugin_system_initialized) return NGFW_ERR_INVALID;
    
    void *handle = dlopen(path, RTLD_NOW);
    if (!handle) {
        log_err("Failed to load plugin %s: %s", path, dlerror());
        return NGFW_ERR_NOT_FOUND;
    }
    
    plugin_register_fn register_fn = (plugin_register_fn)dlsym(handle, "plugin_register");
    if (!register_fn) {
        log_err("Plugin %s has no plugin_register function", path);
        dlclose(handle);
        return NGFW_ERR_NOT_SUPPORTED;
    }
    
    ngfw_ret_t ret = register_fn(NULL);
    if (ret != NGFW_OK) {
        log_err("Plugin %s registration failed", path);
        dlclose(handle);
        return ret;
    }
    
    log_info("Loaded plugin from %s", path);
    return NGFW_OK;
}

void plugin_unload(const char *name)
{
    if (!name || !plugins) return;
    
    plugin_t *pl = hash_lookup(plugins, name);
    if (!pl) return;
    
    if (pl->info && pl->info->exit) {
        pl->info->exit();
    }
    
    if (pl->handle) {
        dlclose(pl->handle);
    }
    
    hash_remove(plugins, name);
    
    ngfw_free(pl->path);
    ngfw_free(pl->name);
    ngfw_free(pl);
    
    log_info("Unloaded plugin %s", name);
}

plugin_t *plugin_find(const char *name)
{
    if (!name || !plugins) return NULL;
    return hash_lookup(plugins, name);
}

ngfw_ret_t plugin_register_module(const plugin_info_t *info)
{
    if (!info || !info->name || !plugins) return NGFW_ERR_INVALID;
    
    if (hash_lookup(plugins, info->name)) {
        log_warn("Plugin %s already registered", info->name);
        return NGFW_ERR_EXISTS;
    }
    
    plugin_t *pl = ngfw_malloc(sizeof(plugin_t));
    if (!pl) return NGFW_ERR_NO_MEM;
    
    pl->name = ngfw_malloc(strlen(info->name) + 1);
    if (!pl->name) {
        ngfw_free(pl);
        return NGFW_ERR_NO_MEM;
    }
    strcpy(pl->name, info->name);
    
    pl->info = (plugin_info_t *)info;
    pl->loaded = true;
    pl->path = NULL;
    pl->handle = NULL;
    
    hash_insert(plugins, pl->name, pl);
    
    log_info("Registered plugin: %s v%s", info->name, info->version);
    return NGFW_OK;
}

ngfw_ret_t plugin_unregister_module(const char *name)
{
    if (!name || !plugins) return NGFW_ERR_INVALID;
    
    plugin_t *pl = hash_remove(plugins, name);
    if (!pl) return NGFW_ERR_NOT_FOUND;
    
    ngfw_free(pl->name);
    ngfw_free(pl);
    
    return NGFW_OK;
}

u32 plugin_count(void)
{
    return plugins ? hash_size(plugins) : 0;
}
