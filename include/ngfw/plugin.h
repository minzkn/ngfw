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

#ifndef NGFW_PLUGIN_H
#define NGFW_PLUGIN_H

#include "ngfw/types.h"
#include "ngfw/module.h"

typedef struct plugin plugin_t;
typedef ngfw_ret_t (*plugin_init_fn)(void);
typedef void (*plugin_exit_fn)(void);

typedef struct plugin_info {
    const char *name;
    const char *version;
    const char *author;
    module_type_t type;
    plugin_init_fn init;
    plugin_exit_fn exit;
} plugin_info_t;

#define PLUGIN_INFO(name, ver, author, type) \
    static plugin_info_t plugin_info_##name = { \
        #name, ver, author, type, NULL, NULL \
    };

typedef ngfw_ret_t (*plugin_register_fn)(const plugin_info_t *);
typedef ngfw_ret_t (*plugin_unregister_fn)(const char *name);

ngfw_ret_t plugin_init(void);
void plugin_shutdown(void);
ngfw_ret_t plugin_load(const char *path);
void plugin_unload(const char *name);
plugin_t *plugin_find(const char *name);
ngfw_ret_t plugin_register_module(const plugin_info_t *info);
ngfw_ret_t plugin_unregister_module(const char *name);
u32 plugin_count(void);

#endif
