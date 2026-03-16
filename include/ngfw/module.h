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

#ifndef NGFW_MODULE_H
#define NGFW_MODULE_H

#include "ngfw/types.h"
#include "ngfw/memory.h"

typedef enum {
    MODULE_TYPE_FILTER,
    MODULE_TYPE_IPS,
    MODULE_TYPE_URLFILTER,
    MODULE_TYPE_ANTIVIRUS,
    MODULE_TYPE_VPN,
    MODULE_TYPE_NAT,
    MODULE_TYPE_QOS,
    MODULE_TYPE_DDOS,
    MODULE_TYPE_COUNT
} module_type_t;

typedef enum {
    MODULE_STATE_NONE,
    MODULE_STATE_INIT,
    MODULE_STATE_STARTED,
    MODULE_STATE_STOPPED,
    MODULE_STATE_ERROR
} module_state_t;

typedef struct module_ops module_ops_t;

typedef struct ngfw_module {
    module_type_t type;
    module_state_t state;
    const char *name;
    const module_ops_t *ops;
    void *context;
    u32 flags;
} ngfw_module_t;

typedef ngfw_ret_t (*module_init_fn)(ngfw_module_t *);
typedef ngfw_ret_t (*module_start_fn)(ngfw_module_t *);
typedef ngfw_ret_t (*module_stop_fn)(ngfw_module_t *);
typedef ngfw_ret_t (*module_process_fn)(ngfw_module_t *, void *);
typedef ngfw_ret_t (*module_config_fn)(ngfw_module_t *, const void *);
typedef ngfw_ret_t (*module_stats_fn)(ngfw_module_t *, void *);
typedef void (*module_destroy_fn)(ngfw_module_t *);

struct module_ops {
    module_init_fn init;
    module_start_fn start;
    module_stop_fn stop;
    module_process_fn process;
    module_config_fn config;
    module_stats_fn get_stats;
    module_destroy_fn destroy;
};

#define MODULE_FLAG_ENABLED   0x0001
#define MODULE_FLAG_BYPASS    0x0002
#define MODULE_FLAG_LOGGING   0x0004

ngfw_ret_t module_init(ngfw_module_t *mod);
ngfw_ret_t module_start(ngfw_module_t *mod);
ngfw_ret_t module_stop(ngfw_module_t *mod);
ngfw_ret_t module_process(ngfw_module_t *mod, void *data);
ngfw_ret_t module_config(ngfw_module_t *mod, const void *config);
ngfw_ret_t module_get_stats(ngfw_module_t *mod, void *stats);
void module_destroy(ngfw_module_t *mod);
const char *module_type_name(module_type_t type);
const char *module_state_name(module_state_t state);

#endif
