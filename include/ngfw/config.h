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

#ifndef NGFW_CONFIG_H
#define NGFW_CONFIG_H

#include "types.h"
#include "filter.h"
#include "session.h"
#include "ips.h"

typedef enum {
    CONFIG_TYPE_STRING,
    CONFIG_TYPE_INT,
    CONFIG_TYPE_BOOL,
    CONFIG_TYPE_ARRAY,
    CONFIG_TYPE_OBJECT
} config_type_t;

typedef struct config_value {
    config_type_t type;
    union {
        char *str;
        s32 num;
        bool boolean;
        struct config_array *array;
        struct config_object *obj;
    } value;
} config_value_t;

typedef struct config_array {
    config_value_t *values;
    u32 count;
} config_array_t;

typedef struct config_object {
    char **keys;
    config_value_t *values;
    u32 count;
} config_object_t;

typedef struct config {
    config_object_t root;
    char *filename;
} config_t;

typedef struct ngfw_config {
    struct {
        u32 max_sessions;
        u32 session_timeout;
        u32 cleanup_interval;
    } session;

    struct {
        bool enabled;
        u32 max_rules;
    } filter;

    struct {
        bool enabled;
        char signatures_file[256];
    } ips;

    struct {
        bool enabled;
        u32 log_level;
        char log_file[256];
        u32 max_size;
        u32 max_files;
    } logging;

    struct {
        bool enabled;
        char listen_addr[64];
        u16 port;
    } webui;

    struct {
        bool enabled;
    } vpn;

    struct {
        bool enabled;
    } urlfilter;

    struct {
        bool enabled;
    } qos;
} ngfw_config_t;

config_t *config_create(void);
void config_destroy(config_t *config);

ngfw_ret_t config_load(config_t *config, const char *filename);
ngfw_ret_t config_save(config_t *config, const char *filename);

ngfw_ret_t config_get_value(config_t *config, const char *path, config_value_t *value);
ngfw_ret_t config_set_value(config_t *config, const char *path, config_value_t *value);

ngfw_ret_t config_to_ngfw_config(config_t *config, ngfw_config_t *ngfw_config);

config_value_t *config_value_create_string(const char *str);
config_value_t *config_value_create_int(s32 num);
config_value_t *config_value_create_bool(bool val);
void config_value_destroy(config_value_t *val);

ngfw_ret_t config_parse_file(config_t *config, const char *filename);
ngfw_ret_t config_parse_json(config_t *config, const char *json);

ngfw_ret_t config_load_default(ngfw_config_t *config);

#endif
