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

#ifndef NGFW_FIRMWARE_H
#define NGFW_FIRMWARE_H

#include "types.h"

#define FIRMWARE_MAX_BACKUPS 3
#define FIRMWARE_VERSION_MAX 64
#define FIRMWARE_PATH_MAX 256

typedef enum {
    FIRMWARE_STATE_IDLE,
    FIRMWARE_STATE_DOWNLOADING,
    FIRMWARE_STATE_VERIFYING,
    FIRMWARE_STATE_UPDATING,
    FIRMWARE_STATE_REBOOTING,
    FIRMWARE_STATE_ROLLBACK,
    FIRMWARE_STATE_MAX
} firmware_state_t;

typedef enum {
    FIRMWARE_TYPE_KERNEL,
    FIRMWARE_TYPE_ROOTFS,
    FIRMWARE_TYPE_APPLICATION,
    FIRMWARE_TYPE_CONFIG,
    FIRMWARE_TYPE_BOOTLOADER,
    FIRMWARE_TYPE_MAX
} firmware_type_t;

typedef struct firmware_info {
    char version[FIRMWARE_VERSION_MAX];
    char build_date[64];
    char description[256];
    u32 size;
    u32 checksum;
    firmware_type_t type;
    bool valid;
} firmware_info_t;

typedef struct firmware_backup {
    char version[FIRMWARE_VERSION_MAX];
    char path[FIRMWARE_PATH_MAX];
    u64 timestamp;
    u32 size;
} firmware_backup_t;

typedef struct firmware_config {
    char update_server[256];
    u32 check_interval;
    bool auto_update;
    bool keep_backup;
    u32 max_retries;
} firmware_config_t;

typedef struct firmware_module firmware_module_t;

firmware_module_t *firmware_create(void);
void firmware_destroy(firmware_module_t *fw);

ngfw_ret_t firmware_init(firmware_module_t *fw);
ngfw_ret_t firmware_shutdown(firmware_module_t *fw);

ngfw_ret_t firmware_check_update(firmware_module_t *fw, firmware_info_t *info);
ngfw_ret_t firmware_download(firmware_module_t *fw, const char *url, const char *path);
ngfw_ret_t firmware_verify(firmware_module_t *fw, const char *path, firmware_info_t *info);

ngfw_ret_t firmware_install(firmware_module_t *fw, const char *path, bool keep_config);
ngfw_ret_t firmware_upgrade(firmware_module_t *fw, const char *version);

ngfw_ret_t firmware_rollback(firmware_module_t *fw);
ngfw_ret_t firmware_recovery(firmware_module_t *fw);

ngfw_ret_t firmware_backup_create(firmware_module_t *fw, const char *name);
ngfw_ret_t firmware_backup_restore(firmware_module_t *fw, const char *name);
ngfw_ret_t firmware_backup_list(firmware_module_t *fw, firmware_backup_t *backups, u32 *count);
ngfw_ret_t firmware_backup_delete(firmware_module_t *fw, const char *name);

ngfw_ret_t firmware_set_config(firmware_module_t *fw, firmware_config_t *config);
firmware_config_t *firmware_get_config(firmware_module_t *fw);

firmware_state_t firmware_get_state(firmware_module_t *fw);
const char *firmware_get_version(void);
const char *firmware_get_build_date(void);

ngfw_ret_t firmware_reboot(firmware_module_t *fw);
ngfw_ret_t firmware_poweroff(firmware_module_t *fw);

typedef void (*firmware_progress_callback_t)(u32 progress, const char *message, void *context);
ngfw_ret_t firmware_set_progress_callback(firmware_module_t *fw, firmware_progress_callback_t callback, void *context);

#endif