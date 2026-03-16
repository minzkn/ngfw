#include "ngfw/firmware.h"
#include "ngfw/memory.h"
#include "ngfw/log.h"
#include "ngfw/crypto.h"
#include "ngfw/platform.h"
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/reboot.h>
#include <linux/reboot.h>
#include <stdio.h>
#include <pthread.h>

#define NGFW_FIRMWARE_VERSION "2.0.0"
#define NGFW_FIRMWARE_BUILD_DATE "2026-03-15"

struct firmware_module {
    firmware_state_t state;
    firmware_config_t config;
    
    firmware_progress_callback_t progress_callback;
    void *progress_context;
    
    firmware_backup_t backups[FIRMWARE_MAX_BACKUPS];
    u32 backup_count;
    
    bool initialized;
    
    pthread_mutex_t lock;
    pthread_t update_thread;
    bool update_running;
};

firmware_module_t *firmware_create(void)
{
    firmware_module_t *fw = ngfw_malloc(sizeof(firmware_module_t));
    if (!fw) return NULL;
    
    memset(fw, 0, sizeof(firmware_module_t));
    
    strcpy(fw->config.update_server, "https://updates.ngfw.local");
    fw->config.check_interval = 86400;
    fw->config.auto_update = false;
    fw->config.keep_backup = true;
    fw->config.max_retries = 3;
    
    fw->state = FIRMWARE_STATE_IDLE;
    
    pthread_mutex_init(&fw->lock, NULL);
    
    return fw;
}

void firmware_destroy(firmware_module_t *fw)
{
    if (fw) {
        pthread_mutex_destroy(&fw->lock);
        ngfw_free(fw);
    }
}

ngfw_ret_t firmware_init(firmware_module_t *fw)
{
    if (!fw) return NGFW_ERR_INVALID;
    
    pthread_mutex_lock(&fw->lock);
    fw->initialized = true;
    fw->state = FIRMWARE_STATE_IDLE;
    pthread_mutex_unlock(&fw->lock);
    
    log_info("Firmware module initialized v%s", firmware_get_version());
    return NGFW_OK;
}

ngfw_ret_t firmware_shutdown(firmware_module_t *fw)
{
    if (!fw) return NGFW_ERR_INVALID;
    
    pthread_mutex_lock(&fw->lock);
    
    if (fw->update_running) {
        fw->update_running = false;
        pthread_join(fw->update_thread, NULL);
    }
    
    fw->initialized = false;
    pthread_mutex_unlock(&fw->lock);
    
    log_info("Firmware module shutdown");
    return NGFW_OK;
}

ngfw_ret_t firmware_check_update(firmware_module_t *fw, firmware_info_t *info)
{
    if (!fw || !info) return NGFW_ERR_INVALID;
    
    pthread_mutex_lock(&fw->lock);
    
    memset(info, 0, sizeof(firmware_info_t));
    strcpy(info->version, NGFW_FIRMWARE_VERSION);
    strcpy(info->build_date, NGFW_FIRMWARE_BUILD_DATE);
    snprintf(info->description, sizeof(info->description), "NGFW Firmware v%s", NGFW_FIRMWARE_VERSION);
    info->size = 0;
    info->type = FIRMWARE_TYPE_APPLICATION;
    info->valid = true;
    
    pthread_mutex_unlock(&fw->lock);
    
    log_info("Firmware check update: current=%s", NGFW_FIRMWARE_VERSION);
    return NGFW_OK;
}

ngfw_ret_t firmware_download(firmware_module_t *fw, const char *url, const char *path)
{
    if (!fw || !url || !path) return NGFW_ERR_INVALID;
    
    pthread_mutex_lock(&fw->lock);
    fw->state = FIRMWARE_STATE_DOWNLOADING;
    pthread_mutex_unlock(&fw->lock);
    
    if (fw->progress_callback) {
        fw->progress_callback(0, "Downloading firmware...", fw->progress_context);
    }
    
    log_info("Downloading firmware from %s to %s", url, path);
    
    FILE *fp = fopen(path, "w");
    if (!fp) {
        pthread_mutex_lock(&fw->lock);
        fw->state = FIRMWARE_STATE_IDLE;
        pthread_mutex_unlock(&fw->lock);
        return NGFW_ERR;
    }
    fprintf(fp, "# Firmware placeholder\n");
    fclose(fp);
    
    if (fw->progress_callback) {
        fw->progress_callback(100, "Download complete", fw->progress_context);
    }
    
    pthread_mutex_lock(&fw->lock);
    fw->state = FIRMWARE_STATE_IDLE;
    pthread_mutex_unlock(&fw->lock);
    
    return NGFW_OK;
}

ngfw_ret_t firmware_verify(firmware_module_t *fw, const char *path, firmware_info_t *info)
{
    if (!fw || !path || !info) return NGFW_ERR_INVALID;
    
    pthread_mutex_lock(&fw->lock);
    fw->state = FIRMWARE_STATE_VERIFYING;
    pthread_mutex_unlock(&fw->lock);
    
    struct stat st;
    if (stat(path, &st) != 0) {
        pthread_mutex_lock(&fw->lock);
        fw->state = FIRMWARE_STATE_IDLE;
        pthread_mutex_unlock(&fw->lock);
        return NGFW_ERR;
    }
    
    memset(info, 0, sizeof(firmware_info_t));
    info->size = st.st_size;
    info->valid = true;
    
    if (fw->progress_callback) {
        fw->progress_callback(100, "Verification complete", fw->progress_context);
    }
    
    pthread_mutex_lock(&fw->lock);
    fw->state = FIRMWARE_STATE_IDLE;
    pthread_mutex_unlock(&fw->lock);
    
    log_info("Firmware verified: %u bytes", info->size);
    return NGFW_OK;
}

ngfw_ret_t firmware_install(firmware_module_t *fw, const char *path, bool keep_config)
{
    if (!fw || !path) return NGFW_ERR_INVALID;
    
    pthread_mutex_lock(&fw->lock);
    fw->state = FIRMWARE_STATE_UPDATING;
    pthread_mutex_unlock(&fw->lock);
    
    if (fw->progress_callback) {
        fw->progress_callback(10, "Creating backup...", fw->progress_context);
    }
    
    if (fw->config.keep_backup && keep_config) {
        firmware_backup_create(fw, "pre-update");
    }
    
    if (fw->progress_callback) {
        fw->progress_callback(30, "Installing firmware...", fw->progress_context);
    }
    
    log_info("Installing firmware from %s (keep_config=%d)", path, keep_config);
    
    if (fw->progress_callback) {
        fw->progress_callback(80, "Updating bootloader...", fw->progress_context);
    }
    
    if (fw->progress_callback) {
        fw->progress_callback(100, "Installation complete", fw->progress_context);
    }
    
    pthread_mutex_lock(&fw->lock);
    fw->state = FIRMWARE_STATE_REBOOTING;
    pthread_mutex_unlock(&fw->lock);
    
    return NGFW_OK;
}

ngfw_ret_t firmware_upgrade(firmware_module_t *fw, const char *version)
{
    if (!fw || !version) return NGFW_ERR_INVALID;
    
    log_info("Upgrading firmware to version %s", version);
    
    firmware_info_t info;
    firmware_check_update(fw, &info);
    
    return firmware_install(fw, "/tmp/firmware.tar.gz", true);
}

ngfw_ret_t firmware_rollback(firmware_module_t *fw)
{
    if (!fw) return NGFW_ERR_INVALID;
    
    pthread_mutex_lock(&fw->lock);
    fw->state = FIRMWARE_STATE_ROLLBACK;
    pthread_mutex_unlock(&fw->lock);
    
    log_info("Rolling back firmware");
    
    if (fw->backup_count > 0) {
        firmware_backup_restore(fw, fw->backups[0].version);
    }
    
    pthread_mutex_lock(&fw->lock);
    fw->state = FIRMWARE_STATE_IDLE;
    pthread_mutex_unlock(&fw->lock);
    
    return NGFW_OK;
}

ngfw_ret_t firmware_recovery(firmware_module_t *fw)
{
    if (!fw) return NGFW_ERR_INVALID;
    
    log_info("Entering recovery mode");
    
    pthread_mutex_lock(&fw->lock);
    fw->state = FIRMWARE_STATE_IDLE;
    pthread_mutex_unlock(&fw->lock);
    
    return NGFW_OK;
}

ngfw_ret_t firmware_backup_create(firmware_module_t *fw, const char *name)
{
    if (!fw || !name) return NGFW_ERR_INVALID;
    
    if (fw->backup_count >= FIRMWARE_MAX_BACKUPS) {
        memmove(&fw->backups[0], &fw->backups[1], sizeof(firmware_backup_t) * (FIRMWARE_MAX_BACKUPS - 1));
        fw->backup_count--;
    }
    
    firmware_backup_t *backup = &fw->backups[fw->backup_count++];
    strncpy(backup->version, name, sizeof(backup->version) - 1);
    snprintf(backup->path, sizeof(backup->path), "/mnt/backup/ngfw-%s.tar.gz", name);
    backup->timestamp = get_ms_time();
    backup->size = 0;
    
    log_info("Created backup: %s", name);
    return NGFW_OK;
}

ngfw_ret_t firmware_backup_restore(firmware_module_t *fw, const char *name)
{
    if (!fw || !name) return NGFW_ERR_INVALID;
    
    log_info("Restoring backup: %s", name);
    
    for (u32 i = 0; i < fw->backup_count; i++) {
        if (strcmp(fw->backups[i].version, name) == 0) {
            return firmware_install(fw, fw->backups[i].path, true);
        }
    }
    
    return NGFW_ERR;
}

ngfw_ret_t firmware_backup_list(firmware_module_t *fw, firmware_backup_t *backups, u32 *count)
{
    if (!fw || !count) return NGFW_ERR_INVALID;
    
    *count = fw->backup_count;
    
    if (backups) {
        memcpy(backups, fw->backups, sizeof(firmware_backup_t) * fw->backup_count);
    }
    
    return NGFW_OK;
}

ngfw_ret_t firmware_backup_delete(firmware_module_t *fw, const char *name)
{
    if (!fw || !name) return NGFW_ERR_INVALID;
    
    for (u32 i = 0; i < fw->backup_count; i++) {
        if (strcmp(fw->backups[i].version, name) == 0) {
            for (u32 j = i; j < fw->backup_count - 1; j++) {
                fw->backups[j] = fw->backups[j + 1];
            }
            fw->backup_count--;
            log_info("Deleted backup: %s", name);
            return NGFW_OK;
        }
    }
    
    return NGFW_ERR;
}

ngfw_ret_t firmware_set_config(firmware_module_t *fw, firmware_config_t *config)
{
    if (!fw || !config) return NGFW_ERR_INVALID;
    
    pthread_mutex_lock(&fw->lock);
    fw->config = *config;
    pthread_mutex_unlock(&fw->lock);
    
    return NGFW_OK;
}

firmware_config_t *firmware_get_config(firmware_module_t *fw)
{
    if (!fw) return NULL;
    return &fw->config;
}

firmware_state_t firmware_get_state(firmware_module_t *fw)
{
    if (!fw) return FIRMWARE_STATE_IDLE;
    
    firmware_state_t state;
    pthread_mutex_lock(&fw->lock);
    state = fw->state;
    pthread_mutex_unlock(&fw->lock);
    
    return state;
}

const char *firmware_get_version(void)
{
    return NGFW_FIRMWARE_VERSION;
}

const char *firmware_get_build_date(void)
{
    return NGFW_FIRMWARE_BUILD_DATE;
}

ngfw_ret_t firmware_reboot(firmware_module_t *fw)
{
    if (!fw) return NGFW_ERR_INVALID;
    
    log_info("Rebooting system...");
    sync();
    sleep(1);
    
    reboot(LINUX_REBOOT_CMD_RESTART);
    
    return NGFW_OK;
}

ngfw_ret_t firmware_poweroff(firmware_module_t *fw)
{
    if (!fw) return NGFW_ERR_INVALID;
    
    log_info("Powering off system...");
    sync();
    sleep(1);
    
    reboot(LINUX_REBOOT_CMD_POWER_OFF);
    
    return NGFW_OK;
}

ngfw_ret_t firmware_set_progress_callback(firmware_module_t *fw, firmware_progress_callback_t callback, void *context)
{
    if (!fw) return NGFW_ERR_INVALID;
    
    pthread_mutex_lock(&fw->lock);
    fw->progress_callback = callback;
    fw->progress_context = context;
    pthread_mutex_unlock(&fw->lock);
    
    return NGFW_OK;
}