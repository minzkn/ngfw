#ifndef NGFW_CONFIG_HOTRELOAD_H
#define NGFW_CONFIG_HOTRELOAD_H

#include "ngfw/types.h"
#include "ngfw/config.h"

typedef struct config_watcher config_watcher_t;

typedef void (*config_change_callback_t)(const char *key, void *user_data);

config_watcher_t *config_watcher_create(config_t *config);
void config_watcher_destroy(config_watcher_t *watcher);
ngfw_ret_t config_watcher_add_callback(config_watcher_t *watcher, config_change_callback_t cb, void *user_data);
ngfw_ret_t config_watcher_watch_file(config_watcher_t *watcher, const char *filename);
ngfw_ret_t config_watcher_check(config_watcher_t *watcher);
ngfw_ret_t config_watcher_start(config_watcher_t *watcher);
void config_watcher_stop(config_watcher_t *watcher);

#endif
