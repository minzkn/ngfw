#ifndef NGFW_NOTIFY_H
#define NGFW_NOTIFY_H

#include "ngfw/types.h"
#include <stdbool.h>
#include <stddef.h>

typedef enum {
    NOTIFY_INFO,
    NOTIFY_WARNING,
    NOTIFY_ERROR,
    NOTIFY_CRITICAL,
    NOTIFY_DEBUG
} notify_level_t;

typedef enum {
    NOTIFY_TYPE_GENERAL,
    NOTIFY_TYPE_SECURITY,
    NOTIFY_TYPE_NETWORK,
    NOTIFY_TYPE_SYSTEM,
    NOTIFY_TYPE_CONFIG,
    NOTIFY_TYPE_FIREWALL
} notify_type_t;

typedef struct notification {
    u64 id;
    u64 timestamp;
    notify_level_t level;
    notify_type_t type;
    char message[256];
    void *data;
} notification_t;

typedef struct notifier notifier_t;

typedef void (*notify_callback_t)(const notification_t *notify, void *arg);

notifier_t *notifier_create(void);
void notifier_destroy(notifier_t *notifier);
ngfw_ret_t notifier_subscribe(notifier_t *notifier, notify_type_t type, notify_callback_t cb, void *arg);
ngfw_ret_t notifier_unsubscribe(notifier_t *notifier, notify_type_t type);
ngfw_ret_t notifier_notify(notifier_t *notifier, notify_level_t level, notify_type_t type, const char *fmt, ...);
u32 notifier_count(notifier_t *notifier);
void notifier_clear(notifier_t *notifier);

#endif
