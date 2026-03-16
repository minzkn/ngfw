#include "ngfw/notify.h"
#include "ngfw/memory.h"
#include "ngfw/platform.h"
#include "ngfw/list.h"
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>

#define MAX_SUBSCRIBERS 64

typedef struct subscriber {
    notify_type_t type;
    notify_callback_t callback;
    void *arg;
} subscriber_t;

struct notifier {
    list_t *subscribers;
    u64 next_id;
    pthread_mutex_t lock;
};

notifier_t *notifier_create(void)
{
    notifier_t *notifier = ngfw_malloc(sizeof(notifier_t));
    if (!notifier) return NULL;
    
    notifier->subscribers = list_create(NULL);
    if (!notifier->subscribers) {
        ngfw_free(notifier);
        return NULL;
    }
    
    notifier->next_id = 1;
    pthread_mutex_init(&notifier->lock, NULL);
    
    return notifier;
}

void notifier_destroy(notifier_t *notifier)
{
    if (!notifier) return;
    
    pthread_mutex_lock(&notifier->lock);
    
    list_node_t *node = notifier->subscribers->head;
    while (node) {
        ngfw_free(node->data);
        node = node->next;
    }
    
    list_destroy(notifier->subscribers);
    pthread_mutex_unlock(&notifier->lock);
    pthread_mutex_destroy(&notifier->lock);
    ngfw_free(notifier);
}

ngfw_ret_t notifier_subscribe(notifier_t *notifier, notify_type_t type, notify_callback_t cb, void *arg)
{
    if (!notifier || !cb) return NGFW_ERR_INVALID;
    
    subscriber_t *sub = ngfw_malloc(sizeof(subscriber_t));
    if (!sub) return NGFW_ERR_NO_MEM;
    
    sub->type = type;
    sub->callback = cb;
    sub->arg = arg;
    
    pthread_mutex_lock(&notifier->lock);
    list_append(notifier->subscribers, sub);
    pthread_mutex_unlock(&notifier->lock);
    
    return NGFW_OK;
}

ngfw_ret_t notifier_unsubscribe(notifier_t *notifier, notify_type_t type)
{
    if (!notifier) return NGFW_ERR_INVALID;
    
    pthread_mutex_lock(&notifier->lock);
    
    list_node_t *node = notifier->subscribers->head;
    list_node_t *prev = NULL;
    
    while (node) {
        subscriber_t *sub = (subscriber_t *)node->data;
        
        if (sub->type == type) {
            if (prev) {
                prev->next = node->next;
            } else {
                notifier->subscribers->head = node->next;
            }
            
            ngfw_free(sub);
            break;
        }
        
        prev = node;
        node = node->next;
    }
    
    pthread_mutex_unlock(&notifier->lock);
    return NGFW_OK;
}

ngfw_ret_t notifier_notify(notifier_t *notifier, notify_level_t level, notify_type_t type, const char *fmt, ...)
{
    if (!notifier || !fmt) return NGFW_ERR_INVALID;
    
    notification_t notify;
    notify.id = notifier->next_id++;
    notify.timestamp = get_ms_time();
    notify.level = level;
    notify.type = type;
    notify.data = NULL;
    
    va_list args;
    va_start(args, fmt);
    vsnprintf(notify.message, sizeof(notify.message), fmt, args);
    va_end(args);
    
    pthread_mutex_lock(&notifier->lock);
    
    list_node_t *node = notifier->subscribers->head;
    while (node) {
        subscriber_t *sub = (subscriber_t *)node->data;
        
        if (sub->type == type || sub->type == NOTIFY_TYPE_GENERAL) {
            sub->callback(&notify, sub->arg);
        }
        
        node = node->next;
    }
    
    pthread_mutex_unlock(&notifier->lock);
    
    return NGFW_OK;
}

u32 notifier_count(notifier_t *notifier)
{
    if (!notifier) return 0;
    u32 count;
    pthread_mutex_lock(&notifier->lock);
    count = list_count(notifier->subscribers);
    pthread_mutex_unlock(&notifier->lock);
    return count;
}

void notifier_clear(notifier_t *notifier)
{
    if (!notifier) return;
    
    pthread_mutex_lock(&notifier->lock);
    
    list_node_t *node = notifier->subscribers->head;
    while (node) {
        list_node_t *next = node->next;
        ngfw_free(node->data);
        node = next;
    }
    notifier->subscribers->head = NULL;
    notifier->subscribers->tail = NULL;
    notifier->subscribers->count = 0;
    
    pthread_mutex_unlock(&notifier->lock);
}
