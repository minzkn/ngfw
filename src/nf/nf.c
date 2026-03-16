#include "ngfw/nf.h"
#include "ngfw/memory.h"
#include "ngfw/list.h"
#include "ngfw/log.h"
#include <stdlib.h>
#include <string.h>
#include <errno.h>

struct nf_handle {
    nf_family_t family;
    list_t *rules[5];
    nf_hook_func hooks[5];
    void *hook_data[5];
    bool initialized;
};

static const char * __attribute__((unused)) chain_names[] = {
    "prerouting", "input", "forward", "output", "postrouting"
};

static const char * __attribute__((unused)) hook_names[] = {
    "PREROUTING", "INPUT", "FORWARD", "OUTPUT", "POSTROUTING"
};

nf_handle_t *nf_create(nf_family_t family)
{
    nf_handle_t *handle = ngfw_malloc(sizeof(nf_handle_t));
    if (!handle) return NULL;

    handle->family = family;
    handle->initialized = false;

    for (int i = 0; i < 5; i++) {
        handle->rules[i] = list_create(NULL);
        if (!handle->rules[i]) {
            for (int j = 0; j < i; j++) {
                list_destroy(handle->rules[j]);
            }
            ngfw_free(handle);
            return NULL;
        }
        handle->hooks[i] = NULL;
        handle->hook_data[i] = NULL;
    }

    return handle;
}

void nf_destroy(nf_handle_t *handle)
{
    if (!handle) return;

    for (int i = 0; i < 5; i++) {
        if (handle->rules[i]) {
            list_destroy(handle->rules[i]);
        }
    }

    ngfw_free(handle);
}

ngfw_ret_t nf_set_hook(nf_handle_t *handle, nf_hook_t hook, nf_hook_func func, void *data)
{
    if (!handle || hook >= 5) return NGFW_ERR_INVALID;

    handle->hooks[hook] = func;
    handle->hook_data[hook] = data;

    return NGFW_OK;
}

ngfw_ret_t nf_clear_hook(nf_handle_t *handle, nf_hook_t hook)
{
    if (!handle || hook >= 5) return NGFW_ERR_INVALID;

    handle->hooks[hook] = NULL;
    handle->hook_data[hook] = NULL;

    return NGFW_OK;
}

ngfw_ret_t nf_add_rule(nf_handle_t *handle, nf_rule_t *rule)
{
    if (!handle || !rule) return NGFW_ERR_INVALID;
    if (rule->chain >= 5) return NGFW_ERR_INVALID;

    nf_rule_t *new_rule = ngfw_malloc(sizeof(nf_rule_t));
    if (!new_rule) return NGFW_ERR_NO_MEM;

    memcpy(new_rule, rule, sizeof(nf_rule_t));

    if (list_append(handle->rules[rule->chain], new_rule) != NGFW_OK) {
        ngfw_free(new_rule);
        return NGFW_ERR_NO_MEM;
    }

    return NGFW_OK;
}

ngfw_ret_t nf_del_rule(nf_handle_t *handle, u32 rule_id)
{
    if (!handle) return NGFW_ERR_INVALID;

    for (int i = 0; i < 5; i++) {
        list_node_t *node;
        list_for_each(handle->rules[i], node) {
            nf_rule_t *rule = (nf_rule_t *)node->data;
            if (rule && rule->id == rule_id) {
                list_remove(handle->rules[i], rule);
                ngfw_free(rule);
                return NGFW_OK;
            }
        }
    }

    return NGFW_ERR_INVALID;
}

ngfw_ret_t nf_flush_rules(nf_handle_t *handle)
{
    if (!handle) return NGFW_ERR_INVALID;

    for (int i = 0; i < 5; i++) {
        list_node_t *node;
        list_for_each(handle->rules[i], node) {
            ngfw_free(node->data);
        }
    }

    return NGFW_OK;
}

ngfw_ret_t nf_process_packet(nf_handle_t *handle, packet_t *pkt)
{
    if (!handle || !pkt) return NGFW_ERR_INVALID;

    nf_chain_t chain;
    switch (pkt->direction) {
        case PKT_DIR_IN:
            chain = NF_CHAIN_PREROUTING;
            break;
        case PKT_DIR_OUT:
            chain = NF_CHAIN_OUTPUT;
            break;
        case PKT_DIR_FWD:
            chain = NF_CHAIN_FORWARD;
            break;
        default:
            return NGFW_ERR_INVALID;
    }

    list_node_t *node;
    list_for_each(handle->rules[chain], node) {
        nf_rule_t *rule = (nf_rule_t *)node->data;
        if (!rule || !rule->enabled) continue;

        if (rule->match == NULL || rule->match(pkt, rule->data) == 0) {
            return rule->verdict;
        }
    }

    if (handle->hooks[chain]) {
        return handle->hooks[chain](handle, pkt, handle->hook_data[chain]);
    }

    return NF_VERDICT_ACCEPT;
}

ngfw_ret_t nf_init_tables(nf_handle_t *handle)
{
    if (!handle) return NGFW_ERR_INVALID;

    handle->initialized = true;
    log_info("Netfilter tables initialized");

    return NGFW_OK;
}

ngfw_ret_t nf_destroy_tables(nf_handle_t *handle)
{
    if (!handle) return NGFW_ERR_INVALID;

    nf_flush_rules(handle);
    handle->initialized = false;

    return NGFW_OK;
}

struct nf_queue {
    packet_t **packets;
    u32 size;
    u32 head;
    u32 tail;
    u32 count;
    void *lock;
    void *not_empty;
};

nf_queue_t *nf_queue_create(u32 size)
{
    nf_queue_t *queue = ngfw_malloc(sizeof(nf_queue_t));
    if (!queue) return NULL;

    queue->packets = ngfw_malloc(sizeof(packet_t *) * size);
    if (!queue->packets) {
        ngfw_free(queue);
        return NULL;
    }

    queue->size = size;
    queue->head = 0;
    queue->tail = 0;
    queue->count = 0;
    queue->lock = NULL;
    queue->not_empty = NULL;

    return queue;
}

void nf_queue_destroy(nf_queue_t *queue)
{
    if (!queue) return;

    for (u32 i = 0; i < queue->count; i++) {
        u32 idx = (queue->head + i) % queue->size;
        if (queue->packets[idx]) {
            packet_destroy(queue->packets[idx]);
        }
    }

    ngfw_free(queue->packets);
    ngfw_free(queue);
}

ngfw_ret_t nf_queue_enqueue(nf_queue_t *queue, packet_t *pkt)
{
    if (!queue || !pkt) return NGFW_ERR_INVALID;

    if (queue->count >= queue->size) {
        return NGFW_ERR_NO_RESOURCE;
    }

    queue->packets[queue->tail] = pkt;
    queue->tail = (queue->tail + 1) % queue->size;
    queue->count++;

    return NGFW_OK;
}

packet_t *nf_queue_dequeue(nf_queue_t *queue)
{
    if (!queue) return NULL;

    if (queue->count == 0) return NULL;

    packet_t *pkt = queue->packets[queue->head];
    queue->head = (queue->head + 1) % queue->size;
    queue->count--;

    return pkt;
}

u32 nf_queue_size(nf_queue_t *queue)
{
    return queue ? queue->count : 0;
}
