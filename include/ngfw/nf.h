#ifndef NGFW_NF_H
#define NGFW_NF_H

#include "types.h"
#include "packet.h"

typedef enum {
    NF_FAMILY_INET,
    NF_FAMILY_INET6,
    NF_FAMILY_BRIDGE,
    NF_FAMILY_ARP
} nf_family_t;

typedef enum {
    NF_CHAIN_PREROUTING,
    NF_CHAIN_INPUT,
    NF_CHAIN_FORWARD,
    NF_CHAIN_OUTPUT,
    NF_CHAIN_POSTROUTING
} nf_chain_t;

typedef enum {
    NF_HOOK_PRE_ROUTING,
    NF_HOOK_LOCAL_IN,
    NF_HOOK_FORWARD,
    NF_HOOK_LOCAL_OUT,
    NF_HOOK_POST_ROUTING
} nf_hook_t;

typedef enum {
    NF_VERDICT_ACCEPT,
    NF_VERDICT_DROP,
    NF_VERDICT_QUEUE,
    NF_VERDICT_REPEAT,
    NF_VERDICT_STOP
} nf_verdict_t;

typedef struct nf_handle nf_handle_t;
typedef struct nf_rule nf_rule_t;

typedef nf_verdict_t (*nf_hook_func)(nf_handle_t *handle, packet_t *pkt, void *data);

struct nf_rule {
    u32 id;
    nf_chain_t chain;
    u16 hook_mask;
    int (*match)(packet_t *pkt, void *data);
    nf_verdict_t verdict;
    void *data;
    bool enabled;
};

nf_handle_t *nf_create(nf_family_t family);
void nf_destroy(nf_handle_t *handle);

ngfw_ret_t nf_set_hook(nf_handle_t *handle, nf_hook_t hook, nf_hook_func func, void *data);
ngfw_ret_t nf_clear_hook(nf_handle_t *handle, nf_hook_t hook);

ngfw_ret_t nf_add_rule(nf_handle_t *handle, nf_rule_t *rule);
ngfw_ret_t nf_del_rule(nf_handle_t *handle, u32 rule_id);
ngfw_ret_t nf_flush_rules(nf_handle_t *handle);

ngfw_ret_t nf_process_packet(nf_handle_t *handle, packet_t *pkt);

ngfw_ret_t nf_init_tables(nf_handle_t *handle);
ngfw_ret_t nf_destroy_tables(nf_handle_t *handle);

typedef struct nf_queue nf_queue_t;

nf_queue_t *nf_queue_create(u32 size);
void nf_queue_destroy(nf_queue_t *queue);
ngfw_ret_t nf_queue_enqueue(nf_queue_t *queue, packet_t *pkt);
packet_t *nf_queue_dequeue(nf_queue_t *queue);
u32 nf_queue_size(nf_queue_t *queue);

#endif
