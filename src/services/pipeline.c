#include "ngfw/pipeline.h"
#include "ngfw/memory.h"
#include "ngfw/list.h"
#include "ngfw/hash.h"
#include "ngfw/log.h"
#include "ngfw/crypto.h"
#include "ngfw/platform.h"
#include <string.h>
#include <stdlib.h>
#include <pthread.h>

#define MAX_HOOKS_PER_STAGE 16
#define DEFAULT_STAGES 8

struct pipeline_stage_hook {
    pipeline_hook_t hook;
    void *data;
};

struct pipeline {
    struct pipeline_stage_hook **hooks;
    u32 num_stages;
    int *num_hooks;
    pipeline_stats_t stats;
    bool initialized;
    bool running;
    pthread_mutex_t lock;
};

pipeline_t *pipeline_create_ex(u32 num_stages)
{
    if (num_stages == 0) num_stages = DEFAULT_STAGES;
    
    pipeline_t *pl = ngfw_malloc(sizeof(pipeline_t));
    if (!pl) return NULL;

    memset(pl, 0, sizeof(pipeline_t));
    
    pl->hooks = ngfw_calloc(num_stages, sizeof(struct pipeline_stage_hook *));
    if (!pl->hooks) {
        ngfw_free(pl);
        return NULL;
    }
    
    for (u32 i = 0; i < num_stages; i++) {
        pl->hooks[i] = ngfw_calloc(MAX_HOOKS_PER_STAGE, sizeof(struct pipeline_stage_hook));
        if (!pl->hooks[i]) {
            for (u32 j = 0; j < i; j++) {
                ngfw_free(pl->hooks[j]);
            }
            ngfw_free(pl->hooks);
            ngfw_free(pl);
            return NULL;
        }
    }
    
    pl->num_hooks = ngfw_calloc(num_stages, sizeof(int));
    if (!pl->num_hooks) {
        for (u32 i = 0; i < num_stages; i++) {
            ngfw_free(pl->hooks[i]);
        }
        ngfw_free(pl->hooks);
        ngfw_free(pl);
        return NULL;
    }
    
    pl->num_stages = num_stages;
    pthread_mutex_init(&pl->lock, NULL);

    log_info("Pipeline created with %u stages", num_stages);

    return pl;
}

pipeline_t *pipeline_create(void)
{
    return pipeline_create_ex(0);
}

void pipeline_destroy(pipeline_t *pipeline)
{
    if (!pipeline) return;
    
    if (pipeline->hooks) {
        for (u32 i = 0; i < pipeline->num_stages; i++) {
            ngfw_free(pipeline->hooks[i]);
        }
        ngfw_free(pipeline->hooks);
    }
    ngfw_free(pipeline->num_hooks);
    pthread_mutex_destroy(&pipeline->lock);
    ngfw_free(pipeline);
}

ngfw_ret_t pipeline_init(pipeline_t *pipeline)
{
    if (!pipeline) return NGFW_ERR_INVALID;

    pipeline->initialized = true;

    log_info("Pipeline initialized");

    return NGFW_OK;
}

ngfw_ret_t pipeline_start(pipeline_t *pipeline)
{
    if (!pipeline || !pipeline->initialized) return NGFW_ERR_INVALID;

    pipeline->running = true;

    log_info("Pipeline started");

    return NGFW_OK;
}

ngfw_ret_t pipeline_stop(pipeline_t *pipeline)
{
    if (!pipeline) return NGFW_ERR_INVALID;

    pipeline->running = false;

    log_info("Pipeline stopped");

    return NGFW_OK;
}

ngfw_ret_t pipeline_register_hook(pipeline_t *pipeline, pipeline_stage_t stage, pipeline_hook_t hook, void *data)
{
    if (!pipeline || !hook) return NGFW_ERR_INVALID;
    if (stage >= 5) return NGFW_ERR_INVALID;

    if (pipeline->num_hooks[stage] >= MAX_HOOKS_PER_STAGE) {
        return NGFW_ERR_NO_RESOURCE;
    }

    pipeline->hooks[stage][pipeline->num_hooks[stage]].hook = hook;
    pipeline->hooks[stage][pipeline->num_hooks[stage]].data = data;
    pipeline->num_hooks[stage]++;

    log_debug("Hook registered for stage %d", stage);

    return NGFW_OK;
}

ngfw_ret_t pipeline_unregister_hook(pipeline_t *pipeline, pipeline_stage_t stage, pipeline_hook_t hook)
{
    if (!pipeline || !hook) return NGFW_ERR_INVALID;
    if (stage >= 5) return NGFW_ERR_INVALID;

    for (int i = 0; i < pipeline->num_hooks[stage]; i++) {
        if (pipeline->hooks[stage][i].hook == hook) {
            for (int j = i; j < pipeline->num_hooks[stage] - 1; j++) {
                pipeline->hooks[stage][j] = pipeline->hooks[stage][j + 1];
            }
            pipeline->num_hooks[stage]--;
            return NGFW_OK;
        }
    }

    return NGFW_ERR;
}

static pipeline_action_t run_hooks(pipeline_t *pipeline, pipeline_context_t *ctx)
{
    int stage_idx = (int)ctx->stage;

    for (int i = 0; i < pipeline->num_hooks[stage_idx]; i++) {
        pipeline_action_t action = pipeline->hooks[stage_idx][i].hook(ctx);

        switch (action) {
            case PIPELINE_ACTION_DROP:
                return PIPELINE_ACTION_DROP;
            case PIPELINE_ACTION_REJECT:
                return PIPELINE_ACTION_REJECT;
            case PIPELINE_ACTION_QUEUE:
                return PIPELINE_ACTION_QUEUE;
            case PIPELINE_ACTION_ACCEPT:
                return PIPELINE_ACTION_ACCEPT;
            case PIPELINE_ACTION_LOG:
                log_debug("Packet logged at stage %d", ctx->stage);
                break;
            case PIPELINE_ACTION_CONTINUE:
            default:
                break;
        }
    }

    return PIPELINE_ACTION_CONTINUE;
}

ngfw_ret_t pipeline_process_packet(pipeline_t *pipeline, packet_t *pkt, pipeline_stage_t stage)
{
    if (!pipeline || !pkt) return NGFW_ERR_INVALID;
    if (!pipeline->running) return NGFW_ERR_NOT_SUPPORTED;

    pipeline_context_t ctx = {
        .packet = pkt,
        .session = NULL,
        .stage = stage,
        .action = PIPELINE_ACTION_CONTINUE,
        .rule_id = 0,
        .session_id = 0,
        .nat_applied = false,
        .qos_applied = false,
        .vpn_decrypted = false,
        .ips_checked = false,
        .url_checked = false,
        .timestamp = get_ms_time(),
        .user_data = NULL,
    };

    pipeline_action_t result = run_hooks(pipeline, &ctx);

    pipeline->stats.packets_processed++;
    pipeline->stats.bytes_processed += pkt->len;

    switch (result) {
        case PIPELINE_ACTION_ACCEPT:
        case PIPELINE_ACTION_CONTINUE:
            pipeline->stats.packets_accepted++;
            return NGFW_OK;

        case PIPELINE_ACTION_DROP:
            pipeline->stats.packets_dropped++;
            return NGFW_ERR;

        case PIPELINE_ACTION_REJECT:
            pipeline->stats.packets_rejected++;
            return NGFW_ERR;

        case PIPELINE_ACTION_QUEUE:
            pipeline->stats.packets_queued++;
            return NGFW_ERR_NO_RESOURCE;

        default:
            return NGFW_OK;
    }
}

pipeline_stats_t *pipeline_get_stats(pipeline_t *pipeline)
{
    if (!pipeline) return NULL;
    return &pipeline->stats;
}

void pipeline_reset_stats(pipeline_t *pipeline)
{
    if (!pipeline) return;
    memset(&pipeline->stats, 0, sizeof(pipeline_stats_t));
}
