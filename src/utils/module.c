#include "ngfw/module.h"
#include "ngfw/log.h"
#include <stddef.h>
#include <string.h>

static const char *module_type_names[MODULE_TYPE_COUNT] = {
    "filter",
    "ips",
    "urlfilter",
    "antivirus",
    "vpn",
    "nat",
    "qos",
    "ddos"
};

static const char *module_state_names[] = {
    "none",
    "initialized",
    "started",
    "stopped",
    "error"
};

const char *module_type_name(module_type_t type)
{
    if (type >= MODULE_TYPE_COUNT) return "unknown";
    return module_type_names[type];
}

const char *module_state_name(module_state_t state)
{
    if (state >= MODULE_STATE_ERROR) return "unknown";
    return module_state_names[state];
}

ngfw_ret_t module_init(ngfw_module_t *mod)
{
    if (!mod) return NGFW_ERR_INVALID;
    if (!mod->ops || !mod->ops->init) return NGFW_ERR_INVALID;
    
    mod->state = MODULE_STATE_INIT;
    return mod->ops->init(mod);
}

ngfw_ret_t module_start(ngfw_module_t *mod)
{
    if (!mod) return NGFW_ERR_INVALID;
    if (!mod->ops || !mod->ops->start) return NGFW_ERR_INVALID;
    if (mod->state != MODULE_STATE_INIT && mod->state != MODULE_STATE_STOPPED) {
        return NGFW_ERR_INVALID;
    }
    
    ngfw_ret_t ret = mod->ops->start(mod);
    if (ret == NGFW_OK) {
        mod->state = MODULE_STATE_STARTED;
    } else {
        mod->state = MODULE_STATE_ERROR;
    }
    return ret;
}

ngfw_ret_t module_stop(ngfw_module_t *mod)
{
    if (!mod) return NGFW_ERR_INVALID;
    if (!mod->ops || !mod->ops->stop) return NGFW_ERR_INVALID;
    if (mod->state != MODULE_STATE_STARTED) {
        return NGFW_ERR_INVALID;
    }
    
    ngfw_ret_t ret = mod->ops->stop(mod);
    if (ret == NGFW_OK) {
        mod->state = MODULE_STATE_STOPPED;
    }
    return ret;
}

ngfw_ret_t module_process(ngfw_module_t *mod, void *data)
{
    if (!mod || !mod->ops || !mod->ops->process) return NGFW_ERR_INVALID;
    if (mod->state != MODULE_STATE_STARTED) return NGFW_ERR_INVALID;
    if (!(mod->flags & MODULE_FLAG_ENABLED)) return NGFW_OK;
    
    return mod->ops->process(mod, data);
}

ngfw_ret_t module_config(ngfw_module_t *mod, const void *config)
{
    if (!mod) return NGFW_ERR_INVALID;
    if (!mod->ops || !mod->ops->config) return NGFW_ERR_INVALID;
    
    return mod->ops->config(mod, config);
}

ngfw_ret_t module_get_stats(ngfw_module_t *mod, void *stats)
{
    if (!mod || !mod->ops || !mod->ops->get_stats) return NGFW_ERR_INVALID;
    
    return mod->ops->get_stats(mod, stats);
}

void module_destroy(ngfw_module_t *mod)
{
    if (!mod) return;
    
    if (mod->ops && mod->ops->destroy) {
        mod->ops->destroy(mod);
    }
    
    mod->state = MODULE_STATE_NONE;
}
