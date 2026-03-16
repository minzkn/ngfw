#include "ngfw/config.h"
#include "ngfw/memory.h"
#include "ngfw/log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

static char *config_trim(char *str)
{
    while (isspace(*str)) str++;
    if (*str == 0) return str;

    char *end = str + strlen(str) - 1;
    while (end > str && isspace(*end)) end--;
    end[1] = '\0';

    return str;
}

static char *config_read_line(FILE *fp)
{
    static char line[4096];
    if (fgets(line, sizeof(line), fp) == NULL) return NULL;
    
    size_t len = strlen(line);
    if (len > 0 && line[len-1] == '\n') line[len-1] = '\0';
    if (len > 1 && line[len-2] == '\r') line[len-2] = '\0';
    
    return line;
}

config_t *config_create(void)
{
    config_t *config = ngfw_malloc(sizeof(config_t));
    if (!config) return NULL;

    memset(&config->root, 0, sizeof(config_object_t));
    config->filename = NULL;

    return config;
}

void config_destroy(config_t *config)
{
    if (!config) return;

    for (u32 i = 0; i < config->root.count; i++) {
        ngfw_free(config->root.keys[i]);
        if (config->root.values[i].type == CONFIG_TYPE_STRING) {
            ngfw_free(config->root.values[i].value.str);
        }
    }
    ngfw_free(config->root.keys);
    ngfw_free(config->root.values);
    ngfw_free(config->filename);
    ngfw_free(config);
}

ngfw_ret_t config_load(config_t *config, const char *filename)
{
    if (!config || !filename) return NGFW_ERR_INVALID;

    return config_parse_file(config, filename);
}

ngfw_ret_t config_save(config_t *config, const char *filename)
{
    if (!config || !filename) return NGFW_ERR_INVALID;

    FILE *fp = fopen(filename, "w");
    if (!fp) return NGFW_ERR_INVALID;

    fprintf(fp, "# NGFW Configuration File\n\n");

    for (u32 i = 0; i < config->root.count; i++) {
        fprintf(fp, "%s = ", config->root.keys[i]);
        
        switch (config->root.values[i].type) {
            case CONFIG_TYPE_STRING:
                fprintf(fp, "\"%s\"\n", config->root.values[i].value.str);
                break;
            case CONFIG_TYPE_INT:
                fprintf(fp, "%d\n", config->root.values[i].value.num);
                break;
            case CONFIG_TYPE_BOOL:
                fprintf(fp, "%s\n", config->root.values[i].value.boolean ? "true" : "false");
                break;
            default:
                fprintf(fp, "\n");
        }
    }

    fclose(fp);
    return NGFW_OK;
}

ngfw_ret_t config_get_value(config_t *config, const char *path, config_value_t *value)
{
    if (!config || !path || !value) return NGFW_ERR_INVALID;
    
    char path_copy[256];
    strncpy(path_copy, path, sizeof(path_copy) - 1);
    path_copy[sizeof(path_copy) - 1] = '\0';
    
    char *dot = strchr(path_copy, '.');
    char *key = path_copy;
    char *subpath = NULL;
    
    if (dot) {
        *dot = '\0';
        subpath = dot + 1;
    }
    
    if (!config->root.keys) return NGFW_ERR;
    
    for (u32 i = 0; i < config->root.count; i++) {
        if (config->root.keys[i] && strcmp(config->root.keys[i], key) == 0) {
            if (subpath && config->root.values[i].type == CONFIG_TYPE_OBJECT && config->root.values[i].value.obj) {
                config_object_t *obj = config->root.values[i].value.obj;
                for (u32 j = 0; j < obj->count; j++) {
                    if (obj->keys && obj->keys[j] && strcmp(obj->keys[j], subpath) == 0) {
                        *value = obj->values[j];
                        return NGFW_OK;
                    }
                }
            }
            *value = config->root.values[i];
            return NGFW_OK;
        }
    }
    
    return NGFW_ERR;
}

ngfw_ret_t config_set_value(config_t *config, const char *path, config_value_t *value)
{
    if (!config || !path || !value) return NGFW_ERR_INVALID;
    
    char path_copy[256];
    strncpy(path_copy, path, sizeof(path_copy) - 1);
    path_copy[sizeof(path_copy) - 1] = '\0';
    
    char *dot = strchr(path_copy, '.');
    char *key = path_copy;
    char *subpath = NULL;
    
    if (dot) {
        *dot = '\0';
        subpath = dot + 1;
    }
    
    if (!config->root.keys) return NGFW_ERR;
    
    for (u32 i = 0; i < config->root.count; i++) {
        if (config->root.keys[i] && strcmp(config->root.keys[i], key) == 0) {
            if (subpath && config->root.values[i].type == CONFIG_TYPE_OBJECT && config->root.values[i].value.obj) {
                config_object_t *obj = config->root.values[i].value.obj;
                for (u32 j = 0; j < obj->count; j++) {
                    if (obj->keys && obj->keys[j] && strcmp(obj->keys[j], subpath) == 0) {
                        obj->values[j] = *value;
                        return NGFW_OK;
                    }
                }
            }
            config->root.values[i] = *value;
            return NGFW_OK;
        }
    }
    
    return NGFW_ERR;
}

ngfw_ret_t config_to_ngfw_config(config_t *config, ngfw_config_t *ngfw_config)
{
    if (!config || !ngfw_config) return NGFW_ERR_INVALID;

    memset(ngfw_config, 0, sizeof(ngfw_config_t));

    ngfw_config->session.max_sessions = 100000;
    ngfw_config->session.session_timeout = 300;
    ngfw_config->session.cleanup_interval = 60;

    ngfw_config->filter.enabled = true;
    ngfw_config->filter.max_rules = 65536;

    ngfw_config->ips.enabled = true;
    strcpy(ngfw_config->ips.signatures_file, "/etc/ngfw/signatures.db");

    ngfw_config->logging.enabled = true;
    ngfw_config->logging.log_level = LOG_INFO;
    strcpy(ngfw_config->logging.log_file, "/var/log/ngfw.log");
    ngfw_config->logging.max_size = 10 * 1024 * 1024;
    ngfw_config->logging.max_files = 5;

    ngfw_config->webui.enabled = false;
    strcpy(ngfw_config->webui.listen_addr, "0.0.0.0");
    ngfw_config->webui.port = 8443;

    ngfw_config->vpn.enabled = false;
    ngfw_config->urlfilter.enabled = false;
    ngfw_config->qos.enabled = false;

    return NGFW_OK;
}

config_value_t *config_value_create_string(const char *str)
{
    config_value_t *val = ngfw_malloc(sizeof(config_value_t));
    if (!val) return NULL;

    val->type = CONFIG_TYPE_STRING;
    val->value.str = strdup(str);

    return val;
}

config_value_t *config_value_create_int(s32 num)
{
    config_value_t *val = ngfw_malloc(sizeof(config_value_t));
    if (!val) return NULL;

    val->type = CONFIG_TYPE_INT;
    val->value.num = num;

    return val;
}

config_value_t *config_value_create_bool(bool val)
{
    config_value_t *value = ngfw_malloc(sizeof(config_value_t));
    if (!value) return NULL;

    value->type = CONFIG_TYPE_BOOL;
    value->value.boolean = val;

    return value;
}

void config_value_destroy(config_value_t *val)
{
    if (!val) return;

    if (val->type == CONFIG_TYPE_STRING && val->value.str) {
        free(val->value.str);
    }
    ngfw_free(val);
}

static ngfw_ret_t config_add_entry(config_object_t *obj, const char *key, config_value_t *value)
{
    char **new_keys = ngfw_realloc(obj->keys, sizeof(char *) * (obj->count + 1));
    if (!new_keys) return NGFW_ERR_NO_MEM;

    config_value_t *new_values = ngfw_realloc(obj->values, sizeof(config_value_t) * (obj->count + 1));
    if (!new_values) {
        ngfw_free(new_keys);
        return NGFW_ERR_NO_MEM;
    }

    obj->keys = new_keys;
    obj->values = new_values;

    obj->keys[obj->count] = strdup(key);
    memcpy(&obj->values[obj->count], value, sizeof(config_value_t));
    obj->count++;

    return NGFW_OK;
}

ngfw_ret_t config_parse_file(config_t *config, const char *filename)
{
    FILE *fp = fopen(filename, "r");
    if (!fp) {
        log_warn("Config file not found: %s, using defaults", filename);
        return config_to_ngfw_config(config, (ngfw_config_t *)config);
    }

    char *line;
    while ((line = config_read_line(fp)) != NULL) {
        line = config_trim(line);

        if (line[0] == '#' || line[0] == '\0') continue;

        char *eq = strchr(line, '=');
        if (!eq) continue;

        *eq = '\0';
        char *key = config_trim(line);
        char *value = config_trim(eq + 1);

        if (value[0] == '"') {
            value++;
            size_t len = strlen(value);
            if (len > 0 && value[len-1] == '"') {
                value[len-1] = '\0';
            }
            config_value_t val;
            val.type = CONFIG_TYPE_STRING;
            val.value.str = value;
            config_add_entry(&config->root, key, &val);
        } else if (strcmp(value, "true") == 0 || strcmp(value, "false") == 0) {
            config_value_t val;
            val.type = CONFIG_TYPE_BOOL;
            val.value.boolean = (strcmp(value, "true") == 0);
            config_add_entry(&config->root, key, &val);
        } else {
            config_value_t val;
            val.type = CONFIG_TYPE_INT;
            val.value.num = atoi(value);
            config_add_entry(&config->root, key, &val);
        }
    }

    fclose(fp);
    return NGFW_OK;
}

ngfw_ret_t config_parse_json(config_t *config, const char *json)
{
    if (!config || !json) return NGFW_ERR_INVALID;
    
    (void)config;
    (void)json;
    return NGFW_ERR;
}

ngfw_ret_t config_load_default(ngfw_config_t *config)
{
    if (!config) return NGFW_ERR_INVALID;

    config->session.max_sessions = 100000;
    config->session.session_timeout = 300;
    config->session.cleanup_interval = 60;

    config->filter.enabled = true;
    config->filter.max_rules = 65536;

    config->ips.enabled = true;
    config->ips.signatures_file[0] = '\0';

    config->logging.enabled = true;
    config->logging.log_level = LOG_INFO;
    strcpy(config->logging.log_file, "/var/log/ngfw.log");
    config->logging.max_size = 10 * 1024 * 1024;
    config->logging.max_files = 5;

    config->webui.enabled = false;
    config->webui.listen_addr[0] = '\0';
    config->webui.port = 8443;

    config->vpn.enabled = false;
    config->urlfilter.enabled = false;
    config->qos.enabled = false;

    return NGFW_OK;
}
