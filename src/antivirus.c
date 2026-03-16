#include "ngfw/antivirus.h"
#include "ngfw/memory.h"
#include "ngfw/hash.h"
#include "ngfw/log.h"
#include "ngfw/crypto.h"
#include "ngfw/platform.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

#define MAX_AV_SIGNATURES 8192
#define MAX_AV_ALERTS 2048

typedef struct av_signature_impl {
    av_signature_t sig;
    struct av_signature_impl *next;
} av_signature_impl_t;

typedef struct av_alert_impl {
    av_alert_t alert;
    struct av_alert_impl *next;
} av_alert_impl_t;

struct antivirus {
    hash_table_t *signatures;
    av_signature_impl_t *sig_list;
    av_alert_impl_t *alert_list;
    av_alert_impl_t *alert_tail;
    av_stats_t stats;
    bool initialized;
    bool running;
    u32 next_alert_id;
};

static u32 av_sig_hash(const void *key, u32 size)
{
    return (*(const u32 *)key) % size;
}

static bool av_sig_match(const void *key1, const void *key2)
{
    return (*(const u32 *)key1) == (*(const u32 *)key2);
}

static void load_default_av_signatures(antivirus_t *av)
{
    av_signature_t default_sigs[] = {
        {1, "EICAR Test", "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*", AV_THREAT_VIRUS, "EICAR-Test", "Standard antivirus test file", true, 1},
        {2, "Win32.Trojan.Generic", "MZ.*This program cannot be run in DOS mode", AV_THREAT_TROJAN, "Win32.Trojan", "Generic Windows trojan", true, 1},
        {3, "Win32.Backdoor.Generic", "PE.*\\x00\\x00\\x00.*GetProcAddress", AV_THREAT_BACKDOOR, "Win32.Backdoor", "Generic backdoor", true, 1},
        {4, "Win64.Cryptor", "PE.*\\x00\\x64\\x86", AV_THREAT_Ransomware, "Win64.Cryptor", "64-bit ransomware", true, 1},
        {5, "JS.Malware", "<script>.*eval.*atob", AV_THREAT_EXPLOIT, "JS.Malware", "JavaScript malware", true, 1},
        {6, "PHP.Shell", "<?php.*system.*\\$_", AV_THREAT_BACKDOOR, "PHP.Shell", "PHP webshell", true, 1},
        {7, "ELF.Miner", "ELF.*stratum+tcp", AV_THREAT_SPYWARE, "ELF.Miner", "Cryptocurrency miner", true, 1},
        {8, "JavaScript.CoinHive", "CoinHive.*start", AV_THREAT_ADWARE, "JavaScript.CoinHive", "Browser-based cryptocurrency miner", true, 1},
        {9, "Macro.Virus", "VBA.*Shell.*cmd", AV_THREAT_VIRUS, "Macro.Virus", "Office macro virus", true, 1},
        {10, "PDF.Exploit", "PDF.*JavaScript.*eval", AV_THREAT_EXPLOIT, "PDF.Exploit", "PDF exploit", true, 1},
    };

    int num_sigs = sizeof(default_sigs) / sizeof(av_signature_t);

    for (int i = 0; i < num_sigs; i++) {
        antivirus_add_signature(av, &default_sigs[i]);
    }

    log_info("Loaded %d default AV signatures", num_sigs);
}

antivirus_t *antivirus_create(void)
{
    antivirus_t *av = ngfw_malloc(sizeof(antivirus_t));
    if (!av) return NULL;

    memset(av, 0, sizeof(antivirus_t));

    av->signatures = hash_create(1024, av_sig_hash, av_sig_match, NULL);
    if (!av->signatures) {
        ngfw_free(av);
        return NULL;
    }

    av->sig_list = NULL;
    av->alert_list = NULL;
    av->alert_tail = NULL;
    av->next_alert_id = 1;

    load_default_av_signatures(av);

    log_info("Anti-Virus created with default signatures");

    return av;
}

void antivirus_destroy(antivirus_t *av)
{
    if (!av) return;

    if (av->signatures) {
        hash_destroy(av->signatures);
    }

    av_signature_impl_t *sig = av->sig_list;
    while (sig) {
        av_signature_impl_t *next = sig->next;
        ngfw_free(sig);
        sig = next;
    }

    av_alert_impl_t *alert = av->alert_list;
    while (alert) {
        av_alert_impl_t *next = alert->next;
        ngfw_free(alert);
        alert = next;
    }

    ngfw_free(av);
}

ngfw_ret_t antivirus_init(antivirus_t *av)
{
    if (!av) return NGFW_ERR_INVALID;

    av->initialized = true;

    log_info("Anti-Virus initialized");

    return NGFW_OK;
}

ngfw_ret_t antivirus_start(antivirus_t *av)
{
    if (!av || !av->initialized) return NGFW_ERR_INVALID;

    av->running = true;

    log_info("Anti-Virus started");

    return NGFW_OK;
}

ngfw_ret_t antivirus_stop(antivirus_t *av)
{
    if (!av) return NGFW_ERR_INVALID;

    av->running = false;

    log_info("Anti-Virus stopped");

    return NGFW_OK;
}

ngfw_ret_t antivirus_add_signature(antivirus_t *av, av_signature_t *sig)
{
    if (!av || !sig) return NGFW_ERR_INVALID;

    av_signature_impl_t *impl = ngfw_malloc(sizeof(av_signature_impl_t));
    if (!impl) return NGFW_ERR_NO_MEM;

    impl->sig = *sig;
    impl->next = NULL;

    hash_insert(av->signatures, &sig->id, impl);

    impl->next = av->sig_list;
    av->sig_list = impl;

    av->stats.signatures_loaded++;
    if (sig->enabled) {
        av->stats.signatures_enabled++;
    }

    log_debug("Anti-Virus signature added: %s (ID: %u)", sig->name, sig->id);

    return NGFW_OK;
}

ngfw_ret_t antivirus_del_signature(antivirus_t *av, u32 sig_id)
{
    if (!av) return NGFW_ERR_INVALID;

    hash_remove(av->signatures, &sig_id);

    log_debug("Anti-Virus signature deleted: %u", sig_id);

    return NGFW_OK;
}

ngfw_ret_t antivirus_enable_signature(antivirus_t *av, u32 sig_id)
{
    if (!av) return NGFW_ERR_INVALID;

    av_signature_impl_t *impl = hash_lookup(av->signatures, &sig_id);
    if (!impl) return NGFW_ERR_INVALID;

    if (!impl->sig.enabled) {
        impl->sig.enabled = true;
        av->stats.signatures_enabled++;
    }

    return NGFW_OK;
}

ngfw_ret_t antivirus_disable_signature(antivirus_t *av, u32 sig_id)
{
    if (!av) return NGFW_ERR_INVALID;

    av_signature_impl_t *impl = hash_lookup(av->signatures, &sig_id);
    if (!impl) return NGFW_ERR_INVALID;

    if (impl->sig.enabled) {
        impl->sig.enabled = false;
        av->stats.signatures_enabled--;
    }

    return NGFW_OK;
}

ngfw_ret_t antivirus_load_signatures(antivirus_t *av, const char *filename)
{
    if (!av || !filename) return NGFW_ERR_INVALID;

    FILE *fp = fopen(filename, "r");
    if (!fp) {
        log_err("Failed to open AV signature file: %s", filename);
        return NGFW_ERR;
    }

    char line[1024];
    int loaded = 0;

    while (fgets(line, sizeof(line), fp)) {
        if (line[0] == '#' || line[0] == '\n') continue;

        av_signature_t sig = {0};
        if (sscanf(line, "%u|%[^|]|%[^|]|%d|%[^|]",
                   &sig.id, sig.name, sig.pattern,
                   (int*)&sig.threat_type, sig.threat_name) >= 3) {
            sig.enabled = true;
            sig.rev = 1;
            antivirus_add_signature(av, &sig);
            loaded++;
        }
    }

    fclose(fp);

    log_info("Loaded %d AV signatures from %s", loaded, filename);

    return NGFW_OK;
}

ngfw_ret_t antivirus_save_signatures(antivirus_t *av, const char *filename)
{
    if (!av || !filename) return NGFW_ERR_INVALID;

    FILE *fp = fopen(filename, "w");
    if (!fp) {
        return NGFW_ERR;
    }

    fprintf(fp, "# NGFW Anti-Virus Signatures\n");
    fprintf(fp, "# Format: id|name|pattern|threat_type|threat_name\n\n");

    av_signature_impl_t *sig = av->sig_list;
    while (sig) {
        fprintf(fp, "%u|%s|%s|%d|%s\n",
                sig->sig.id, sig->sig.name, sig->sig.pattern,
                sig->sig.threat_type, sig->sig.threat_name);
        sig = sig->next;
    }

    fclose(fp);

    return NGFW_OK;
}

static int av_pattern_match(const char *pattern, const u8 *data, u32 data_len)
{
    if (!pattern || !data) return 0;

    size_t pattern_len = strlen(pattern);

    if (pattern_len == 0) return 0;

    if (pattern[0] == 'M' && pattern[1] == 'Z') {
        return (data_len >= 2 && data[0] == 0x4D && data[1] == 0x5A) ? 1 : 0;
    }

    if (pattern[0] == 'P' && pattern[1] == 'E') {
        return (data_len >= 2 && data[0] == 0x50 && data[1] == 0x45) ? 1 : 0;
    }

    if (strstr(pattern, ".*")) {
        const char *p = pattern;
        u32 data_pos = 0;

        while (*p && data_pos < data_len) {
            if (*p == '.') {
                p++;
                if (*p == '*') {
                    p++;
                    continue;
                }
            }

            if (*p == '\\') {
                p++;
                if (*p == 'x' && data_pos + 1 < data_len) {
                    unsigned int byte;
                    if (sscanf(p + 1, "%2x", &byte) == 1) {
                        if (data[data_pos] != (u8)byte) return 0;
                        data_pos++;
                        p += 3;
                        continue;
                    }
                }
            }

            if (*p == data[data_pos]) {
                p++;
                data_pos++;
            } else {
                return 0;
            }
        }

        return (*p == '\0') ? 1 : 0;
    }

    return (data_len >= pattern_len && memcmp(data, pattern, pattern_len) == 0) ? 1 : 0;
}

ngfw_ret_t antivirus_scan_buffer(antivirus_t *av, const u8 *buffer, u32 len, av_scan_result_t *result, av_alert_t *alert)
{
    if (!av || !buffer || !result) return NGFW_ERR_INVALID;

    *result = AV_SCAN_RESULT_CLEAN;

    av->stats.files_scanned++;
    av->stats.bytes_scanned += len;

    av_signature_impl_t *sig = av->sig_list;
    while (sig) {
        if (!sig->sig.enabled) {
            sig = sig->next;
            continue;
        }

        if (len > 0) {
            if (av_pattern_match(sig->sig.pattern, buffer, len)) {
                *result = AV_SCAN_RESULT_INFECTED;
                av->stats.files_infected++;
                av->stats.files_blocked++;

                if (alert) {
                    alert->id = av->next_alert_id++;
                    alert->signature_id = sig->sig.id;
                    strncpy(alert->signature_name, sig->sig.name, sizeof(alert->signature_name) - 1);
                    alert->threat_type = sig->sig.threat_type;
                    strncpy(alert->threat_name, sig->sig.threat_name, sizeof(alert->threat_name) - 1);
                    alert->timestamp = get_ms_time();
                    snprintf(alert->message, sizeof(alert->message),
                             "%s - %s", sig->sig.name, sig->sig.description);

                    av_alert_impl_t *impl = ngfw_malloc(sizeof(av_alert_impl_t));
                    if (impl) {
                        impl->alert = *alert;
                        impl->next = NULL;

                        if (av->alert_tail) {
                            av->alert_tail->next = impl;
                            av->alert_tail = impl;
                        } else {
                            av->alert_list = impl;
                            av->alert_tail = impl;
                        }
                    }
                }

                log_warn("Anti-Virus Alert: %s (Threat: %s)", sig->sig.name, sig->sig.threat_name);

                return NGFW_OK;
            }
        }

        sig = sig->next;
    }

    av->stats.scans_passed++;

    return NGFW_OK;
}

ngfw_ret_t antivirus_scan_packet(antivirus_t *av, packet_t *pkt, av_scan_result_t *result, av_alert_t *alert)
{
    if (!av || !pkt) return NGFW_ERR_INVALID;

    u8 *data = pkt->data;
    u32 data_len = pkt->len;

    if (!data || data_len == 0) {
        return NGFW_ERR;
    }

    return antivirus_scan_buffer(av, data, data_len, result, alert);
}

av_stats_t *antivirus_get_stats(antivirus_t *av)
{
    if (!av) return NULL;
    return &av->stats;
}

void antivirus_reset_stats(antivirus_t *av)
{
    if (!av) return;
    memset(&av->stats, 0, sizeof(av_stats_t));
}

void antivirus_reset_alerts(antivirus_t *av)
{
    if (!av) return;

    av_alert_impl_t *alert = av->alert_list;
    while (alert) {
        av_alert_impl_t *next = alert->next;
        ngfw_free(alert);
        alert = next;
    }

    av->alert_list = NULL;
    av->alert_tail = NULL;
    av->next_alert_id = 1;
}

ngfw_ret_t antivirus_get_alerts(antivirus_t *av, av_alert_t **alerts, u32 *count)
{
    if (!av || !alerts || !count) return NGFW_ERR_INVALID;

    u32 total = 0;
    av_alert_impl_t *alert = av->alert_list;
    while (alert) {
        total++;
        alert = alert->next;
    }
    
    if (total == 0) {
        *alerts = NULL;
        *count = 0;
        return NGFW_OK;
    }

    *alerts = ngfw_malloc(total * sizeof(av_alert_t));
    if (!*alerts) return NGFW_ERR_NO_MEM;

    u32 i = 0;
    alert = av->alert_list;
    while (alert) {
        (*alerts)[i].id = alert->alert.id;
        (*alerts)[i].signature_id = alert->alert.signature_id;
        strncpy((*alerts)[i].signature_name, alert->alert.signature_name, sizeof((*alerts)[i].signature_name) - 1);
        (*alerts)[i].threat_type = alert->alert.threat_type;
        strncpy((*alerts)[i].threat_name, alert->alert.threat_name, sizeof((*alerts)[i].threat_name) - 1);
        (*alerts)[i].timestamp = alert->alert.timestamp;
        strncpy((*alerts)[i].message, alert->alert.message, sizeof((*alerts)[i].message) - 1);
        i++;
        alert = alert->next;
    }

    *count = i;
    return NGFW_OK;
}
