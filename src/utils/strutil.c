#include "ngfw/strutil.h"
#include "ngfw/memory.h"
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdio.h>

char *strutil_trim(char *str)
{
    if (!str) return NULL;
    
    while (isspace((unsigned char)*str)) str++;
    
    if (*str == '\0') return str;
    
    char *end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end)) end--;
    
    end[1] = '\0';
    return str;
}

char *strutil_dup_trim(const char *str)
{
    if (!str) return NULL;
    
    while (isspace((unsigned char)*str)) str++;
    
    if (*str == '\0') return ngfw_malloc(1);
    
    const char *end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end)) end--;
    
    size_t len = end - str + 1;
    char *result = ngfw_malloc(len + 1);
    if (!result) return NULL;
    
    memcpy(result, str, len);
    result[len] = '\0';
    return result;
}

bool strutil_starts_with(const char *str, const char *prefix)
{
    if (!str || !prefix) return false;
    return strncmp(str, prefix, strlen(prefix)) == 0;
}

bool strutil_ends_with(const char *str, const char *suffix)
{
    if (!str || !suffix) return false;
    
    size_t str_len = strlen(str);
    size_t suffix_len = strlen(suffix);
    
    if (suffix_len > str_len) return false;
    
    return strcmp(str + str_len - suffix_len, suffix) == 0;
}

char *strutil_join(const char **parts, const char *sep)
{
    if (!parts || !sep) return NULL;
    
    size_t sep_len = strlen(sep);
    size_t total_len = 0;
    u32 count = 0;
    
    for (u32 i = 0; parts[i]; i++) {
        total_len += strlen(parts[i]);
        count++;
    }
    
    if (count == 0) return ngfw_malloc(1);
    
    total_len += (count - 1) * sep_len + 1;
    
    char *result = ngfw_malloc(total_len);
    if (!result) return NULL;
    
    result[0] = '\0';
    for (u32 i = 0; i < count; i++) {
        if (i > 0) strcat(result, sep);
        strcat(result, parts[i]);
    }
    
    return result;
}

char **strutil_split(const char *str, char delim, u32 *count)
{
    if (!str || !count) return NULL;
    
    *count = 0;
    for (const char *p = str; *p; p++) {
        if (*p == delim) (*count)++;
    }
    (*count)++;
    
    char **parts = ngfw_malloc(*count * sizeof(char *));
    if (!parts) return NULL;
    
    char buffer[4096];
    u32 part_idx = 0;
    u32 buf_pos = 0;
    
    for (const char *p = str; *p; p++) {
        if (*p == delim) {
            buffer[buf_pos] = '\0';
            parts[part_idx] = ngfw_malloc(buf_pos + 1);
            if (parts[part_idx]) {
                strcpy(parts[part_idx], buffer);
            }
            part_idx++;
            buf_pos = 0;
        } else {
            if (buf_pos < sizeof(buffer) - 1) {
                buffer[buf_pos++] = *p;
            }
        }
    }
    
    buffer[buf_pos] = '\0';
    parts[part_idx] = ngfw_malloc(buf_pos + 1);
    if (parts[part_idx]) {
        strcpy(parts[part_idx], buffer);
    }
    
    return parts;
}

void strutil_free_split(char **parts, u32 count)
{
    if (!parts) return;
    for (u32 i = 0; i < count; i++) {
        ngfw_free(parts[i]);
    }
    ngfw_free(parts);
}

char *strutil_replace(const char *str, const char *old, const char *new_str)
{
    if (!str || !old || !new_str) return NULL;
    
    size_t old_len = strlen(old);
    size_t new_len = strlen(new_str);
    size_t str_len = strlen(str);
    
    if (old_len == 0) return ngfw_malloc(1);
    
    u32 count = 0;
    const char *p = str;
    while ((p = strstr(p, old)) != NULL) {
        count++;
        p += old_len;
    }
    
    if (count == 0) {
        char *result = ngfw_malloc(str_len + 1);
        if (result) strcpy(result, str);
        return result;
    }
    
    size_t result_len = str_len + count * (new_len - old_len);
    char *result = ngfw_malloc(result_len + 1);
    if (!result) return NULL;
    
    char *dest = result;
    p = str;
    while (*p) {
        const char *match = strstr(p, old);
        if (!match) {
            strcpy(dest, p);
            break;
        }
        
        size_t prefix_len = match - p;
        memcpy(dest, p, prefix_len);
        dest += prefix_len;
        
        memcpy(dest, new_str, new_len);
        dest += new_len;
        
        p = match + old_len;
    }
    
    result[result_len] = '\0';
    return result;
}

char *strutil_to_lower(const char *str)
{
    if (!str) return NULL;
    
    char *result = ngfw_malloc(strlen(str) + 1);
    if (!result) return NULL;
    
    char *p = result;
    while (*str) {
        *p++ = tolower(*str++);
    }
    *p = '\0';
    
    return result;
}

char *strutil_to_upper(const char *str)
{
    if (!str) return NULL;
    
    char *result = ngfw_malloc(strlen(str) + 1);
    if (!result) return NULL;
    
    char *p = result;
    while (*str) {
        *p++ = toupper(*str++);
    }
    *p = '\0';
    
    return result;
}

bool strutil_equals_ignore_case(const char *a, const char *b)
{
    if (!a || !b) return false;
    
    while (*a && *b) {
        if (tolower(*a) != tolower(*b)) return false;
        a++;
        b++;
    }
    
    return *a == *b;
}

char *strutil_hex_encode(const u8 *data, u32 len)
{
    if (!data || len == 0) return NULL;
    
    char *result = ngfw_malloc(len * 2 + 1);
    if (!result) return NULL;
    
    for (u32 i = 0; i < len; i++) {
        sprintf(result + i * 2, "%02x", data[i]);
    }
    result[len * 2] = '\0';
    
    return result;
}

char *strutil_hex_decode(const char *hex, u32 *out_len)
{
    if (!hex || !out_len) return NULL;
    
    size_t hex_len = strlen(hex);
    if (hex_len % 2 != 0) return NULL;
    
    *out_len = hex_len / 2;
    u8 *result = ngfw_malloc(*out_len);
    if (!result) return NULL;
    
    for (size_t i = 0; i < *out_len; i++) {
        char byte_str[3] = {hex[i*2], hex[i*2+1], '\0'};
        char *end;
        result[i] = (u8)strtol(byte_str, &end, 16);
        if (*end != '\0') {
            ngfw_free(result);
            return NULL;
        }
    }
    
    return (char *)result;
}

u32 strutil_hash(const char *str)
{
    if (!str) return 0;
    
    u32 hash = 5381;
    while (*str) {
        hash = ((hash << 5) + hash) + (*str++);
    }
    return hash;
}
