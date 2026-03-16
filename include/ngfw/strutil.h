#ifndef NGFW_STRUTIL_H
#define NGFW_STRUTIL_H

#include "ngfw/types.h"
#include <stdbool.h>
#include <stddef.h>

char *strutil_trim(char *str);
char *strutil_dup_trim(const char *str);
bool strutil_starts_with(const char *str, const char *prefix);
bool strutil_ends_with(const char *str, const char *suffix);
char *strutil_join(const char **parts, const char *sep);
char **strutil_split(const char *str, char delim, u32 *count);
void strutil_free_split(char **parts, u32 count);
char *strutil_replace(const char *str, const char *old, const char *new_str);
char *strutil_to_lower(const char *str);
char *strutil_to_upper(const char *str);
bool strutil_equals_ignore_case(const char *a, const char *b);
char *strutil_hex_encode(const u8 *data, u32 len);
char *strutil_hex_decode(const char *hex, u32 *out_len);
u32 strutil_hash(const char *str);

#endif
