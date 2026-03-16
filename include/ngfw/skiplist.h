#ifndef NGFW_SKIPLIST_H
#define NGFW_SKIPLIST_H

#include "ngfw/types.h"
#include <stdbool.h>
#include <stddef.h>

typedef struct skiplist skiplist_t;
typedef struct skiplist_node skiplist_node_t;

typedef int (*skiplist_compare_t)(const void *a, const void *b);

skiplist_t *skiplist_create(skiplist_compare_t compare);
void skiplist_destroy(skiplist_t *list);
bool skiplist_insert(skiplist_t *list, void *key, void *value);
void *skiplist_search(skiplist_t *list, const void *key);
bool skiplist_delete(skiplist_t *list, const void *key);
u32 skiplist_size(skiplist_t *list);
bool skiplist_empty(skiplist_t *list);

typedef bool (*skiplist_foreach_cb)(void *key, void *value, void *arg);
void skiplist_foreach(skiplist_t *list, skiplist_foreach_cb cb, void *arg);

#endif
