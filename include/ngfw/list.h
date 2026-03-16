#ifndef NGFW_LIST_H
#define NGFW_LIST_H

#include "types.h"

typedef struct list_node {
    struct list_node *next;
    struct list_node *prev;
    void *data;
} list_node_t;

typedef struct list {
    list_node_t *head;
    list_node_t *tail;
    u32 count;
    void (*destroy)(void *);
} list_t;

list_t *list_create(void (*destroy)(void *));
void list_destroy(list_t *list);
ngfw_ret_t list_append(list_t *list, void *data);
ngfw_ret_t list_prepend(list_t *list, void *data);
ngfw_ret_t list_remove(list_t *list, void *data);
void *list_first(list_t *list);
void *list_last(list_t *list);
bool list_empty(list_t *list);
u32 list_count(list_t *list);
#define list_for_each(list, node) for ((node) = (list)->head; (node) != NULL; (node) = (node)->next)

#endif
