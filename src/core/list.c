/*
 * NGFW - Next-Generation Firewall
 * Copyright (C) 2024 NGFW Project
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 */

#include "ngfw/list.h"
#include "ngfw/memory.h"
#include <stddef.h>

list_t *list_create(void (*destroy)(void *))
{
    list_t *list = ngfw_malloc(sizeof(list_t));
    if (!list) return NULL;
    
    list->head = NULL;
    list->tail = NULL;
    list->count = 0;
    list->destroy = destroy;
    
    return list;
}

void list_destroy(list_t *list)
{
    if (!list) return;
    
    list_node_t *node = list->head;
    while (node) {
        list_node_t *next = node->next;
        if (list->destroy && node->data) {
            list->destroy(node->data);
        }
        ngfw_free(node);
        node = next;
    }
    
    ngfw_free(list);
}

ngfw_ret_t list_append(list_t *list, void *data)
{
    if (!list) return NGFW_ERR_INVALID;
    
    list_node_t *node = ngfw_malloc(sizeof(list_node_t));
    if (!node) return NGFW_ERR_NO_MEM;
    
    node->data = data;
    node->next = NULL;
    node->prev = list->tail;
    
    if (list->tail) {
        list->tail->next = node;
    }
    list->tail = node;
    
    if (!list->head) {
        list->head = node;
    }
    
    list->count++;
    return NGFW_OK;
}

ngfw_ret_t list_prepend(list_t *list, void *data)
{
    if (!list) return NGFW_ERR_INVALID;
    
    list_node_t *node = ngfw_malloc(sizeof(list_node_t));
    if (!node) return NGFW_ERR_NO_MEM;
    
    node->data = data;
    node->prev = NULL;
    node->next = list->head;
    
    if (list->head) {
        list->head->prev = node;
    }
    list->head = node;
    
    if (!list->tail) {
        list->tail = node;
    }
    
    list->count++;
    return NGFW_OK;
}

ngfw_ret_t list_remove(list_t *list, void *data)
{
    if (!list) return NGFW_ERR_INVALID;
    
    list_node_t *node = list->head;
    while (node) {
        if (node->data == data) {
            if (node->prev) {
                node->prev->next = node->next;
            } else {
                list->head = node->next;
            }
            
            if (node->next) {
                node->next->prev = node->prev;
            } else {
                list->tail = node->prev;
            }
            
            if (list->destroy && node->data) {
                list->destroy(node->data);
            }
            
            ngfw_free(node);
            list->count--;
            return NGFW_OK;
        }
        node = node->next;
    }
    
    return NGFW_ERR_INVALID;
}

void *list_first(list_t *list)
{
    if (!list || !list->head) return NULL;
    return list->head->data;
}

void *list_last(list_t *list)
{
    if (!list || !list->tail) return NULL;
    return list->tail->data;
}

bool list_empty(list_t *list)
{
    return !list || list->count == 0;
}

u32 list_count(list_t *list)
{
    return list ? list->count : 0;
}
