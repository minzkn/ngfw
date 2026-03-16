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

#ifndef NGFW_BLOOM_H
#define NGFW_BLOOM_H

#include "ngfw/types.h"
#include <stdbool.h>
#include <stddef.h>

typedef struct bloom_filter bloom_filter_t;

bloom_filter_t *bloom_create(u64 expected_items, double false_positive_rate);
void bloom_destroy(bloom_filter_t *bloom);
void bloom_add(bloom_filter_t *bloom, const void *data, u32 len);
bool bloom_test(bloom_filter_t *bloom, const void *data, u32 len);
void bloom_clear(bloom_filter_t *bloom);
u64 bloom_size(bloom_filter_t *bloom);
u64 bloom_capacity(bloom_filter_t *bloom);
double bloom_false_positive_rate(bloom_filter_t *bloom);

#endif
