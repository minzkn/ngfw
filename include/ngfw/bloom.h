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
