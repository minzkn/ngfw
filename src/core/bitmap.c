#include "ngfw/types.h"
#include "ngfw/memory.h"
#include <stddef.h>
#include <string.h>

typedef struct bitmap {
    u8 *data;
    u32 size;
} bitmap_t;

void *bitmap_create(u32 bits)
{
    u32 bytes = (bits + 7) / 8;
    u8 *data = ngfw_calloc(bytes, 1);
    return data;
}

void bitmap_destroy(void *bitmap)
{
    ngfw_free(bitmap);
}

void bitmap_set(void *bitmap, u32 bit)
{
    u8 *data = (u8 *)bitmap;
    data[bit / 8] |= (1 << (bit % 8));
}

void bitmap_clear(void *bitmap, u32 bit)
{
    u8 *data = (u8 *)bitmap;
    data[bit / 8] &= ~(1 << (bit % 8));
}

int bitmap_test(void *bitmap, u32 bit)
{
    u8 *data = (u8 *)bitmap;
    return (data[bit / 8] & (1 << (bit % 8))) != 0;
}

void bitmap_set_range(void *bitmap, u32 start, u32 len)
{
    for (u32 i = 0; i < len; i++) {
        bitmap_set(bitmap, start + i);
    }
}

void bitmap_clear_range(void *bitmap, u32 start, u32 len)
{
    for (u32 i = 0; i < len; i++) {
        bitmap_clear(bitmap, start + i);
    }
}

u32 bitmap_find_first(void *bitmap, u32 bits)
{
    for (u32 i = 0; i < bits; i++) {
        if (bitmap_test(bitmap, i)) {
            return i;
        }
    }
    return bits;
}

u32 bitmap_find_next(void *bitmap, u32 bits, u32 pos)
{
    for (u32 i = pos + 1; i < bits; i++) {
        if (bitmap_test(bitmap, i)) {
            return i;
        }
    }
    return bits;
}
