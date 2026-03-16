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

#include "ngfw/crypto.h"
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>
#include <fcntl.h>

static int random_fd = -1;

void random_bytes(u8 *buf, u32 len)
{
    if (random_fd < 0) {
        random_fd = open("/dev/urandom", O_RDONLY);
    }
    
    if (random_fd >= 0) {
        (void)read(random_fd, buf, len);
    } else {
        struct timeval tv;
        gettimeofday(&tv, NULL);
        u64 seed = tv.tv_sec * 1000000 + tv.tv_usec;
        seed ^= (u64)getpid() << 32;
        
        for (u32 i = 0; i < len; i++) {
            seed = seed * 1103515245 + 12345;
            buf[i] = (seed >> 16) & 0xFF;
        }
    }
}

u32 random_u32(void)
{
    u32 val;
    random_bytes((u8 *)&val, sizeof(val));
    return val;
}

u64 random_u64(void)
{
    u64 val;
    random_bytes((u8 *)&val, sizeof(val));
    return val;
}
