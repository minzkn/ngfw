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

#include "ngfw/platform.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/utsname.h>

void sysinfo_get(system_info_t *info)
{
    if (!info) return;
    
    memset(info, 0, sizeof(system_info_t));
    
    struct utsname uts;
    if (uname(&uts) == 0) {
        strncpy(info->kernel_version, uts.release, sizeof(info->kernel_version) - 1);
        sscanf(uts.release, "%d.%d.%d", &info->kernel_major, &info->kernel_minor, &info->kernel_patch);
    }
    
    info->num_cpus = sysconf(_SC_NPROCESSORS_ONLN);
    
    long pages = sysconf(_SC_PHYS_PAGES);
    long page_size = sysconf(_SC_PAGESIZE);
    if (pages > 0 && page_size > 0) {
        info->total_memory = (u64)pages * (u64)page_size / (1024 * 1024);
    }
    
    pages = sysconf(_SC_AVPHYS_PAGES);
    if (pages > 0 && page_size > 0) {
        info->free_memory = (u64)pages * (u64)page_size / (1024 * 1024);
    }
    
    info->num_numa_nodes = 1;
}
