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

#ifndef NGFW_HAL_H
#define NGFW_HAL_H

/*
 * Hardware Abstraction Layer (HAL)
 * 
 * Provides uniform interface to hardware resources:
 * - CPU information and affinity
 * - Memory allocation and NUMA awareness
 * - Network interface access
 * - Hardware acceleration (crypto, checksum)
 * - DPDK integration (optional)
 */

#include "ngfw/hal/cpu.h"
#include "ngfw/hal/memory.h"
#include "ngfw/hal/netif.h"
#include "ngfw/hal/accel.h"
#include "ngfw/hal/dpdk.h"

#endif
