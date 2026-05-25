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

#ifndef NGFW_CORE_H
#define NGFW_CORE_H

/*
 * Core Layer
 * 
 * Fundamental data structures and utilities:
 * - Memory management (slab, pool, ring buffer)
 * - Data structures (list, hash, tree, bitmap)
 * - Pattern matching (BMH, Aho-Corasick, regex)
 * - Synchronization (spinlock, rwlock, barrier)
 * - Utilities (timer, logging, string)
 */

#include "ngfw/core/memory.h"
#include "ngfw/core/ds.h"
#include "ngfw/core/match.h"
#include "ngfw/core/sync.h"
#include "ngfw/core/utils.h"

#endif
