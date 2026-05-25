/*
 * NGFW - Next-Generation Firewall
 * Copyright (C) 2024 NGFW Project
 *
 * Main include file - includes all layers
 */

#ifndef NGFW_H
#define NGFW_H

/* Core types */
#include "ngfw/types.h"

/* All layers */
#include "ngfw/hal/hal.h"
#include "ngfw/core/core.h"
#include "ngfw/network/network.h"
#include "ngfw/security/security.h"
#include "ngfw/services/services.h"
#include "ngfw/app/app.h"

#endif
