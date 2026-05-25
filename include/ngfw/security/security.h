/*
 * NGFW - Next-Generation Firewall
 * Copyright (C) 2024 NGFW Project
 */

#ifndef NGFW_SECURITY_H
#define NGFW_SECURITY_H

/*
 * Security Layer
 * 
 * Security modules:
 * - Session tracking
 * - Packet filtering
 * - Intrusion Prevention (IPS)
 * - URL filtering
 * - NAT
 * - DDoS mitigation
 * - VPN
 * - Anti-Virus
 * - QoS
 */

#include "ngfw/security/session.h"
#include "ngfw/security/filter.h"
#include "ngfw/security/ips.h"
#include "ngfw/security/urlfilter.h"
#include "ngfw/security/nat.h"
#include "ngfw/security/ddos.h"
#include "ngfw/security/vpn.h"
#include "ngfw/security/antivirus.h"
#include "ngfw/security/qos.h"

#endif
