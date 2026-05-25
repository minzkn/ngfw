# NGFW Makefile
# Next-Generation Firewall Build System
#
# Copyright (C) 2024 NGFW Project
# Licensed under the GNU General Public License v2
#
# Layered Architecture Headers:
#   HAL (Hardware Abstraction Layer) - Hardware access
#   Core Layer - Data structures, utilities
#   Network Layer - Protocol handling
#   Security Layer - Security modules
#   Services Layer - System services
#   Application Layer - Main engine

ifeq ($(findstring clean,$(MAKECMDGOALS)),clean)
    CLEANING := 1
endif

CC ?= gcc
AR ?= ar
RM ?= rm -f

# Build configuration
ARCH ?= x86_64
CROSS_COMPILE ?=
CC := $(CROSS_COMPILE)$(CC)

CFLAGS += -Wall -Wextra -Wpedantic -std=c99
CFLAGS += -D_XOPEN_SOURCE=700 -D_POSIX_C_SOURCE=200809L
CFLAGS += -fstack-protector-strong -fomit-frame-pointer -O2
CFLAGS += -Iinclude -Iinclude/ngfw

# Debug build
ifdef DEBUG
    CFLAGS += -g -DDEBUG -O0 -fstack-protector-all
else
    CFLAGS += -DNDEBUG -O3 -fstack-protector-strong
endif

# Target architecture
CFLAGS += -DARCH_$(shell echo $(ARCH) | tr '[:lower:]' '[:upper:]')

# Module configuration
ENABLE_CORE ?= 1
ENABLE_NETWORK ?= 1
ENABLE_IPS ?= 1
ENABLE_VPN ?= 0
ENABLE_URLFILTER ?= 1
ENABLE_ANTIVIRUS ?= 0
ENABLE_QOS ?= 1

CFLAGS += -DENABLE_CORE=$(ENABLE_CORE) -DENABLE_NETWORK=$(ENABLE_NETWORK)
CFLAGS += -DENABLE_IPS=$(ENABLE_IPS) -DENABLE_VPN=$(ENABLE_VPN)
CFLAGS += -DENABLE_URLFILTER=$(ENABLE_URLFILTER)
CFLAGS += -DENABLE_ANTIVIRUS=$(ENABLE_ANTIVIRUS) -DENABLE_QOS=$(ENABLE_QOS)

# =============================================================================
# Source files (existing structure with new layered headers)
# =============================================================================

# HAL Layer - Hardware Abstraction Layer
HAL_SRCS = src/hal/hal_memory.c src/hal/hal_cpu.c src/hal/hal_accel.c \
           src/hal/hal_netif.c src/hal/hal_dpdk.c src/hal/hal_platform.c \
           src/hal/hal_thread.c

# Core Layer - Data structures, utilities, memory management
CORE_SRCS = src/core/memory.c src/core/list.c src/core/hash.c src/core/log.c \
            src/core/timer.c src/core/spinlock.c src/core/bitmap.c src/core/percpu.c \
            src/core/slab_alloc.c src/core/ac_match.c

# Network Layer - Protocol handling and packet processing
NETWORK_SRCS = src/network/packet.c src/network/interface.c src/network/ip.c \
               src/network/tcp.c src/network/udp.c src/network/icmp.c

# Crypto - Cryptographic primitives
CRYPTO_SRCS = src/crypto/aes.c src/crypto/sha.c src/crypto/random.c \
              src/crypto/md5.c src/crypto/crc.c

# Security Layer - Security modules (IPS, NAT, VPN, etc.)
SECURITY_SRCS = src/security/session.c src/security/filter.c src/security/urlfilter.c \
                src/security/ips.c src/security/vpn.c src/security/nat.c \
                src/security/ddos.c src/security/antivirus.c src/security/qos.c \
                src/security/hwaccel.c

# Utils - Utility functions and data structures
UTILS_SRCS = src/utils/module.c src/utils/mempool.c src/utils/plugin.c \
             src/utils/ringbuffer.c src/utils/ratelimit.c src/utils/connpool.c \
             src/utils/bloom.c src/utils/lrucache.c src/utils/skiplist.c \
             src/utils/asynclog.c src/utils/ipv6.c src/utils/metrics.c \
             src/utils/strutil.c src/utils/timerwheel.c \
             src/utils/packet_alloc.c src/utils/protocols.c src/utils/notify.c \
             src/utils/executil.c src/utils/patmatch.c

# Services Layer - System services (config, logging, monitoring)
SERVICES_SRCS = src/services/config.c src/services/logger.c src/services/monitor.c \
                src/services/web.c src/services/cli.c src/services/snmp.c \
                src/services/prometheus.c src/services/auth.c src/services/capture.c \
                src/services/event.c src/services/firmware.c src/services/ipc.c \
                src/services/logdb.c src/services/pipeline.c \
                src/services/config_hotreload.c

# NF - Netfilter kernel integration
NF_SRCS = src/nf/nf.c src/nf/nfnetlink.c src/netfilter.c

# DPDK - Data Plane Development Kit (optional)
DPDK_SRCS = src/dpdk.c

# Thread pool - Worker thread management
THREADPOOL_SRCS = src/threadpool.c

# Engine - Main packet processing engine
ENGINE_SRCS = src/engine.c

# VPN data - VPN module data structures
VPN_DATA_SRCS = src/vpn/vpn_data.c

# =============================================================================
# Object files by layer
# =============================================================================

HAL_OBJS = $(HAL_SRCS:.c=.o)
CORE_OBJS = $(CORE_SRCS:.c=.o)
NETWORK_OBJS = $(NETWORK_SRCS:.c=.o)
CRYPTO_OBJS = $(CRYPTO_SRCS:.c=.o)
SECURITY_OBJS = $(SECURITY_SRCS:.c=.o)
UTILS_OBJS = $(UTILS_SRCS:.c=.o)
SERVICES_OBJS = $(SERVICES_SRCS:.c=.o)
NF_OBJS = $(NF_SRCS:.c=.o)
DPDK_OBJS = $(DPDK_SRCS:.c=.o)
THREADPOOL_OBJS = $(THREADPOOL_SRCS:.c=.o)
ENGINE_OBJS = $(ENGINE_SRCS:.c=.o)
VPN_DATA_OBJS = $(VPN_DATA_SRCS:.c=.o)

# DPDK is optional
ifeq ($(ENABLE_DPDK),1)
    CFLAGS += -DENABLE_DPDK=1
else
    DPDK_OBJS =
endif

# All objects - organized by layer
OBJS = $(HAL_OBJS) $(CORE_OBJS) $(NETWORK_OBJS) $(CRYPTO_OBJS) \
       $(SECURITY_OBJS) $(UTILS_OBJS) $(SERVICES_OBJS) $(NF_OBJS) \
       $(VPN_DATA_OBJS) $(THREADPOOL_OBJS) $(DPDK_OBJS) $(ENGINE_OBJS)

# Static library
LIB = libngfw.a

# Test executable
TESTS = tests/ngfw_test

# Main executable
MAIN = ngfw

# Default target
all: check_config $(LIB) $(MAIN)

check_config:
	@echo "Building NGFW for ARCH=$(ARCH)"
	@echo "  ENABLE_CORE=$(ENABLE_CORE)"
	@echo "  ENABLE_NETWORK=$(ENABLE_NETWORK)"
	@echo "  ENABLE_IPS=$(ENABLE_IPS)"
	@echo "  ENABLE_VPN=$(ENABLE_VPN)"
	@echo "  ENABLE_DPDK=$(ENABLE_DPDK)"

# DPDK configuration
ENABLE_DPDK ?= 0
DPDK_DIR ?= $(CURDIR)/dpdk-24.11

ifeq ($(ENABLE_DPDK),1)
    CFLAGS += -I$(DPDK_DIR)/include
    LDFLAGS += -L$(DPDK_DIR)/build -lrte_eal -lrte_ethdev -lrte_mbuf -lrte_mempool -lrte_net -lrte_ether -lrte_hash -lrte_ring
endif

# Create static library
$(LIB): $(OBJS)
	$(AR) rcs $@ $^

# Compile source files
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Test build
test: $(TESTS)

$(TESTS): tests/test_main.c $(OBJS)
	$(CC) $(CFLAGS) $^ -o $@ -lpthread -lm

# Unit tests
unit_test: tests/unit_tests
	./tests/unit_tests

tests/unit_tests: tests/unit_tests.c $(HAL_OBJS) $(CORE_OBJS) $(NETWORK_OBJS) $(SECURITY_OBJS) $(CRYPTO_OBJS)
	$(CC) $(CFLAGS) $^ -o $@ -lpthread -lm

# Main executable
$(MAIN): src/main.c $(OBJS)
	$(CC) $(CFLAGS) $^ -o $@ -lpthread -lm

# Build for ARM64
arm64:
	$(MAKE) ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- CC=aarch64-linux-gnu-gcc

# Build for RISC-V
riscv64:
	$(MAKE) ARCH=riscv64 CROSS_COMPILE=riscv64-linux-gnu- CC=riscv64-linux-gnu-gcc

# Build with all features
full:
	$(MAKE) ENABLE_IPS=1 ENABLE_VPN=1 ENABLE_ANTIVIRUS=1

# Clean build artifacts
clean:
	@$(MAKE) CLEANING=1 OBJS= DEPS= _clean
	@find . -name '*.o' -type f -delete 2>/dev/null || true
	@find . -name '*.d' -type f -delete 2>/dev/null || true

_clean:
	$(RM) libngfw.a tests/ngfw_test ngfw
	$(RM) -r *.dSYM
	$(RM) core

distclean: clean
	$(RM) -rf build/ *.log *.tmp

# Install
PREFIX ?= /usr/local
install:
	install -d $(PREFIX)/lib $(PREFIX)/include/ngfw
	install -m 644 $(LIB) $(PREFIX)/lib/
	install -m 644 include/ngfw/hal/*.h $(PREFIX)/include/ngfw/hal/
	install -m 644 include/ngfw/core/*.h $(PREFIX)/include/ngfw/core/
	install -m 644 include/ngfw/network/*.h $(PREFIX)/include/ngfw/network/
	install -m 644 include/ngfw/security/*.h $(PREFIX)/include/ngfw/security/
	install -m 644 include/ngfw/services/*.h $(PREFIX)/include/ngfw/services/
	install -m 644 include/ngfw/app/*.h $(PREFIX)/include/ngfw/app/
	install -m 644 include/ngfw/*.h $(PREFIX)/include/ngfw/

# Dependencies
DEPS = $(OBJS:.o=.d)

%.d: %.c
	$(CC) $(CFLAGS) -MM -MT $(<:.c=.o) $< > $@

ifndef CLEANING
-include $(DEPS)
endif

.PHONY: all check_config test clean distclean install arm64 riscv64 full _clean
