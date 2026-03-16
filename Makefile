# NGFW Makefile
# Next-Generation Firewall Build System

# Skip dependency inclusion for clean/distclean targets
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
CFLAGS += -fno-stack-protector -fomit-frame-pointer -O2
CFLAGS += -Iinclude -Iinclude/ngfw

# Debug build
ifdef DEBUG
    CFLAGS += -g -DDEBUG -O0
else
    CFLAGS += -DNDEBUG -O3
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

# Source files
CORE_SRCS = src/core/memory.c src/core/list.c src/core/hash.c src/core/log.c \
            src/core/timer.c src/core/spinlock.c src/core/bitmap.c

NETWORK_SRCS = src/network/packet.c src/network/interface.c src/network/ip.c \
                src/network/tcp.c src/network/udp.c src/network/icmp.c

CRYPTO_SRCS = src/crypto/aes.c src/crypto/sha.c src/crypto/random.c \
               src/crypto/md5.c src/crypto/crc.c

SECURITY_SRCS = src/security/session.c src/security/filter.c src/security/urlfilter.c

PLATFORM_SRCS = src/platform/cpu.c src/platform/thread.c

NF_SRCS = src/nf/nf.c

UTILS_SRCS = src/utils/module.c src/utils/mempool.c src/utils/plugin.c \
              src/utils/ringbuffer.c src/utils/ratelimit.c src/utils/connpool.c \
              src/utils/bloom.c src/utils/lrucache.c src/utils/skiplist.c \
              src/utils/asynclog.c src/utils/ipv6.c src/utils/metrics.c \
              src/utils/strutil.c src/utils/timerwheel.c \
              src/utils/packet_alloc.c src/utils/protocols.c src/utils/notify.c

SERVICES_SRCS = src/services/config.c src/services/config_hotreload.c \
                 src/services/logger.c src/services/event.c src/services/ipc.c \
                 src/services/monitor.c src/services/auth.c src/services/firmware.c \
                 src/services/web.c src/services/cli.c src/services/pipeline.c \
                 src/services/capture.c src/services/logdb.c src/services/snmp.c \
                 src/services/prometheus.c

VPN_SRCS = src/vpn.c

IPS_SRCS = src/ips.c

ANTIVIRUS_SRCS = src/antivirus.c

NAT_SRCS = src/nat.c

DDOS_SRCS = src/ddos.c

QOS_SRCS = src/qos.c

THREADPOOL_SRCS = src/threadpool.c

DPDK_SRCS = src/dpdk.c

NETFILTER_SRCS = src/netfilter.c

HWACCEL_SRCS = src/hwaccel.c

ENGINE_SRCS = src/engine.c

SRC_DIRS = src/core src/network src/crypto src/security src/platform src/nf src/utils src/services src/vpn src/ips src/antivirus src/nat src/ddos src/qos src/threadpool src/netfilter src/hwaccel

# Object files
CORE_OBJS = $(CORE_SRCS:.c=.o)
NETWORK_OBJS = $(NETWORK_SRCS:.c=.o)
CRYPTO_OBJS = $(CRYPTO_SRCS:.c=.o)
SECURITY_OBJS = $(SECURITY_SRCS:.c=.o)
PLATFORM_OBJS = $(PLATFORM_SRCS:.c=.o)
NF_OBJS = $(NF_SRCS:.c=.o)
UTILS_OBJS = $(UTILS_SRCS:.c=.o)
SERVICES_OBJS = $(SERVICES_SRCS:.c=.o)

VPN_OBJS = $(VPN_SRCS:.c=.o)
IPS_OBJS = $(IPS_SRCS:.c=.o)
ANTIVIRUS_OBJS = $(ANTIVIRUS_SRCS:.c=.o)
NAT_OBJS = $(NAT_SRCS:.c=.o)
DDOS_OBJS = $(DDOS_SRCS:.c=.o)
QOS_OBJS = $(QOS_SRCS:.c=.o)
THREADPOOL_OBJS = $(THREADPOOL_SRCS:.c=.o)
DPDK_OBJS = $(DPDK_SRCS:.c=.o)
NETFILTER_OBJS = $(NETFILTER_SRCS:.c=.o)
HWACCEL_OBJS = $(HWACCEL_SRCS:.c=.o)
ENGINE_OBJS = $(ENGINE_SRCS:.c=.o)

# DPDK is optional
DPDK_OBJS =

OBJS = $(CORE_OBJS) $(NETWORK_OBJS) $(CRYPTO_OBJS) $(SECURITY_OBJS) $(PLATFORM_OBJS) $(NF_OBJS) $(UTILS_OBJS) $(SERVICES_OBJS) $(VPN_OBJS) $(IPS_OBJS) $(ANTIVIRUS_OBJS) $(NAT_OBJS) $(DDOS_OBJS) $(QOS_OBJS) $(THREADPOOL_OBJS) $(NETFILTER_OBJS) $(HWACCEL_OBJS) $(ENGINE_OBJS)

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

ifdef ENABLE_DPDK
ifeq ($(ENABLE_DPDK),1)
    CFLAGS += -DENABLE_DPDK=1 -I$(DPDK_DIR)/include
    LDFLAGS += -L$(DPDK_DIR)/build -lrte_eal -lrte_ethdev -lrte_mbuf -lrte_mempool -lrte_net -lrte_ether -lrte_hash -lrte_ring
endif
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
	install -m 644 include/ngfw/*.h $(PREFIX)/include/ngfw/

# Dependencies
DEPS = $(OBJS:.o=.d)

%.d: %.c
	$(CC) $(CFLAGS) -MM -MT $(<:.c=.o) $< > $@

ifndef CLEANING
-include $(DEPS)
endif

# Object files (must be after CLEANING check)
ifndef CLEANING
# Source files
CORE_SRCS = src/core/memory.c src/core/list.c src/core/hash.c src/core/log.c \
            src/core/timer.c src/core/spinlock.c src/core/bitmap.c

NETWORK_SRCS = src/network/packet.c src/network/interface.c src/network/ip.c \
                src/network/tcp.c src/network/udp.c src/network/icmp.c

CRYPTO_SRCS = src/crypto/aes.c src/crypto/sha.c src/crypto/random.c \
               src/crypto/md5.c src/crypto/crc.c

SECURITY_SRCS = src/security/session.c src/security/filter.c src/security/urlfilter.c

PLATFORM_SRCS = src/platform/cpu.c src/platform/thread.c

NF_SRCS = src/nf/nf.c

UTILS_SRCS = src/utils/module.c src/utils/mempool.c src/utils/plugin.c \
              src/utils/ringbuffer.c src/utils/ratelimit.c src/utils/connpool.c \
              src/utils/bloom.c src/utils/lrucache.c src/utils/skiplist.c \
              src/utils/asynclog.c src/utils/ipv6.c src/utils/metrics.c \
              src/utils/strutil.c src/utils/timerwheel.c \
              src/utils/packet_alloc.c src/utils/protocols.c src/utils/notify.c

SERVICES_SRCS = src/services/config.c src/services/config_hotreload.c \
                 src/services/logger.c src/services/event.c src/services/ipc.c \
                 src/services/monitor.c src/services/auth.c src/services/firmware.c \
                 src/services/web.c src/services/cli.c src/services/pipeline.c \
                 src/services/capture.c src/services/logdb.c src/services/snmp.c \
                 src/services/prometheus.c

VPN_SRCS = src/vpn.c

IPS_SRCS = src/ips.c

ANTIVIRUS_SRCS = src/antivirus.c

NAT_SRCS = src/nat.c

DDOS_SRCS = src/ddos.c

QOS_SRCS = src/qos.c

THREADPOOL_SRCS = src/threadpool.c

DPDK_SRCS = src/dpdk.c

NETFILTER_SRCS = src/netfilter.c

HWACCEL_SRCS = src/hwaccel.c

ENGINE_SRCS = src/engine.c

# Object files
CORE_OBJS = $(CORE_SRCS:.c=.o)
NETWORK_OBJS = $(NETWORK_SRCS:.c=.o)
CRYPTO_OBJS = $(CRYPTO_SRCS:.c=.o)
SECURITY_OBJS = $(SECURITY_SRCS:.c=.o)
PLATFORM_OBJS = $(PLATFORM_SRCS:.c=.o)
NF_OBJS = $(NF_SRCS:.c=.o)
UTILS_OBJS = $(UTILS_SRCS:.c=.o)
SERVICES_OBJS = $(SERVICES_SRCS:.c=.o)

VPN_OBJS = $(VPN_SRCS:.c=.o)
IPS_OBJS = $(IPS_SRCS:.c=.o)
ANTIVIRUS_OBJS = $(ANTIVIRUS_SRCS:.c=.o)
NAT_OBJS = $(NAT_SRCS:.c=.o)
DDOS_OBJS = $(DDOS_SRCS:.c=.o)
QOS_OBJS = $(QOS_SRCS:.c=.o)
THREADPOOL_OBJS = $(THREADPOOL_SRCS:.c=.o)
DPDK_OBJS = $(DPDK_SRCS:.c=.o)
NETFILTER_OBJS = $(NETFILTER_SRCS:.c=.o)
HWACCEL_OBJS = $(HWACCEL_SRCS:.c=.o)
ENGINE_OBJS = $(ENGINE_SRCS:.c=.o)

# DPDK is optional
DPDK_OBJS =

OBJS = $(CORE_OBJS) $(NETWORK_OBJS) $(CRYPTO_OBJS) $(SECURITY_OBJS) $(PLATFORM_OBJS) $(NF_OBJS) $(UTILS_OBJS) $(SERVICES_OBJS) $(VPN_OBJS) $(IPS_OBJS) $(ANTIVIRUS_OBJS) $(NAT_OBJS) $(DDOS_OBJS) $(QOS_OBJS) $(THREADPOOL_OBJS) $(NETFILTER_OBJS) $(HWACCEL_OBJS) $(ENGINE_OBJS)
endif

.PHONY: all check_config test clean distclean install arm64 riscv64 full _clean
