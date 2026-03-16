#!/bin/bash

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$SCRIPT_DIR"
BUILD_DIR="$PROJECT_ROOT/build_firmware"
INSTALL_DIR="$BUILD_DIR/rootfs"
CROSS_COMPILE="${CROSS_COMPILE:-aarch64-linux-gnu-}"

echo "=============================================="
echo "NGFW Firmware Build Script"
echo "=============================================="
echo "Project: $PROJECT_ROOT"
echo "Cross Compiler: $CROSS_COMPILE"
echo ""

mkdir -p "$BUILD_DIR"
mkdir -p "$INSTALL_DIR/usr/bin"
mkdir -p "$INSTALL_DIR/usr/lib"
mkdir -p "$INSTALL_DIR/etc/ngfw"
mkdir -p "$INSTALL_DIR/var/log/ngfw"
mkdir -p "$INSTALL_DIR/var/cache/ngfw"
mkdir -p "$INSTALL_DIR/lib/modules/$(uname -r)"

ARCH="${ARCH:-arm64}"

echo "[1/6] Building userspace application..."
cd "$PROJECT_ROOT"

if [ "$ARCH" = "arm64" ]; then
    make clean > /dev/null 2>&1 || true
    make ARCH=arm64 CROSS_COMPILE="$CROSS_COMPILE" ENABLE_DPDK=0
elif [ "$ARCH" = "x86_64" ]; then
    make clean > /dev/null 2>&1 || true
    make
else
    echo "Unsupported architecture: $ARCH"
    exit 1
fi

echo "[2/6] Copying binaries..."
cp -f "$PROJECT_ROOT/ngfw" "$INSTALL_DIR/usr/bin/"
cp -f "$PROJECT_ROOT/ngfw_test" "$INSTALL_DIR/usr/bin/" 2>/dev/null || true
cp -f "$PROJECT_ROOT/libngfw.a" "$INSTALL_DIR/usr/lib/"

echo "[3/6] Copying configuration..."
cp -rf "$PROJECT_ROOT/etc/"* "$INSTALL_DIR/etc/ngfw/"

echo "[4/6] Copying database files..."
cp -f "$PROJECT_ROOT/etc/"*.db "$INSTALL_DIR/etc/ngfw/" 2>/dev/null || true

echo "[5/6] Creating firmware image..."
cd "$BUILD_DIR"

FIRMWARE_VERSION="1.0.0"
FIRMWARE_DATE=$(date +%Y%m%d)

tar -czvf "ngfw-firmware-${ARCH}-${FIRMWARE_VERSION}-${FIRMWARE_DATE}.tar.gz" -C "$INSTALL_DIR" .

echo "[6/6] Building kernel module (if source available)..."
if [ -d "$PROJECT_ROOT/kernel" ]; then
    cd "$PROJECT_ROOT/kernel"
    if [ "$ARCH" = "arm64" ]; then
        make CROSS_COMPILE="$CROSS_COMPILE" KDIR=/lib/modules/$(uname -r)/build 2>/dev/null || true
        cp -f "ngfw_kmod.ko" "$INSTALL_DIR/lib/modules/" 2>/dev/null || true
    fi
    cd "$PROJECT_ROOT"
fi

echo ""
echo "=============================================="
echo "Build Complete!"
echo "=============================================="
echo "Firmware: build_firmware/ngfw-firmware-${ARCH}-${FIRMWARE_VERSION}-${FIRMWARE_DATE}.tar.gz"
echo "Size: $(du -h "ngfw-firmware-${ARCH}-${FIRMWARE_VERSION}-${FIRMWARE_DATE}.tar.gz" | cut -f1)"
echo ""
echo "To deploy:"
echo "  tar -xzf ngfw-firmware-*.tar.gz -C /"
echo "  insmod /lib/modules/ngfw_kmod.ko"
echo "  /usr/bin/ngfw --daemon"
echo ""
