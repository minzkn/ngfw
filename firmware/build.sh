#!/bin/bash
#
# NGFW Firmware Build Script
# Complete firmware build process
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

VERSION="2.0.0"
ARCH="arm64"
BOARD="virt"

BUILD_DIR="$SCRIPT_DIR/build"
OUTPUT_DIR="$SCRIPT_DIR/output"
KERNEL_DIR="$PROJECT_ROOT/linux"
DPDK_DIR="$PROJECT_ROOT/dpdk"
BUILDROOT_DIR="$SCRIPT_DIR/buildroot"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_dependencies() {
    log_info "Checking build dependencies..."
    
    local deps=("gcc" "make" "git" "bc" "lz4" "openssl" "libssl-dev")
    local missing=()
    
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            missing+=("$dep")
        fi
    done
    
    if [ ${#missing[@]} -ne 0 ]; then
        log_error "Missing dependencies: ${missing[*]}"
        log_info "Install with: apt-get install ${missing[*]}"
        exit 1
    fi
    
    log_info "All dependencies satisfied"
}

setup_directories() {
    log_info "Setting up build directories..."
    
    mkdir -p "$BUILD_DIR"
    mkdir -p "$OUTPUT_DIR"
    mkdir -p "$BUILD_DIR/kernel"
    mkdir -p "$BUILD_DIR/uboot"
    mkdir -p "$BUILD_DIR/rootfs"
    mkdir -p "$OUTPUT_DIR/images"
    
    log_info "Directories created"
}

build_kernel() {
    log_info "Building Linux kernel..."
    
    local kernel_version="6.1.80"
    local kernel_path="$BUILD_DIR/kernel/linux-$kernel_version"
    
    if [ ! -d "$kernel_path" ]; then
        log_info "Downloading kernel $kernel_version..."
        cd "$BUILD_DIR/kernel"
        wget -q "https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-$kernel_version.tar.xz" || \
        curl -sL "https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-$kernel_version.tar.xz" -o "linux-$kernel_version.tar.xz"
        tar -xf "linux-$kernel_version.tar.xz"
    fi
    
    cd "$kernel_path"
    
    cp "$KERNEL_DIR/config-ngfw" .config
    
    log_info "Compiling kernel..."
    make -j$(nproc) ARCH=$ARCH CROSS_COMPILE=aarch64-linux-gnu- Image || \
    make -j$(nproc) zImage
    
    log_info "Kernel built successfully"
}

build_kernel_modules() {
    log_info "Building kernel modules..."
    
    cd "$KERNEL_DIR"
    
    make -C "$BUILD_DIR/kernel/linux-6.1.80" ARCH=$ARCH \
        CROSS_COMPILE=aarch64-linux-gnu- modules
    
    log_info "Kernel modules built"
}

build_ngfw_module() {
    log_info "Building NGFW kernel module..."
    
    cd "$KERNEL_DIR"
    
    make ARCH=$ARCH KDIR="$BUILD_DIR/kernel/linux-6.1.80" modules || \
    make ARCH=$ARCH KDIR=/lib/modules/$(uname -r)/build modules
    
    cp ngfw_mod.ko "$OUTPUT_DIR/" 2>/dev/null || true
    
    log_info "NGFW module built"
}

build_dpdk_module() {
    log_info "Building DPDK kernel module..."
    
    cd "$DPDK_DIR"
    
    make ARCH=$ARCH KDIR="$BUILD_DIR/kernel/linux-6.1.80" modules
    
    log_info "DPDK module built"
}

build_ngfw_userspace() {
    log_info "Building NGFW userspace application..."
    
    cd "$PROJECT_ROOT"
    
    make clean
    make ARCH=$ARCH CC=aarch64-linux-gnu-gcc
    
    cp ngfw "$OUTPUT_DIR/"
    
    log_info "NGFW userspace application built"
}

build_rootfs() {
    log_info "Building root filesystem..."
    
    local rootfs_path="$BUILD_DIR/rootfs"
    
    mkdir -p "$rootfs_path"
    
    log_info "Installing base system..."
    debootstrap --variant=minbase --arch=arm64 bookworm "$rootfs_path" http://deb.debian.org/debian || \
    apt-get install -y --no-install-recommends -y qemu-user-static && \
    cp /usr/bin/qemu-aarch64-static "$rootfs_path/usr/bin/"
    
    log_info "Installing NGFW application..."
    cp -r "$OUTPUT_DIR/ngfw" "$rootfs_path/usr/sbin/"
    
    log_info "Installing configuration..."
    cp -r "$SCRIPT_DIR/overlay/"* "$rootfs_path/"
    
    log_info "Creating filesystem image..."
    local rootfs_img="$OUTPUT_DIR/rootfs.ext4"
    dd if=/dev/zero of="$rootfs_img" bs=1M count=512
    mkfs.ext4 -F "$rootfs_img"
    
    mkdir -p /mnt/rootfs_temp
    mount "$rootfs_img" /mnt/rootfs_temp
    cp -r "$rootfs_path/"* /mnt/rootfs_temp/
    umount /mnt/rootfs_temp
    
    log_info "Root filesystem created"
}

create_firmware_image() {
    log_info "Creating firmware image..."
    
    local firmware_img="$OUTPUT_DIR/images/ngfw-$VERSION-$ARCH.img"
    
    dd if=/dev/zero of="$firmware_img" bs=1M count=1024
    
    parted -s "$firmware_img" mklabel msdos
    parted -s "$firmware_img" mkpart primary fat32 1 64
    parted -s "$firmware_img" mkpart primary ext4 64 -1
    
    log_info "Firmware image created: $firmware_img"
}

generate_checksums() {
    log_info "Generating checksums..."
    
    cd "$OUTPUT_DIR"
    
    for img in images/*.img; do
        if [ -f "$img" ]; then
            sha256sum "$img" > "$img.sha256"
            md5sum "$img" > "$img.md5"
        fi
    done
    
    log_info "Checksums generated"
}

build_all() {
    log_info "Starting NGFW firmware build v$VERSION"
    
    check_dependencies
    setup_directories
    build_kernel
    build_kernel_modules
    build_ngfw_module
    build_ngfw_userspace
    build_rootfs
    create_firmware_image
    generate_checksums
    
    log_info "========================================="
    log_info "Firmware build completed successfully!"
    log_info "Version: $VERSION"
    log_info "Architecture: $ARCH"
    log_info "Output: $OUTPUT_DIR"
    log_info "========================================="
}

show_help() {
    echo "NGFW Firmware Build Script"
    echo ""
    echo "Usage: $0 [command]"
    echo ""
    echo "Commands:"
    echo "  all         Build complete firmware (default)"
    echo "  kernel      Build only kernel"
    echo "  userspace   Build only NGFW userspace app"
    echo "  rootfs      Build root filesystem"
    echo "  image       Create firmware image"
    echo "  clean       Clean build artifacts"
    echo "  help        Show this help"
    echo ""
}

clean() {
    log_info "Cleaning build artifacts..."
    
    rm -rf "$BUILD_DIR"
    rm -rf "$OUTPUT_DIR"/*
    
    cd "$PROJECT_ROOT"
    make clean
    
    log_info "Clean complete"
}

case "${1:-all}" in
    all)
        build_all
        ;;
    kernel)
        check_dependencies
        setup_directories
        build_kernel
        build_kernel_modules
        build_ngfw_module
        ;;
    userspace)
        build_ngfw_userspace
        ;;
    rootfs)
        setup_directories
        build_rootfs
        ;;
    image)
        create_firmware_image
        ;;
    clean)
        clean
        ;;
    help|--help|-h)
        show_help
        ;;
    *)
        log_error "Unknown command: $1"
        show_help
        exit 1
        ;;
esac