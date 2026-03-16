#!/bin/bash

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
NGFW_DIR="$SCRIPT_DIR"
KERNEL_DIR="$NGFW_DIR/linux-6.12"

echo "============================================"
echo "NGFW QEMU Test Environment"
echo "============================================"

check_requirements() {
    if ! command -v qemu-system-x86_64 &> /dev/null; then
        echo "Error: qemu-system-x86_64 not found"
        echo "Install with: apt-get install qemu-system-x86"
        exit 1
    fi
    
    if ! command -v qemu-img &> /dev/null; then
        echo "Error: qemu-img not found"
        exit 1
    fi
}

build_userspace() {
    echo ""
    echo "[1/5] Building NGFW userspace application..."
    cd "$NGFW_DIR"
    make clean
    make
    make test
    echo "Userspace build complete"
}

build_kernel_module() {
    echo ""
    echo "[2/5] Building NGFW kernel module..."
    
    cd "$NGFW_DIR/kernel"
    
    if [ ! -d "$KERNEL_DIR" ]; then
        echo "Warning: Kernel source not found, skipping module build"
        return 0
    fi
    
    if [ ! -f "$KERNEL_DIR/.config" ]; then
        echo "Configuring kernel..."
        cd "$KERNEL_DIR"
        make defconfig
        make -j$(nproc)
    fi
    
    cd "$NGFW_DIR/kernel"
    make clean
    make KDIR="$KERNEL_DIR"
    echo "Kernel module build complete"
}

prepare_rootfs() {
    echo ""
    echo "[3/5] Preparing root filesystem..."
    
    ROOTFS_DIR="$NGFW_DIR/qemu/rootfs"
    mkdir -p "$ROOTFS_DIR"/{bin,etc,lib,var/log,var/run,home}
    
    cp "$NGFW_DIR/ngfw" "$ROOTFS_DIR/bin/"
    cp -r "$NGFW_DIR/firmware" "$ROOTFS_DIR/etc/"
    
    if [ -f "$NGFW_DIR/kernel/ngfw_kmod.ko" ]; then
        cp "$NGFW_DIR/kernel/ngfw_kmod.ko" "$ROOTFS_DIR/lib/"
    fi
    
    echo "Rootfs prepared at $ROOTFS_DIR"
}

create_disk_image() {
    echo ""
    echo "[4/5] Creating disk image..."
    
    IMG_FILE="$NGFW_DIR/qemu/ngfw.img"
    
    if [ -f "$IMG_FILE" ]; then
        rm -f "$IMG_FILE"
    fi
    
    qemu-img create -f raw "$IMG_FILE" 2G
    
    mkfs.ext4 -F "$IMG_FILE" || true
    
    echo "Disk image created: $IMG_FILE"
}

run_qemu() {
    echo ""
    echo "[5/5] Starting QEMU VM..."
    
    KERNEL="$KERNEL_DIR/arch/x86_64/boot/bzImage"
    IMG_FILE="$NGFW_DIR/qemu/ngfw.img"
    
    if [ ! -f "$KERNEL" ]; then
        echo "Error: Kernel image not found at $KERNEL"
        echo "Please build the kernel first"
        exit 1
    fi
    
    qemu-system-x86_64 \
        -kernel "$KERNEL" \
        -append "console=ttyS0 root=/dev/sda rw" \
        -hda "$IMG_FILE" \
        -m 2G \
        -nographic \
        -netdev user,id=net0,hostfwd=tcp::2222-:22 \
        -device e1000,netdev=net0 \
        -enable-kvm \
        "$@"
}

show_help() {
    echo "Usage: $0 [command]"
    echo ""
    echo "Commands:"
    echo "  all         Build and run everything (default)"
    echo "  build       Build userspace and kernel module"
    echo "  userspace   Build only userspace application"
    echo "  kernel      Build only kernel module"
    echo "  prepare     Prepare root filesystem and disk image"
    echo "  run         Run QEMU VM"
    echo "  help        Show this help"
    echo ""
    echo "Examples:"
    echo "  $0 all"
    echo "  $0 build"
    echo "  $0 run"
}

main() {
    check_requirements
    
    case "${1:-all}" in
        all)
            build_userspace
            build_kernel_module
            prepare_rootfs
            create_disk_image
            run_qemu
            ;;
        build)
            build_userspace
            build_kernel_module
            ;;
        userspace)
            build_userspace
            ;;
        kernel)
            build_kernel_module
            ;;
        prepare)
            prepare_rootfs
            create_disk_image
            ;;
        run)
            run_qemu
            ;;
        help|--help|-h)
            show_help
            ;;
        *)
            echo "Unknown command: $1"
            show_help
            exit 1
            ;;
    esac
}

main "$@"
