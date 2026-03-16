#!/bin/bash

set -e

INSTALL_ROOT="${INSTALL_ROOT:-/}"
FORCE="${FORCE:-0}"
START_SERVICES="${START_SERVICES:-1}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ "$EUID" -ne 0 ] && [ "$FORCE" -eq 0 ]; then
    echo "Please run as root or use FORCE=1"
    exit 1
fi

echo "=============================================="
echo "NGFW Firmware Deployment Script"
echo "=============================================="
echo "Install root: $INSTALL_ROOT"
echo ""

echo "[1/7] Checking prerequisites..."
if ! command -v iptables >/dev/null 2>&1; then
    echo "Error: iptables not found"
    exit 1
fi

if ! command -v ip >/dev/null 2>&1; then
    echo "Error: iproute2 not found"
    exit 1
fi

echo "[2/7] Creating directories..."
mkdir -p "$INSTALL_ROOT/usr/bin"
mkdir -p "$INSTALL_ROOT/usr/lib"
mkdir -p "$INSTALL_ROOT/etc/ngfw"
mkdir -p "$INSTALL_ROOT/var/log/ngfw"
mkdir -p "$INSTALL_ROOT/var/cache/ngfw"
mkdir -p "$INSTALL_ROOT/lib/modules"

echo "[3/7] Stopping existing NGFW services..."
if [ -f "$INSTALL_ROOT/etc/init.d/ngfw" ]; then
    "$INSTALL_ROOT/etc/init.d/ngfw" stop 2>/dev/null || true
fi
systemctl stop ngfw 2>/dev/null || true

pkill -9 ngfw 2>/dev/null || true

echo "[4/7] Installing binaries..."
cp -f "$SCRIPT_DIR/../ngfw" "$INSTALL_ROOT/usr/bin/" 2>/dev/null || true
chmod +x "$INSTALL_ROOT/usr/bin/ngfw"

echo "[5/7] Installing kernel module..."
if [ -f "$SCRIPT_DIR/../kernel/ngfw_kmod.ko" ]; then
    cp -f "$SCRIPT_DIR/../kernel/ngfw_kmod.ko" "$INSTALL_ROOT/lib/modules/"
    depmod -a 2>/dev/null || true
    echo "Kernel module installed"
else
    echo "Warning: Kernel module not found"
fi

echo "[6/7] Installing configuration..."
if [ -d "$SCRIPT_DIR/../etc" ]; then
    cp -rf "$SCRIPT_DIR/../etc/"* "$INSTALL_ROOT/etc/ngfw/" 2>/dev/null || true
fi

echo "[7/7] Configuring system..."
cat > "$INSTALL_ROOT/etc/iptables/ngfw.rules" << 'EOF'
*filter
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
-A INPUT -i lo -j ACCEPT
-A INPUT -p icmp -j ACCEPT
-A INPUT -p tcp --dport 22 -j ACCEPT
-A INPUT -p tcp --dport 443 -j ACCEPT
-A INPUT -p tcp --dport 8443 -j ACCEPT
-A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
COMMIT

*nat
:PREROUTING ACCEPT [0:0]
:INPUT ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
COMMIT
EOF

echo "1" > /proc/sys/net/ipv4/ip_forward

if [ "$START_SERVICES" = "1" ]; then
    echo ""
    echo "Starting services..."
    
    if [ -f "$INSTALL_ROOT/lib/modules/ngfw_kmod.ko" ]; then
        insmod "$INSTALL_ROOT/lib/modules/ngfw_kmod.ko" 2>/dev/null || true
        echo "Kernel module loaded"
    fi
    
    iptables-restore < "$INSTALL_ROOT/etc/iptables/ngfw.rules" 2>/dev/null || true
    
    "$INSTALL_ROOT/usr/bin/ngfw" --daemon
    echo "NGFW daemon started"
fi

echo ""
echo "=============================================="
echo "Deployment Complete!"
echo "=============================================="
echo ""
echo "To check status:"
echo "  cat /proc/ngfw/stats"
echo "  ps aux | grep ngfw"
echo "  iptables -L -n -v"
echo ""
