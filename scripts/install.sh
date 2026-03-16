#!/bin/bash
#
# NGFW Installation Script
# Complete system installation and configuration
#

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

INSTALL_LOG="/var/log/ngfw-install.log"

log() {
    echo -e "${GREEN}[INSTALL]${NC} $1" | tee -a "$INSTALL_LOG"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1" | tee -a "$INSTALL_LOG"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" | tee -a "$INSTALL_LOG"
}

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1" | tee -a "$INSTALL_LOG"
}

check_root() {
    if [ "$EUID" -ne 0 ]; then
        log_error "This script must be run as root"
        exit 1
    fi
}

detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
        VERSION=$VERSION_ID
    else
        log_error "Cannot detect OS"
        exit 1
    fi
    log_info "Detected OS: $OS $VERSION"
}

install_dependencies() {
    log_info "Installing dependencies..."
    
    case "$OS" in
        debian|ubuntu)
            apt-get update
            apt-get install -y \
                build-essential \
                pkg-config \
                libssl-dev \
                libpcre3-dev \
                libnetfilter-conntrack-dev \
                libmnl-dev \
                iptables \
                ipset \
                iproute2 \
                snmp \
                snmpd \
                rsync \
                curl \
                wget \
                htop \
                iftop \
                iotop \
                sysstat \
                net-tools \
                bridge-utils
            ;;
        centos|rhel|fedora)
            yum install -y \
                gcc \
                make \
                pkgconfig \
                openssl-devel \
                pcre-devel \
                libnetfilter_conntrack-devel \
                iptables \
                ipset \
                iproute \
                net-snmp \
                rsync \
                curl \
                wget \
                htop \
                sysstat
            ;;
        *)
            log_warn "Unknown OS, skipping dependency installation"
            ;;
    esac
    
    log_info "Dependencies installed"
}

create_directories() {
    log_info "Creating system directories..."
    
    mkdir -p /etc/ngfw
    mkdir -p /var/log/ngfw
    mkdir -p /var/run/ngfw
    mkdir -p /var/cache/ngfw
    mkdir -p /var/lib/ngfw
    
    chmod 755 /etc/ngfw
    chmod 755 /var/log/ngfw
    chmod 755 /var/run/ngfw
    chmod 755 /var/cache/ngfw
    chmod 755 /var/lib/ngfw
    
    log_info "Directories created"
}

install_binary() {
    log_info "Installing NGFW binary..."
    
    if [ -f "./ngfw" ]; then
        cp ./ngfw /usr/sbin/ngfw
        chmod 755 /usr/sbin/ngfw
        log_info "NGFW binary installed"
    else
        log_error "Binary not found"
        return 1
    fi
}

install_config() {
    log_info "Installing configuration files..."
    
    if [ -f "./etc/ngfw.conf" ]; then
        cp ./etc/ngfw.conf /etc/ngfw/ngfw.conf
        chmod 640 /etc/ngfw/ngfw.conf
    fi
    
    mkdir -p /etc/ngfw/rules
    mkdir -p /etc/ngfw/ssl
    mkdir -p /etc/ngfw/scripts
    
    log_info "Configuration installed"
}

install_init_scripts() {
    log_info "Installing init scripts..."
    
    if [ -f "./scripts/init.d/ngfw" ]; then
        cp ./scripts/init.d/ngfw /etc/init.d/ngfw
        chmod 755 /etc/init.d/ngfw
    fi
    
    if [ -f "./scripts/systemd/ngfw.service" ]; then
        cp ./scripts/systemd/ngfw.service /etc/systemd/system/
        chmod 644 /etc/systemd/system/ngfw.service
        systemctl daemon-reload
    fi
    
    log_info "Init scripts installed"
}

configure_iptables() {
    log_info "Configuring iptables..."
    
    cat > /etc/iptables.rules << 'EOF'
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]

-A INPUT -i lo -j ACCEPT
-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
-A INPUT -p tcp --dport 22 -j ACCEPT
-A INPUT -p tcp --dport 80 -j ACCEPT
-A INPUT -p tcp --dport 443 -j ACCEPT
-A INPUT -p tcp --dport 2022 -j ACCEPT
-A INPUT -p icmp -j ACCEPT

COMMIT
*nat
:PREROUTING ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
-A POSTROUTING -j MASQUERADE
COMMIT
EOF

    chmod 600 /etc/iptables.rules
    log_info "Iptables configured"
}

configure_sysctl() {
    log_info "Configuring kernel parameters..."
    
    cat >> /etc/sysctl.conf << 'EOF'

net.ipv4.ip_forward=1
net.ipv4.conf.all.rp_filter=1
net.netfilter.nf_conntrack_max=262144
net.netfilter.nf_conntrack_tcp_timeout_established=3600
EOF

    sysctl -p
    log_info "Kernel parameters configured"
}

setup_user() {
    log_info "Setting up NGFW user..."
    
    if ! id ngfw &>/dev/null; then
        useradd -r -s /sbin/nologin -d /var/lib/ngfw -c "NGFW Service Account" ngfw
    fi
    
    chown -R ngfw:ngfw /var/log/ngfw
    chown -R ngfw:ngfw /var/run/ngfw
    chown -R ngfw:ngfw /var/lib/ngfw
    
    log_info "User configured"
}

verify_installation() {
    log_info "Verifying installation..."
    
    [ -f /usr/sbin/ngfw ] && [ -f /etc/ngfw/ngfw.conf ] && [ -d /var/log/ngfw ]
}

start_service() {
    log_info "Starting NGFW service..."
    
    systemctl start ngfw 2>/dev/null || /usr/sbin/ngfw -c /etc/ngfw/ngfw.conf -d 2>/dev/null || true
    
    if pgrep -x ngfw > /dev/null; then
        log_info "NGFW service started"
    else
        log_warn "Service may not have started"
    fi
}

show_status() {
    echo ""
    echo "=========================================="
    echo "  NGFW Installation Complete"
    echo "=========================================="
    echo ""
    echo "Service Status:"
    pgrep -x ngfw > /dev/null && echo -e "  NGFW: ${GREEN}Running${NC}" || echo -e "  NGFW: ${RED}Stopped${NC}"
    echo ""
    echo "Access:"
    echo "  Web UI: https://$(hostname -I | awk '{print $1}'):8443"
    echo "  CLI: nc localhost 2022"
    echo ""
}

check_root
detect_os
install_dependencies
create_directories
install_binary
install_config
install_init_scripts
configure_iptables
configure_sysctl
setup_user

if verify_installation; then
    log_info "Installation successful"
else
    log_error "Installation failed"
    exit 1
fi

start_service
show_status