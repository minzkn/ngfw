#!/bin/bash
#
# NGFW Recovery System
# Rescue mode and system recovery
#

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

RECOVERY_LOG="/var/log/ngfw-recovery.log"

log() {
    echo -e "$1" | tee -a "$RECOVERY_LOG"
}

check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}Error: Must run as root${NC}"
        exit 1
    fi
}

check_recovery_partition() {
    log "${CYAN}=== Checking Recovery Partition ===${NC}"
    
    if mount | grep -q "/dev/mmcblk0p3"; then
        log "Recovery partition found"
        return 0
    else
        log "${YELLOW}Warning: Recovery partition not found${NC}"
        return 1
    fi
}

backup_current_system() {
    log "${CYAN}=== Backing Up Current System ===${NC}"
    
    local backup_dir="/mnt/backup-$(date +%Y%m%d-%H%M%S)"
    mkdir -p "$backup_dir"
    
    log "Backing up /etc/ngfw..."
    tar -czf "$backup_dir/etc_ngfw.tar.gz" /etc/ngfw 2>/dev/null || true
    
    log "Backing up /var/lib/ngfw..."
    tar -czf "$backup_dir/var_lib_ngfw.tar.gz" /var/lib/ngfw 2>/dev/null || true
    
    log "Backing up /var/log/ngfw..."
    tar -czf "$backup_dir/var_log_ngfw.tar.gz" /var/log/ngfw 2>/dev/null || true
    
    log "Backup created: $backup_dir"
}

restore_from_backup() {
    log "${CYAN}=== Restoring from Backup ===${NC}"
    
    local backup_file=$1
    
    if [ -z "$backup_file" ]; then
        log "Available backups:"
        ls -la /mnt/backup-*.tar.gz 2>/dev/null || log "No backups found"
        return 1
    fi
    
    if [ ! -f "$backup_file" ]; then
        log "${RED}Error: Backup file not found: $backup_file${NC}"
        return 1
    fi
    
    log "Restoring from: $backup_file"
    
    tar -xzf "$backup_file" -C / 2>/dev/null || true
    
    log "Restore complete"
}

reset_to_defaults() {
    log "${CYAN}=== Resetting to Factory Defaults ===${NC}"
    
    log "This will remove all custom configuration..."
    
    rm -rf /etc/ngfw/*
    rm -rf /var/lib/ngfw/*
    rm -rf /var/log/ngfw/*
    
    if [ -f /etc/ngfw/ngfw.conf ]; then
        cp /mnt/public_home/work/research/ngfw/etc/ngfw.conf /etc/ngfw/ngfw.conf
    fi
    
    log "Factory defaults restored"
}

reinstall_ngfw() {
    log "${CYAN}=== Reinstalling NGFW ===${NC}"
    
    log "Stopping service..."
    pkill ngfw 2>/dev/null || true
    
    log "Reinstalling binary..."
    cp /mnt/public_home/work/research/ngfw/ngfw /usr/sbin/ngfw
    chmod 755 /usr/sbin/ngfw
    
    log "Starting service..."
    /usr/sbin/ngfw -c /etc/ngfw/ngfw.conf -d &
    
    sleep 2
    
    if pgrep -x ngfw > /dev/null; then
        log "NGFW reinstalled and started"
    else
        log "${RED}Error: NGFW failed to start${NC}"
        return 1
    fi
}

fix_network() {
    log "${CYAN}=== Fixing Network Configuration ===${NC}"
    
    log "Resetting network interfaces..."
    ip link set eth0 down 2>/dev/null || true
    ip addr flush dev eth0 2>/dev/null || true
    
    log "Applying default network config..."
    ip addr add 192.168.1.100/24 dev eth0 2>/dev/null || true
    ip link set eth0 up 2>/dev/null || true
    ip route add default via 192.168.1.1 2>/dev/null || true
    
    log "Network reset complete"
}

fix_firewall() {
    log "${CYAN}=== Fixing Firewall ===${NC}"
    
    log "Flushing all iptables rules..."
    iptables -F
    iptables -t nat -F
    iptables -t mangle -F
    iptables -X
    
    log "Setting default policies..."
    iptables -P INPUT ACCEPT
    iptables -P FORWARD ACCEPT
    iptables -P OUTPUT ACCEPT
    
    log "Allowing loopback..."
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A OUTPUT -o lo -j ACCEPT
    
    log "Allowing established connections..."
    iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    
    log "Allowing SSH..."
    iptables -A INPUT -p tcp --dport 22 -j ACCEPT
    
    log "Firewall reset complete"
}

update_firmware() {
    local fw_file=$1
    
    log "${CYAN}=== Updating Firmware ===${NC}"
    
    if [ -z "$fw_file" ]; then
        log "Error: Firmware file not specified"
        return 1
    fi
    
    log "Verifying firmware..."
    
    if tar -tzf "$fw_file" >/dev/null 2>&1; then
        log "Extracting firmware..."
        tar -xzf "$fw_file" -C /tmp/
        
        log "Installing new kernel..."
        cp /tmp/boot/vmlinuz-* /boot/ 2>/dev/null || true
        
        log "Installing new modules..."
        cp -r /tmp/lib/modules/* /lib/modules/ 2>/dev/null || true
        
        log "Cleaning up..."
        rm -rf /tmp/boot /tmp/lib
        
        log "Reboot required for changes to take effect"
        reboot
    else
        log "${RED}Error: Invalid firmware file${NC}"
        return 1
    fi
}

emergency_shell() {
    log "${CYAN}=== Starting Emergency Shell ===${NC}"
    log "Type 'exit' to return to recovery menu"
    
    /bin/bash
}

show_menu() {
    echo ""
    echo "========================================"
    echo "  NGFW Recovery System"
    echo "========================================"
    echo ""
    echo "1) Backup current system"
    echo "2) Restore from backup"
    echo "3) Reset to factory defaults"
    echo "4) Reinstall NGFW"
    echo "5) Fix network"
    echo "6) Fix firewall"
    echo "7) Update firmware"
    echo "8) Emergency shell"
    echo "9) Reboot"
    echo "0) Exit"
    echo ""
    echo -n "Select option: "
}

main() {
    check_root
    
    mkdir -p /var/log/ngfw
    touch "$RECOVERY_LOG"
    
    log "NGFW Recovery System started at $(date)"
    
    while true; do
        show_menu
        read -r choice
        
        case "$choice" in
            1) backup_current_system ;;
            2) restore_from_backup ;;
            3) reset_to_defaults ;;
            4) reinstall_ngfw ;;
            5) fix_network ;;
            6) fix_firewall ;;
            7) update_firmware ;;
            8) emergency_shell ;;
            9) reboot ;;
            0) exit 0 ;;
            *) log "Invalid option" ;;
        esac
    done
}

case "$1" in
    backup)
        check_root
        backup_current_system
        ;;
    restore)
        check_root
        restore_from_backup "$2"
        ;;
    reset)
        check_root
        reset_to_defaults
        ;;
    fix-network)
        check_root
        fix_network
        ;;
    fix-firewall)
        check_root
        fix_firewall
        ;;
    shell)
        emergency_shell
        ;;
    *)
        main
        ;;
esac