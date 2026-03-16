#!/bin/bash
#
# NGFW System Diagnostics Tool
# Comprehensive system health check and troubleshooting
#

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

LOG_FILE="/var/log/ngfw/diagnostics.log"

log() {
    echo -e "$1" | tee -a "$LOG_FILE"
}

check_header() {
    log ""
    log "${CYAN}========================================${NC}"
    log "${CYAN}  $1${NC}"
    log "${CYAN}========================================${NC}"
    log ""
}

check_pass() {
    log "  [${GREEN}PASS${NC}] $1"
}

check_fail() {
    log "  [${RED}FAIL${NC}] $1"
}

check_warn() {
    log "  [${YELLOW}WARN${NC}] $1"
}

check_info() {
    log "  [${BLUE}INFO${NC}] $1"
}

system_info() {
    check_header "System Information"
    
    log "Hostname: $(hostname)"
    log "Kernel: $(uname -r)"
    log "Architecture: $(uname -m)"
    log "Uptime: $(uptime -p 2>/dev/null || uptime)"
    log "Load Average: $(cat /proc/loadavg | awk '{print $1, $2, $3}')"
}

cpu_check() {
    check_header "CPU Check"
    
    local cpu_usage=$(top -bn1 | grep "Cpu(s)" | sed "s/.*, *\([0-9.]*\)%* id.*/\1/" | awk '{print 100 - $1}')
    
    if (( $(echo "$cpu_usage > 90" | bc -l 2>/dev/null || echo 0) )); then
        check_fail "CPU usage high: ${cpu_usage}%"
    else
        check_pass "CPU usage: ${cpu_usage}%"
    fi
    
    log "CPU cores: $(nproc)"
    
    if command -v lscpu &> /dev/null; then
        log "CPU model: $(lscpu | grep 'Model name' | cut -d: -f2 | xargs)"
    fi
}

memory_check() {
    check_header "Memory Check"
    
    local mem_total=$(free -m | awk '/^Mem:/{print $2}')
    local mem_used=$(free -m | awk '/^Mem:/{print $3}')
    local mem_percent=$((mem_used * 100 / mem_total))
    
    log "Total: ${mem_total}MB"
    log "Used: ${mem_used}MB"
    log "Usage: ${mem_percent}%"
    
    if [ $mem_percent -gt 90 ]; then
        check_fail "Memory usage high: ${mem_percent}%"
    elif [ $mem_percent -gt 70 ]; then
        check_warn "Memory usage elevated: ${mem_percent}%"
    else
        check_pass "Memory usage normal"
    fi
    
    swap_total=$(free -m | awk '/^Swap:/{print $2}')
    if [ "$swap_total" -gt 0 ]; then
        swap_used=$(free -m | awk '/^Swap:/{print $3}')
        log "Swap used: ${swap_used}MB"
    fi
}

disk_check() {
    check_header "Disk Check"
    
    df -h | grep -E '^/dev|^Filesystem' | while read -r line; do
        local usage=$(echo "$line" | awk '{print $5}' | tr -d '%')
        local mount=$(echo "$line" | awk '{print $6}')
        
        if [ "$usage" -gt 90 ]; then
            check_fail "$mount: ${usage}%"
        elif [ "$usage" -gt 80 ]; then
            check_warn "$mount: ${usage}%"
        else
            check_pass "$mount: ${usage}%"
        fi
    done
    
    local inodes=$(df -i | grep -E '^/dev' | head -1 | awk '{print $5}' | tr -d '%')
    if [ "$inodes" -gt 80 ]; then
        check_warn "Inode usage: ${inodes}%"
    fi
}

network_check() {
    check_header "Network Check"
    
    log "Interfaces:"
    ip -br addr show | while read -r line; do
        log "  $line"
    done
    
    log ""
    log "Routes:"
    ip route show | while read -r line; do
        log "  $line"
    done
    
    log ""
    log "Network statistics:"
    netstat -s | head -20
}

firewall_check() {
    check_header "Firewall Check"
    
    local rules_count=$(iptables -L -n 2>/dev/null | grep -c "^Chain" || echo 0)
    log "IPTables chains: $rules_count"
    
    local filter_rules=$(iptables -L INPUT -n 2>/dev/null | wc -l)
    log "INPUT rules: $filter_rules"
    
    local nat_rules=$(iptables -t nat -L -n 2>/dev/null | wc -l)
    log "NAT rules: $nat_rules"
    
    check_info "Firewall status:"
    iptables -L -n -v --line-numbers 2>/dev/null | head -20 || check_fail "Cannot read iptables"
}

connection_tracking() {
    check_header "Connection Tracking"
    
    if [ -f /proc/net/nf_conntrack ]; then
        local conn_count=$(wc -l < /proc/net/nf_conntrack)
        local max_conn=$(cat /proc/sys/net/netfilter/nf_conntrack_max 2>/dev/null || echo 0)
        local conn_percent=$((conn_count * 100 / max_conn))
        
        log "Active connections: $conn_count / $max_conn ($conn_percent%)"
        
        if [ $conn_percent -gt 90 ]; then
            check_warn "Connection table nearly full"
        else
            check_pass "Connection tracking normal"
        fi
        
        log ""
        log "Connection states:"
        cat /proc/net/nf_conntrack | cut -d' ' -f4 | sort | uniq -c | sort -rn | head -10
    else
        check_fail "Connection tracking not available"
    fi
}

ngfw_service_check() {
    check_header "NGFW Service Check"
    
    if pgrep -x ngfw > /dev/null; then
        check_pass "NGFW process running"
        
        local pid=$(pgrep -x ngfw)
        log "PID: $pid"
        
        local cpu=$(ps -p $pid -o %cpu= 2>/dev/null || echo 0)
        local mem=$(ps -p $pid -o %mem= 2>/dev/null || echo 0)
        log "CPU: ${cpu}%, Memory: ${mem}%"
        
        local threads=$(ps -p $pid -o nlwp= 2>/dev/null || echo 0)
        log "Threads: $threads"
    else
        check_fail "NGFW process not running"
    fi
    
    log ""
    log "Ports in use:"
    netstat -tulnp 2>/dev/null | grep -E ':(443|80|2022|161|8443)' || check_info "No NGFW ports detected"
}

log_check() {
    check_header "Log Analysis"
    
    local error_count=$(tail -n 1000 /var/log/ngfw/ngfw.log 2>/dev/null | grep -ci error || echo 0)
    local warn_count=$(tail -n 1000 /var/log/ngfw/ngfw.log 2>/dev/null | grep -ci warn || echo 0)
    
    log "Errors in last 1000 lines: $error_count"
    log "Warnings in last 1000 lines: $warn_count"
    
    if [ $error_count -gt 10 ]; then
        check_warn "High error rate"
    else
        check_pass "Log status normal"
    fi
    
    log ""
    log "Recent errors:"
    tail -n 10 /var/log/ngfw/ngfw.log 2>/dev/null | grep -i error || check_info "No recent errors"
}

performance_metrics() {
    check_header "Performance Metrics"
    
    log "Packet statistics:"
    if [ -f /proc/net/dev ]; then
        cat /proc/net/dev | grep -E 'eth0|ens|enp' | while read -r line; do
            local iface=$(echo "$line" | cut -d: -f1)
            local rx=$(echo "$line" | awk '{print $2}')
            local tx=$(echo "$line" | awk '{print $10}')
            log "  $iface - RX: $rx, TX: $tx"
        done
    fi
    
    log ""
    log "Throughput (last second):"
    cat /proc/net/dev | grep -E 'eth0|ens|enp' | while read -r line; do
        local iface=$(echo "$line" | cut -d: -f1)
        log "  $iface: $(cat /sys/class/net/$iface/statistics/rx_bytes 2>/dev/null) bytes received"
    done
}

security_check() {
    check_header "Security Check"
    
    local failed_logins=$(last -f /var/log/btmp 2>/dev/null | wc -l || echo 0)
    log "Failed login attempts: $failed_logins"
    
    if [ $failed_logins -gt 50 ]; then
        check_warn "High number of failed logins"
    fi
    
    log ""
    log "Open ports:"
    netstat -tuln 2>/dev/null | awk '{print $4}' | cut -d: -f2 | sort -nu | tr '\n' ' '
    log ""
    
    local ssh_attacks=$(grep -c "Failed password" /var/log/auth.log 2>/dev/null | tail -1 || echo 0)
    log "SSH attack attempts: $ssh_attacks"
}

summary() {
    check_header "Summary"
    
    log "Diagnostics completed at $(date)"
    log "Log file: $LOG_FILE"
    
    local warnings=$(grep -c "WARN" "$LOG_FILE" 2>/dev/null || echo 0)
    local failures=$(grep -c "FAIL" "$LOG_FILE" 2>/dev/null || echo 0)
    
    log ""
    log "Issues found:"
    log "  Warnings: $warnings"
    log "  Failures: $failures"
    
    if [ $failures -gt 0 ]; then
        log ""
        log "${RED}Action required! Please review the failed checks above.${NC}"
    fi
}

main() {
    mkdir -p /var/log/ngfw
    touch "$LOG_FILE"
    
    log "NGFW System Diagnostics"
    log "Started at $(date)"
    log ""
    
    system_info
    cpu_check
    memory_check
    disk_check
    network_check
    firewall_check
    connection_tracking
    ngfw_service_check
    log_check
    performance_metrics
    security_check
    summary
    
    log ""
    log "Diagnostics complete"
}

main "$@"