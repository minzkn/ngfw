# NGFW System Health Monitor

#!/bin/bash

INTERVAL=60
ALERT_LOG=/var/log/ngfw/health_alerts.log

log_alert() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> $ALERT_LOG
    logger -t ngfw-health "$1"
}

check_cpu() {
    cpu_usage=$(top -bn1 | grep "Cpu(s)" | sed "s/.*, *\([0-9.]*\)%* id.*/\1/" | awk '{print 100 - $1}')
    
    if (( $(echo "$cpu_usage > 90" | bc -l 2>/dev/null || echo 0) )); then
        log_alert "HIGH CPU: ${cpu_usage}%"
    fi
    
    echo "CPU: ${cpu_usage}%"
}

check_memory() {
    mem_total=$(free -m | awk '/^Mem:/{print $2}')
    mem_used=$(free -m | awk '/^Mem:/{print $3}')
    mem_percent=$((mem_used * 100 / mem_total))
    
    if [ $mem_percent -gt 90 ]; then
        log_alert "HIGH MEMORY: ${mem_percent}%"
    fi
    
    echo "Memory: ${mem_percent}%"
}

check_disk() {
    disk_usage=$(df -h / | awk 'NR==2{print $5}' | tr -d '%')
    
    if [ $disk_usage -gt 90 ]; then
        log_alert "HIGH DISK: ${disk_usage}%"
    fi
    
    echo "Disk: ${disk_usage}%"
}

check_network() {
    rx_bytes=$(cat /sys/class/net/eth0/statistics/rx_bytes 2>/dev/null || echo 0)
    tx_bytes=$(cat /sys/class/net/eth0/statistics/tx_bytes 2>/dev/null || echo 0)
    
    echo "Network RX: $rx_bytes TX: $tx_bytes"
}

check_ngfw_service() {
    if ! pgrep -x ngfw > /dev/null; then
        log_alert "NGFW SERVICE NOT RUNNING"
    fi
}

check_sessions() {
    if [ -f /proc/net/nf_conntrack ]; then
        session_count=$(wc -l < /proc/net/nf_conntrack)
        echo "Sessions: $session_count"
    fi
}

check_logs() {
    error_count=$(tail -n 100 /var/log/ngfw.log 2>/dev/null | grep -c ERROR || echo 0)
    if [ $error_count -gt 10 ]; then
        log_alert "HIGH ERROR RATE: $error_count errors in last 100 lines"
    fi
}

echo "=== NGFW System Health Monitor ==="
echo "Timestamp: $(date)"
echo ""

while true; do
    check_cpu
    check_memory
    check_disk
    check_network
    check_ngfw_service
    check_sessions
    check_logs
    
    echo "---"
    sleep $INTERVAL
done