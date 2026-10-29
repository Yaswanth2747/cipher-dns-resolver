#!/usr/bin/env bash
# cipherDNS System DNS Restore Script
# Restores default network DNS resolver

set -e

echo "[cipherDNS] Restoring default upstream DNS resolver..."

if command -v resolvectl &> /dev/null; then
    INTERFACE=$(ip route | grep default | awk '{print $5}' | head -n1)
    INTERFACE=${INTERFACE:-enp2s0}
    # Restore campus / gateway DNS (10.200.1.11) or revert
    resolvectl revert "$INTERFACE" 2>/dev/null || resolvectl dns "$INTERFACE" 10.200.1.11 8.8.8.8
    resolvectl flush-caches
    echo "[cipherDNS] Restored network interface $INTERFACE DNS uplink."
else
    if [ -f /etc/resolv.conf.cipherdns.bak ]; then
        cp /etc/resolv.conf.cipherdns.bak /etc/resolv.conf
        echo "[cipherDNS] Restored /etc/resolv.conf from backup."
    else
        echo "[cipherDNS] Resetting /etc/resolv.conf to standard public DNS (8.8.8.8)..."
        echo "nameserver 8.8.8.8" > /etc/resolv.conf 2>/dev/null || echo "Run: sudo bash -c 'echo nameserver 8.8.8.8 > /etc/resolv.conf'"
    fi
fi

echo "[cipherDNS] Default DNS restored."

