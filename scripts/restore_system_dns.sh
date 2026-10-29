#!/usr/bin/env bash
# cipherDNS System DNS Restore Script
# Restores default network DNS resolver

set -e

INTERFACE=$(ip route | grep default | awk '{print $5}' | head -n1)
INTERFACE=${INTERFACE:-enp2s0}

echo "[cipherDNS] Restoring default network DNS resolver..."

if command -v resolvectl &> /dev/null; then
    resolvectl revert "$INTERFACE" 2>/dev/null || resolvectl dns "$INTERFACE" 10.200.1.11 2>/dev/null || true
    resolvectl flush-caches 2>/dev/null || true
fi

if [ "$EUID" -eq 0 ] && [ -f /etc/resolv.conf.cipherdns.bak ]; then
    if grep -q "SYMLINK:" /etc/resolv.conf.cipherdns.bak; then
        TARGET=$(cat /etc/resolv.conf.cipherdns.bak | cut -d':' -f2)
        rm -f /etc/resolv.conf
        ln -s "$TARGET" /etc/resolv.conf
    else
        cp -a /etc/resolv.conf.cipherdns.bak /etc/resolv.conf
    fi
    rm -f /etc/resolv.conf.cipherdns.bak
    echo "[cipherDNS] Restored original /etc/resolv.conf"
fi

echo "[cipherDNS] Default system DNS successfully restored."
