#!/usr/bin/env bash
# cipherDNS System DNS Setup Script
# Redirects local OS DNS resolution to 127.0.0.1

set -e

echo "[cipherDNS] Configuring local DNS resolver to 127.0.0.1..."

if command -v resolvectl &> /dev/null; then
    # Detect default routing interface
    INTERFACE=$(ip route | grep default | awk '{print $5}' | head -n1)
    if [ -n "$INTERFACE" ]; then
        echo "[cipherDNS] Detected default network interface: $INTERFACE"
        resolvectl dns "$INTERFACE" 127.0.0.1
        resolvectl flush-caches
        echo "[cipherDNS] Successfully routed interface $INTERFACE to 127.0.0.1"
    else
        echo "[cipherDNS] Warning: Could not detect default interface. Trying link 2..."
        resolvectl dns enp2s0 127.0.0.1 || true
    fi
else
    echo "[cipherDNS] resolvectl not found. Direct /etc/resolv.conf backup & update:"
    if [ -w /etc/resolv.conf ]; then
        cp /etc/resolv.conf /etc/resolv.conf.cipherdns.bak
        echo "nameserver 127.0.0.1" > /etc/resolv.conf
        echo "[cipherDNS] Updated /etc/resolv.conf to nameserver 127.0.0.1"
    else
        echo "[cipherDNS] Run with sudo to write /etc/resolv.conf:"
        echo "sudo bash -c 'echo \"nameserver 127.0.0.1\" > /etc/resolv.conf'"
    fi
fi

echo "[cipherDNS] System DNS is now pointed to cipherDNS! Verify with: dig netflix.com"
