#!/usr/bin/env bash
# cipherDNS System DNS Restore Script
# Restores default network DNS resolver and cleans up any lingering processes

INTERFACE=$(ip route | grep default | awk '{print $5}' | head -n1)
INTERFACE=${INTERFACE:-enp2s0}

echo "[cipherDNS] Restoring default network DNS resolver..."

if [ "$EUID" -ne 0 ]; then
    echo "[!] cipherDNS requires root privileges to restore /etc/resolv.conf."
    echo "[!] Re-launching with sudo..."
    exec sudo "$0" "$@"
fi

# 1. Kill any lingering cipherdns / python processes on ports 53 and 8000
echo "[cipherDNS] Terminating any lingering processes on ports 53 / 8000..."
fuser -k 53/udp 2>/dev/null || true
fuser -k 8000/tcp 2>/dev/null || true
pkill -9 -f "run.py.*--dns-port" 2>/dev/null || true
sleep 0.5

# 2. Revert resolvectl DNS setting on interface
if command -v resolvectl &> /dev/null; then
    resolvectl revert "$INTERFACE" 2>/dev/null || resolvectl dns "$INTERFACE" 10.200.1.11 2>/dev/null || true
    resolvectl flush-caches 2>/dev/null || true
fi

# 3. Restore /etc/resolv.conf symlink to systemd-resolved
rm -f /etc/resolv.conf
rm -f /etc/resolv.conf.cipherdns.bak

if [ -f /run/systemd/resolve/stub-resolv.conf ]; then
    ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf
elif [ -f /run/systemd/resolve/resolv.conf ]; then
    ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf
else
    cat << 'EOF' > /etc/resolv.conf
nameserver 8.8.8.8
nameserver 1.1.1.1
EOF
fi

systemctl restart systemd-resolved 2>/dev/null || true
echo "[cipherDNS] Restored /etc/resolv.conf symlink and restarted systemd-resolved."
echo "[cipherDNS] Default system DNS successfully restored."
