#!/usr/bin/env bash
# cipherDNS Universal Launcher
# Automatically uses .venv python, binds to port 53, and routes laptop DNS

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if [ -f "$SCRIPT_DIR/.venv/bin/python3" ]; then
    PYTHON_EXEC="$SCRIPT_DIR/.venv/bin/python3"
elif [ -n "$VIRTUAL_ENV" ] && [ -f "$VIRTUAL_ENV/bin/python3" ]; then
    PYTHON_EXEC="$VIRTUAL_ENV/bin/python3"
else
    PYTHON_EXEC="$(which python3)"
fi

# Detect default interface
INTERFACE=$(ip route | grep default | awk '{print $5}' | head -n1)
INTERFACE=${INTERFACE:-enp2s0}

cleanup() {
    echo ""
    echo "[cipherDNS] Restoring system DNS settings..."
    resolvectl revert "$INTERFACE" 2>/dev/null || resolvectl dns "$INTERFACE" 10.200.1.11 2>/dev/null || true
    resolvectl flush-caches 2>/dev/null || true
    
    rm -f /etc/resolv.conf
    rm -f /etc/resolv.conf.cipherdns.bak
    if [ -f /run/systemd/resolve/stub-resolv.conf ]; then
        ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf
    elif [ -f /run/systemd/resolve/resolv.conf ]; then
        ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf
    else
        echo "nameserver 8.8.8.8" > /etc/resolv.conf
    fi
    systemctl restart systemd-resolved 2>/dev/null || true
    echo "[cipherDNS] Restored /etc/resolv.conf symlink and restarted systemd-resolved."
    echo "[cipherDNS] Clean shutdown complete."
}

if [ "$EUID" -ne 0 ]; then
    echo "[!] cipherDNS requires root privileges to bind port 53 and route system DNS."
    echo "[!] Re-launching with sudo..."
    exec sudo "$0" "$@"
fi

# Terminate any previous stale/zombie cipherDNS or python instances on ports 53 and 8000
echo "[cipherDNS] Terminating any stale DNS/Web processes on ports 53/8000..."
fuser -k 53/udp 2>/dev/null || true
fuser -k 8000/tcp 2>/dev/null || true
pkill -9 -f "run.py.*--dns-port" 2>/dev/null || true
sleep 0.5

# Trap signals for clean restoration
trap cleanup EXIT INT TERM HUP

echo "============================================================"
echo "  🚀 Starting cipherDNS..."
echo "  Python Interpreter: $PYTHON_EXEC"
echo "  Network Interface:  $INTERFACE"
echo "============================================================"

# Automatically configure system DNS
echo "[cipherDNS] Directing system DNS on $INTERFACE to 127.0.0.1..."
resolvectl dns "$INTERFACE" 127.0.0.1 2>/dev/null || true
resolvectl flush-caches 2>/dev/null || true

rm -f /etc/resolv.conf
cat << 'EOF' > /etc/resolv.conf
# cipherDNS Active System Resolver
nameserver 127.0.0.1
options edns0 trust-ad
EOF
echo "[cipherDNS] /etc/resolv.conf pointed to 127.0.0.1"
echo "[cipherDNS] All laptop traffic (Chrome, curl, wget) is now routed to cipherDNS!"
echo "============================================================"

"$PYTHON_EXEC" run.py --dns-port 53 --dns-host 127.0.0.1 --web-port 8000 "$@"
