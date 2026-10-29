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
    if [ -f /etc/resolv.conf.cipherdns.bak ]; then
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
    echo "[cipherDNS] Clean shutdown complete."
}

if [ "$EUID" -ne 0 ]; then
    echo "[!] cipherDNS requires root privileges to bind port 53 and route system DNS."
    echo "[!] Re-launching with sudo..."
    exec sudo "$0" "$@"
fi

# Trap signals for clean restoration
trap cleanup EXIT INT TERM

echo "============================================================"
echo "  🚀 Starting cipherDNS..."
echo "  Python Interpreter: $PYTHON_EXEC"
echo "  Network Interface:  $INTERFACE"
echo "============================================================"

# Automatically configure system DNS
echo "[cipherDNS] Directing system DNS on $INTERFACE to 127.0.0.1..."
resolvectl dns "$INTERFACE" 127.0.0.1 2>/dev/null || true
resolvectl flush-caches 2>/dev/null || true

if [ ! -f /etc/resolv.conf.cipherdns.bak ]; then
    if [ -L /etc/resolv.conf ]; then
        TARGET=$(readlink /etc/resolv.conf)
        echo "SYMLINK:$TARGET" > /etc/resolv.conf.cipherdns.bak
    else
        cp -a /etc/resolv.conf /etc/resolv.conf.cipherdns.bak
    fi
fi
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
